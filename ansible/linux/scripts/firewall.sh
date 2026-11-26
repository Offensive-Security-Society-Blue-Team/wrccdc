#!/bin/sh
# firewall.sh - CCDC host firewall that is hard to lock yourself out with and refuses to run without the scorer.
# Our own code. Ideas from UCI LOCS firewall_template.sh (timed test mode, logging chains) and Cal Poly Pomona
# blue basewall.sh (scoring host always allowed, management ports LAN-only, new outbound connections dropped).
#
# What it does (IPv4):
#   inbound : scorer + trusted get everything; everyone else is blocked from MANAGEMENT ports only
#             (databases, SMB, RDP/WinRM, kube API, admin panels...). --strict blocks every port except --public.
#   outbound: new connections only to trusted, scorer, DNS, NTP and --allow-out. This kills reverse shells and C2.
#   It only ADDS drops in its own table/chains: firewalld, Docker and Podman rules are left exactly as they were.
#
# Commands:
#   plan                show listening ports and what each rule would do; changes nothing
#   test [SECONDS]      apply, then undo automatically after SECONDS (default 90) unless you run 'confirm'
#   confirm             keep the rules from 'test'
#   apply               apply with no timer (after a test went fine), or 'apply --saved' after a reboot
#   revert              remove everything this script added
#   status              rules, drop counters, last drops; shouts if the scorer or a trusted IP is being dropped
# Options:
#   --trusted LIST      comma list of IPs/CIDRs: LAN, VPN, teammates, black team   (required for test/apply)
#   --scorer LIST       scoring engine IPs, always fully allowed (required; 'none' only if you are sure)
#   --restrict-ssh      SSH only from trusted + scorer (off by default: black team may need SSH)
#   --strict            inbound default-deny except --public PORTS (comma list) + trusted + scorer
#   --public PORTS      ports anyone may reach in --strict mode, e.g. 80,443
#   --mgmt PORTS        replace the default list of restricted TCP management ports
#   --no-egress         don't filter outbound connections
#   --allow-out LIST    extra outbound destinations: IP, CIDR or IP:PORT (comma list)
#   --backend nft|iptables   force a backend (default: nft if it works, else iptables)
#   --no-container-nets don't auto-trust Docker/Podman/k8s bridge and pod networks on this box
#   --kill-existing     also cut connections to/from untrusted IPs that are already open (live reverse shells);
#                       without it they survive, because established connections are always allowed
#   --saved             reuse the options from the last test/apply
# Example (Ansible):
#   ansible linux -m script -a "scripts/firewall.sh plan --trusted 192.168.220.0/24 --scorer 10.234.234.234"
#   ansible linux -m script -a "scripts/firewall.sh test 120 --trusted 192.168.220.0/24 --scorer 10.234.234.234"
#   (check the scoreboard)   ansible linux -m script -a "scripts/firewall.sh confirm"
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
DIR=/root/.ccdc-fw
MGMT_TCP_DEFAULT="21,23,111,135,139,445,873,1433,2049,2375,2376,2379,2380,3306,3389,5432,5900,5985,5986,6379,6443,8006,9090,9200,10000,10250,11211,27017"
MGMT_UDP="69,111,137,138,161,2049,11211"
h=$(hostname -s 2>/dev/null || hostname)
say() { echo "[$h] $*"; }
die() { echo "[$h] ERROR: $*"; exit 1; }
has() { command -v "$1" >/dev/null 2>&1; }

CMD=${1:-help}; [ $# -gt 0 ] && shift
SECS=90
case "$CMD" in test) case "${1:-}" in ''|-*) ;; *) SECS=$1; shift;; esac;; esac
TRUSTED=""; SCORER=""; RESTRICT_SSH=0; STRICT=0; PUBLIC=""; MGMT_TCP=$MGMT_TCP_DEFAULT; EGRESS=1; ALLOW_OUT=""; BACKEND=""
CONTAINER_NETS=1; KILL=0
case " $* " in *" --saved "*)
    [ -f "$DIR/config" ] || { echo "[$h] ERROR: no saved config yet ($DIR/config)"; exit 1; }
    # shellcheck disable=SC1091
    . "$DIR/config" ;;
esac
while [ $# -gt 0 ]; do
    case "$1" in --trusted|--scorer|--public|--mgmt|--allow-out|--backend)
        case "${2:-}" in ''|--*) echo "[$h] ERROR: $1 needs a value"; exit 1;; esac;; esac
    case "$1" in
        --trusted) TRUSTED=$2; shift ;;
        --scorer) SCORER=$2; shift ;;
        --restrict-ssh) RESTRICT_SSH=1 ;;
        --strict) STRICT=1 ;;
        --public) PUBLIC=$2; shift ;;
        --mgmt) MGMT_TCP=$2; shift ;;
        --no-egress) EGRESS=0 ;;
        --allow-out) ALLOW_OUT=$2; shift ;;
        --backend) BACKEND=$2; shift ;;
        --no-container-nets) CONTAINER_NETS=0 ;;
        --kill-existing) KILL=1 ;;
        --saved) ;;
        *) die "unknown option: $1" ;;
    esac
    shift
done
[ "$(id -u)" = 0 ] || die "run as root"
mkdir -p "$DIR" && chmod 700 "$DIR"

# ---------- helpers ----------
is_ip()   { echo "$1" | awk -F/ '{ if (NF > 2 || (NF == 2 && ($2 !~ /^[0-9]+$/ || $2 + 0 > 32))) exit 1   # every octet 0-255, mask 0-32
                                if (split($1, o, ".") != 4) exit 1
                                for (i = 1; i <= 4; i++) if (o[i] !~ /^[0-9]+$/ || o[i] + 0 > 255) exit 1 }'; }
is_port() { echo "$1" | grep -Eq '^[0-9]{1,5}$' && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
csv_words() { echo "$1" | tr ',' ' '; }
check_ips() { for x in $(csv_words "$2"); do is_ip "$x" || die "$1: '$x' is not an IPv4 address or CIDR"; done; }
check_ports() { for x in $(csv_words "$2"); do is_port "$x" || die "$1: '$x' is not a port"; done; }
nft_list() { echo "$1" | sed 's/,/, /g'; }          # "a,b" -> "a, b" for nft sets
dns_servers() {
    for f in /etc/resolv.conf /run/systemd/resolve/resolv.conf; do
        [ -f "$f" ] && awk '/^nameserver/ {print $2}' "$f"
    done | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | grep -v '^127\.' | sort -u | tr '\n' ',' | sed 's/,$//'
}
my_subnets() { ip -4 -o addr show 2>/dev/null | awk '$2 != "lo" {print $4}' | tr '\n' ' '; }
ssh_client_ip() { # sudo (Ansible become) drops SSH_CONNECTION, so also look in our parent processes' environment
    c=${SSH_CONNECTION:-${SSH_CLIENT:-}}; p=$$
    while [ -z "$c" ] && [ -n "$p" ] && [ "$p" -gt 1 ] 2>/dev/null; do
        c=$(tr '\0' '\n' < "/proc/$p/environ" 2>/dev/null | sed -n 's/^SSH_CONNECTION=//p; s/^SSH_CLIENT=//p' | head -n 1)
        p=$(awk '/^PPid:/ {print $2}' "/proc/$p/status" 2>/dev/null)
    done
    echo "$c" | awk '{print $1}' | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
}
net_of() { awk -F/ '{ m = ($2 == "") ? 32 : $2; split($1, o, "."); n = ((o[1] * 256 + o[2]) * 256 + o[3]) * 256 + o[4]; d = 2 ^ (32 - m); n = int(n / d) * d
                      printf "%d.%d.%d.%d/%d\n", int(n / 16777216) % 256, int(n / 65536) % 256, int(n / 256) % 256, n % 256, m }'; }
container_nets() { # Docker/Podman/libvirt bridges and k8s pod networks on this box (pods must reach the API server and kubelet)
    {
        ip -4 -o addr show 2>/dev/null | awk '$2 ~ /^(docker|br-|cni|flannel|podman|cali|vxlan|kube|virbr|lxcbr|lxdbr|cilium|weave)/ {print $4}'
        if has k3s || [ -d /etc/rancher/k3s ]; then
            for k in cluster-cidr:10.42.0.0/16 service-cidr:10.43.0.0/16; do
                v=$(sed -n "s/^ *${k%%:*}: *[\"']\{0,1\}\([0-9./]*\).*/\1/p" /etc/rancher/k3s/config.yaml 2>/dev/null | head -n 1); echo "${v:-${k#*:}}"
            done
        fi
    } | while read -r n; do is_ip "$n" && echo "$n" | net_of; done | sort -u | tr '\n' ',' | sed 's/,$//'
}
untrusted_conns() { # "ip proc" for open TCP connections whose peer is not loopback, trusted or scorer
    if has ss; then ss -tnp 2>/dev/null | awk '$1 == "ESTAB" {print $5, $6}'
    else netstat -tnp 2>/dev/null | awk '$6 == "ESTABLISHED" {print $5, $7}'; fi |
    awk -v nets="$TRUSTED,$SCORER" '
        function num(ip, o) { split(ip, o, "."); return ((o[1] * 256 + o[2]) * 256 + o[3]) * 256 + o[4] }
        BEGIN { k = split(nets, L, ",") }
        { ip = $1; sub(/:[0-9]+$/, "", ip); sub(/^\[(::ffff:)?/, "", ip); sub(/\]$/, "", ip)
          if (ip !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ || ip ~ /^127\./) next
          for (i = 1; i <= k; i++) { if (L[i] == "") continue; split(L[i], p, "/"); d = 2 ^ (32 - ((p[2] == "") ? 32 : p[2]))
                                     if (int(num(ip) / d) == int(num(p[1]) / d)) next }
          pr = $2; sub(/.*\(\("/, "", pr); sub(/".*/, "", pr); sub(/^[0-9]+\//, "", pr); print ip, (pr == "" ? "?" : pr) }' | sort -u
}
report_conns() { # survivors of the firewall; with --kill-existing, cut them
    u=$(untrusted_conns); [ -n "$u" ] || return 0
    if [ "$KILL" = 1 ]; then
        for ip in $(echo "$u" | awk '{print $1}' | sort -u); do
            has conntrack && { conntrack -D -s "$ip" >/dev/null 2>&1; conntrack -D -d "$ip" >/dev/null 2>&1; }
            has ss && ss -K dst "$ip" >/dev/null 2>&1
            say "cut open connections with $ip ($(echo "$u" | awk -v i="$ip" '$1 == i {print $2}' | sort -u | tr '\n' ' ' | sed 's/ $//'))"
        done
    else
        say "open connections with untrusted IPs (these SURVIVE the firewall; check them, or re-run with --kill-existing):"
        echo "$u" | sed "s/^/[$h]   /"
    fi
}
pick_backend() {
    if [ -n "$BACKEND" ]; then echo "$BACKEND"; return; fi
    if has nft && nft list tables >/dev/null 2>&1; then echo nft
    elif has iptables && iptables -S >/dev/null 2>&1; then echo iptables
    else echo none; fi
}
listening() {
    if has ss; then ss -tulnp 2>/dev/null | tail -n +2 | awk '{n = split($5, a, ":"); pr = $7; sub(/users:\(\("/, "", pr); sub(/".*/, "", pr); print $1, a[n], pr}'
    else netstat -tulnp 2>/dev/null | awk 'NR > 2 {n = split($4, a, ":"); pr = $NF; sub(/^[0-9]+\//, "", pr); print $1, a[n], pr}'; fi | sort -u | sort -k2,2n -k1,1
}
in_list() { case ",$2," in *",$1,"*) return 0;; esac; return 1; }

# ---------- what a port gets ----------
port_fate() { # proto port -> text
    pr=$1; p=$2
    if [ "$STRICT" = 1 ]; then in_list "$p" "$PUBLIC" && echo "open to all" || echo "BLOCKED except trusted/scorer"; return; fi
    case "$pr" in tcp*) list="$MGMT_TCP";; *) list="$MGMT_UDP";; esac
    [ "$RESTRICT_SSH" = 1 ] && list="$list,22"
    in_list "$p" "$list" && echo "management: trusted/scorer only" || echo "open to all"
}

# ---------- build rules ----------
build_nft() { # writes $DIR/rules.nft
    mg=$MGMT_TCP; [ "$RESTRICT_SSH" = 1 ] && mg="$mg,22"
    {
    echo "table ip ccdc {"
    [ -n "$TRUSTED" ] && echo "  set trusted { type ipv4_addr; flags interval; auto-merge; elements = { $(nft_list "$TRUSTED") } }"
    [ -n "$SCORER" ] && echo "  set scorer { type ipv4_addr; flags interval; auto-merge; elements = { $(nft_list "$SCORER") } }"
    echo "  chain in {"
    echo "    type filter hook input priority -5; policy accept;"
    echo "    iif \"lo\" accept"
    echo "    ct state established,related accept"
    [ -n "$SCORER" ] && echo "    ip saddr @scorer accept"
    [ -n "$TRUSTED" ] && echo "    ip saddr @trusted accept"
    echo "    ip protocol icmp accept"
    echo "    udp dport 68 accept"
    if [ "$STRICT" = 1 ]; then
        [ -n "$PUBLIC" ] && echo "    tcp dport { $(nft_list "$PUBLIC") } accept" && echo "    udp dport { $(nft_list "$PUBLIC") } accept"
        echo "    limit rate 10/minute log prefix \"CCDC-DROP-IN \""
        echo "    counter drop"
    else
        echo "    tcp dport { $(nft_list "$mg") } limit rate 10/minute log prefix \"CCDC-DROP-IN \""
        echo "    tcp dport { $(nft_list "$mg") } counter drop"
        echo "    udp dport { $(nft_list "$MGMT_UDP") } counter drop"
    fi
    echo "  }"
    if [ "$EGRESS" = 1 ]; then
        echo "  chain out {"
        echo "    type filter hook output priority -5; policy accept;"
        echo "    oif \"lo\" accept"
        echo "    ct state established,related accept"
        [ -n "$SCORER" ] && echo "    ip daddr @scorer accept"
        [ -n "$TRUSTED" ] && echo "    ip daddr @trusted accept"
        [ -n "$DNS" ] && echo "    ip daddr { $(nft_list "$DNS") } udp dport 53 accept" && echo "    ip daddr { $(nft_list "$DNS") } tcp dport 53 accept"
        echo "    udp dport 123 accept"
        echo "    udp dport 67 accept"
        echo "    ip protocol icmp accept"
        for a in $(csv_words "$ALLOW_OUT"); do
            case "$a" in
                *:*) echo "    ip daddr ${a%:*} tcp dport ${a##*:} accept"; echo "    ip daddr ${a%:*} udp dport ${a##*:} accept" ;;
                *) echo "    ip daddr $a accept" ;;
            esac
        done
        echo "    limit rate 10/minute log prefix \"CCDC-DROP-OUT \""
        echo "    counter drop"
        echo "  }"
    fi
    echo "}"
    } > "$DIR/rules.nft"
}
ipt() { iptables "$@" || { echo "[$h] iptables rejected: $*" >&2; : > "$DIR/.iptfail"; }; }
ipt_ports() { # chain proto portlist target...  (multiport takes at most 15 ports per rule)
    c=$1; pr=$2; pl=$3; shift 3
    echo "$pl" | tr ',' '\n' | awk 'NF' | awk '{ b = b (b ? "," : "") $0; if (NR % 15 == 0) { print b; b = "" } } END { if (b) print b }' | while read -r chunk; do
        ipt -A "$c" -p "$pr" -m multiport --dports "$chunk" "$@"
    done
}
build_iptables() { # applies directly; RETURN = "not dropped by us", so existing rules after our jump still apply
    rm -f "$DIR/.iptfail"
    for c in CCDC-IN CCDC-OUT; do iptables -N "$c" 2>/dev/null || iptables -F "$c"; done
    st="-m conntrack --ctstate"; iptables -m conntrack -h >/dev/null 2>&1 || st="-m state --state"
    ipt -A CCDC-IN -i lo -j RETURN
    # shellcheck disable=SC2086
    ipt -A CCDC-IN $st ESTABLISHED,RELATED -j RETURN
    for s in $(csv_words "$SCORER"); do ipt -A CCDC-IN -s "$s" -j RETURN; done
    for t in $(csv_words "$TRUSTED"); do ipt -A CCDC-IN -s "$t" -j RETURN; done
    ipt -A CCDC-IN -p icmp -j RETURN
    ipt -A CCDC-IN -p udp --dport 68 -j RETURN
    if [ "$STRICT" = 1 ]; then
        [ -n "$PUBLIC" ] && ipt_ports CCDC-IN tcp "$PUBLIC" -j RETURN && ipt_ports CCDC-IN udp "$PUBLIC" -j RETURN
        ipt -A CCDC-IN -m limit --limit 10/min -j LOG --log-prefix "CCDC-DROP-IN "
        ipt -A CCDC-IN -j DROP
    else
        mg=$MGMT_TCP; [ "$RESTRICT_SSH" = 1 ] && mg="$mg,22"
        ipt_ports CCDC-IN tcp "$mg" -m limit --limit 10/min -j LOG --log-prefix "CCDC-DROP-IN "
        ipt_ports CCDC-IN tcp "$mg" -j DROP
        ipt_ports CCDC-IN udp "$MGMT_UDP" -j DROP
    fi
    if [ "$EGRESS" = 1 ]; then
        ipt -A CCDC-OUT -o lo -j RETURN
        # shellcheck disable=SC2086
        ipt -A CCDC-OUT $st ESTABLISHED,RELATED -j RETURN
        for s in $(csv_words "$SCORER"); do ipt -A CCDC-OUT -d "$s" -j RETURN; done
        for t in $(csv_words "$TRUSTED"); do ipt -A CCDC-OUT -d "$t" -j RETURN; done
        for d in $(csv_words "$DNS"); do ipt -A CCDC-OUT -d "$d" -p udp --dport 53 -j RETURN; ipt -A CCDC-OUT -d "$d" -p tcp --dport 53 -j RETURN; done
        ipt -A CCDC-OUT -p udp --dport 123 -j RETURN
        ipt -A CCDC-OUT -p udp --dport 67 -j RETURN
        ipt -A CCDC-OUT -p icmp -j RETURN
        for a in $(csv_words "$ALLOW_OUT"); do
            case "$a" in
                *:*) ipt -A CCDC-OUT -d "${a%:*}" -p tcp --dport "${a##*:}" -j RETURN; ipt -A CCDC-OUT -d "${a%:*}" -p udp --dport "${a##*:}" -j RETURN ;;
                *) ipt -A CCDC-OUT -d "$a" -j RETURN ;;
            esac
        done
        ipt -A CCDC-OUT -m limit --limit 10/min -j LOG --log-prefix "CCDC-DROP-OUT "
        ipt -A CCDC-OUT -j DROP
    fi
    iptables -C INPUT -j CCDC-IN 2>/dev/null || ipt -I INPUT 1 -j CCDC-IN
    if [ "$EGRESS" = 1 ]; then iptables -C OUTPUT -j CCDC-OUT 2>/dev/null || ipt -I OUTPUT 1 -j CCDC-OUT; fi
    [ ! -f "$DIR/.iptfail" ]
}
write_revert() { # standalone undo script, so the timer works after this script is gone
    cat > "$DIR/revert.sh" <<EOF
#!/bin/sh
# written by firewall.sh $(date '+%F %T'); backend: $1
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
if [ "\${1:-}" = timer ] && [ ! -f "$DIR/pending" ]; then exit 0; fi
nft delete table ip ccdc 2>/dev/null
while iptables -D INPUT -j CCDC-IN 2>/dev/null; do :; done
while iptables -D OUTPUT -j CCDC-OUT 2>/dev/null; do :; done
for c in CCDC-IN CCDC-OUT; do iptables -F "\$c" 2>/dev/null; iptables -X "\$c" 2>/dev/null; done
rm -f "$DIR/pending" "$DIR/timer.pid"
echo "\$(date '+%F %T') reverted (\${1:-manual})" >> "$DIR/history.log"
EOF
    chmod 700 "$DIR/revert.sh"
}
start_timer() {
    touch "$DIR/pending"
    if [ -z "${CCDC_FW_NO_SYSTEMD:-}" ] && has systemd-run && [ -d /run/systemd/system ]; then
        systemctl stop ccdc-fw-revert.timer >/dev/null 2>&1; systemctl reset-failed ccdc-fw-revert.service ccdc-fw-revert.timer >/dev/null 2>&1
        systemd-run --quiet --unit ccdc-fw-revert --on-active="${SECS}s" /bin/sh "$DIR/revert.sh" timer >/dev/null 2>&1 && return 0
    fi
    nohup sh -c "sleep $SECS; sh '$DIR/revert.sh' timer" >/dev/null 2>&1 &
    echo $! > "$DIR/timer.pid"
}
stop_timer() {
    rm -f "$DIR/pending"
    systemctl stop ccdc-fw-revert.timer >/dev/null 2>&1
    [ -f "$DIR/timer.pid" ] && kill "$(cat "$DIR/timer.pid")" 2>/dev/null
    rm -f "$DIR/timer.pid"
}
save_config() {
    {
        echo "TRUSTED='$TRUSTED'"; echo "SCORER='${SCORER:-none}'"; echo "RESTRICT_SSH=$RESTRICT_SSH"; echo "STRICT=$STRICT"
        echo "PUBLIC='$PUBLIC'"; echo "MGMT_TCP='$MGMT_TCP'"; echo "EGRESS=$EGRESS"; echo "ALLOW_OUT='$ALLOW_OUT'"; echo "BACKEND='$BACKEND'"; echo "CONTAINER_NETS=$CONTAINER_NETS"
    } > "$DIR/config"
    chmod 600 "$DIR/config"
}
warn_others() {
    if has firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
        for s in $(csv_words "$SCORER"); do
            firewall-cmd --list-all-zones 2>/dev/null | grep -q "${s%/*}" && say "WARNING: firewalld rules mention scorer $s. firewalld can still drop it (this happened at Inv3): firewall-cmd --list-all-zones | grep ${s%/*}"
        done
        say "note: firewalld is active; its rules still apply on top of these"
    fi
    has ufw && ufw status 2>/dev/null | grep -q 'Status: active' && say "note: ufw is active; its rules still apply on top of these"
    { has docker || has podman || has kubectl || has k3s; } && say "note: containers present; traffic to published container ports goes through FORWARD and is not filtered here"
    { ip -6 route show default 2>/dev/null; ip -6 -o addr show scope global 2>/dev/null; } | grep -q . && say "note: this box has IPv6 (global/ULA address or default route); only IPv4 is filtered"
}
preflight() {
    [ -n "$TRUSTED" ] || die "--trusted is required (your LAN/VPN/team/black team). Subnets on this box: $(my_subnets)"
    [ -n "$SCORER" ] || die "--scorer is required: find it first (ip_map.sh, or IPs hitting every scored service). Use --scorer none only if you are sure."
    [ "$SCORER" = none ] && { say "WARNING: no scorer allowed explicitly. Scored management ports may break."; SCORER=""; }
    check_ips --trusted "$TRUSTED"; [ -n "$SCORER" ] && check_ips --scorer "$SCORER"
    check_ports --mgmt "$MGMT_TCP"; [ -n "$PUBLIC" ] && check_ports --public "$PUBLIC"
    [ "$STRICT" = 1 ] && [ -z "$PUBLIC" ] && die "--strict needs --public PORTS (the scored ports), or everyone but trusted/scorer is cut off"
    for a in $(csv_words "$ALLOW_OUT"); do is_ip "${a%:*}" || die "--allow-out: bad address in '$a'"; case "$a" in *:*) is_port "${a##*:}" || die "--allow-out: bad port in '$a'";; esac; done
    me=$(ssh_client_ip)
    if [ -n "$me" ] && ! in_list "$me" "$TRUSTED"; then TRUSTED="$TRUSTED,$me"; say "added your current SSH client $me to trusted so this session survives"; fi
    [ -z "$me" ] && say "WARNING: could not find your SSH client IP; make sure the Ansible host / jump host is in --trusted"
    if [ "$CONTAINER_NETS" = 1 ]; then
        for n in $(csv_words "$(container_nets)"); do in_list "$n" "$TRUSTED" || { TRUSTED="$TRUSTED,$n"; say "trusted container/pod network $n (--no-container-nets to skip)"; }; done
    fi
    DNS=$(dns_servers)
}
apply_rules() {
    B=$(pick_backend); [ "$B" = none ] && die "no working nft or iptables on this box"
    sh "$DIR/revert.sh" quiet >/dev/null 2>&1   # start clean if rules from an earlier run exist
    write_revert "$B"
    if [ "$B" = nft ]; then
        build_nft
        nft -f "$DIR/rules.nft" || { sh "$DIR/revert.sh" failed; die "nft rejected the ruleset ($DIR/rules.nft); nothing applied"; }
    else
        build_iptables || { sh "$DIR/revert.sh" failed; die "iptables failed; rolled back"; }
    fi
    save_config
    echo "$(date '+%F %T') $CMD backend=$B trusted=$TRUSTED scorer=${SCORER:-none} egress=$EGRESS strict=$STRICT" >> "$DIR/history.log"
    say "firewall ON ($B): inbound management ports trusted/scorer only$( [ "$STRICT" = 1 ] && echo " (STRICT: only $PUBLIC open)"), outbound $( [ "$EGRESS" = 1 ] && echo "restricted" || echo "unrestricted")"
}

case "$CMD" in
    plan)
        DNS=$(dns_servers); B=$(pick_backend)
        say "backend: $B | subnets: $(my_subnets)| your SSH client: $(ssh_client_ip || echo '?') | DNS: ${DNS:-none}"
        [ -z "$SCORER" ] && say "scorer: NOT SET (test/apply will refuse until --scorer is given)"
        [ -z "$TRUSTED" ] && say "trusted: NOT SET (suggestion: the subnets above, plus VPN/teammate/black team IPs)"
        listening | while read -r pr p proc; do printf '[%s]   %-4s %-6s %-18s -> %s\n' "$h" "$pr" "$p" "${proc:--}" "$(port_fate "$pr" "$p")"; done
        cn=$( [ "$CONTAINER_NETS" = 1 ] && container_nets ); [ -n "$cn" ] && say "container/pod networks (auto-trusted): $cn"
        KILL=0; report_conns
        [ "$EGRESS" = 1 ] && say "outbound: new connections only to trusted, scorer, DNS (${DNS:-none}), NTP${ALLOW_OUT:+, $ALLOW_OUT}" || say "outbound: not filtered"
        warn_others ;;
    test)
        is_port "$SECS" || die "test SECONDS must be a number"
        preflight; apply_rules; start_timer
        report_conns
        say "TEST MODE: rules undo themselves in ${SECS}s. Check the scoreboard and your services now, then run: firewall.sh confirm"
        warn_others ;;
    confirm)
        [ -f "$DIR/pending" ] || { say "nothing pending (no test running, or it already reverted: see $DIR/history.log)"; exit 0; }
        stop_timer; echo "$(date '+%F %T') confirmed" >> "$DIR/history.log"; say "kept. Rules stay until 'revert' or a reboot ('apply --saved' after a reboot)" ;;
    apply)
        preflight; stop_timer; apply_rules; report_conns; warn_others ;;
    revert)
        stop_timer; [ -f "$DIR/revert.sh" ] && sh "$DIR/revert.sh" manual; say "firewall rules removed" ;;
    status)
        [ -f "$DIR/config" ] && . "$DIR/config"
        [ -f "$DIR/pending" ] && say "TEST MODE: auto-revert pending (run 'confirm' to keep)"
        if nft list table ip ccdc >/dev/null 2>&1; then say "nft table ip ccdc:"; nft list table ip ccdc | grep -E 'counter|elements' | sed "s/^/[$h]   /"
        elif iptables -S CCDC-IN >/dev/null 2>&1; then say "iptables chains:"; iptables -L CCDC-IN -n -v 2>/dev/null | awk '/DROP/' | sed "s/^/[$h]   /"; iptables -L CCDC-OUT -n -v 2>/dev/null | awk '/DROP/' | sed "s/^/[$h]   /"
        else say "firewall OFF (no ccdc rules loaded)"; fi
        drops=$( { journalctl -k --no-pager -n 3000 2>/dev/null || dmesg 2>/dev/null; } | grep 'CCDC-DROP' )
        if [ -n "$drops" ]; then
            say "top dropped sources (last 3000 kernel log lines):"
            echo "$drops" | grep -oE 'CCDC-DROP-(IN|OUT).*SRC=[0-9.]+ DST=[0-9.]+.*DPT=[0-9]+' | sed -E 's/CCDC-DROP-(IN|OUT).*SRC=([0-9.]+) DST=([0-9.]+).*DPT=([0-9]+)/\1 \2 -> \3:\4/' | sort | uniq -c | sort -rn | head -10 | sed "s/^/[$h]   /"
            say "if one of these is the scorer or a teammate: re-run 'apply --saved --trusted <old list>,<that IP>' or 'revert'"
        fi
        warn_others ;;
    *)
        sed -n '2,35p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'; exit 1 ;;
esac

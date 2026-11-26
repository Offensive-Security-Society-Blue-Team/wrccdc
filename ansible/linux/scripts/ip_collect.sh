#!/bin/sh
# ip_collect.sh - READ-ONLY. Runs on each box (pushed by ip_map.sh). Summarizes every remote IP this box has seen:
# SSH logins (with key fingerprint / certificate ID), failed logins, web requests (attack patterns, tool user-agents,
# activity spread over time), FTP and SMB clients, live connections (incl. shells holding sockets), firewall drops.
# Output: one pipe-separated summary line per IP and source; ip_map.sh on the laptop turns it into the who-is-who table.
# Ideas from CPP blue inject/*log.sh, DSU ace injects and UCI LOCS log tooling; our own code.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
case "${1:-}" in
    -h|--help) cat >&2 <<'USAGE'
usage: ip_collect.sh     (READ-ONLY; run as root so it can read the logs; normally pushed by ./ip_map.sh)
  ./ip_map.sh                                        <- use this from the laptop
  ansible haf -m script -a "scripts/ip_collect.sh"   raw collector output for one box
USAGE
        exit 0 ;;
    ?*) echo "error: unknown option: $1 (try -h)" >&2; exit 1 ;;
esac
R=${IPMAP_ROOT:-}                      # test hook: read logs under another root
N=${IPMAP_LINES:-60000}                # newest lines read per log file
IPRE='[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+'
h=$(hostname -s 2>/dev/null || hostname)
has() { command -v "$1" >/dev/null 2>&1; }
echo "HOST|$h"

# ---- this box: own addresses, gateway, DNS (so they aren't mistaken for anyone) ----
if [ -z "$R" ]; then
    ip -4 -o addr show 2>/dev/null | awk '$2 != "lo" {split($4, a, "/"); print "SELF|" a[1] "|" $4}'
    ip -4 route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "via") print "GW|" $(i + 1)}'
fi
awk '/^nameserver/ {print "DNS|" $2}' "$R/etc/resolv.conf" 2>/dev/null | grep -E "^DNS\|$IPRE$"

# ---- SSH: successful and failed logins ----
authlines() {
    found=0
    for f in "$R"/var/log/auth.log "$R"/var/log/auth.log.1 "$R"/var/log/secure "$R"/var/log/secure-* "$R"/var/log/messages; do
        [ -f "$f" ] || continue
        tail -n "$N" "$f" 2>/dev/null | grep -E 'sshd|sshd-session|pam_unix' && found=1
    done
    if [ "$found" = 0 ] && [ -z "$R" ] && has journalctl; then
        journalctl -n "$N" --no-pager -o short -t sshd -t sshd-session 2>/dev/null
    fi
}
authlines | awk -v IPRE="$IPRE" '
function minute(line) {
    if (match(line, /^[A-Z][a-z][a-z] +[0-9]+ [0-9][0-9]:[0-9][0-9]/)) return substr(line, RSTART, RLENGTH)
    if (match(line, /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]/)) return substr(line, RSTART, RLENGTH)
    return "?"
}
{
    ip = ""; user = ""; fi = 0
    for (i = 1; i <= NF; i++) if ($i == "from" && $(i + 1) ~ "^" IPRE "$") { ip = $(i + 1); user = $(i - 1); fi = i; break }
    if (ip == "" && match($0, /rhost=[0-9.]+/)) { ip = substr($0, RSTART + 6, RLENGTH - 6); if (match($0, /user=[^ ]+/)) user = substr($0, RSTART + 5, RLENGTH - 5) }
    if (ip == "") next
    m = minute($0)
    if ($0 ~ /Accepted /) {
        meth = ""; for (i = 1; i <= NF; i++) if ($i == "Accepted") { meth = $(i + 1); user = $(i + 3) }
        kt = "-"; fp = "-"; cid = "-"
        for (i = 1; i <= NF; i++) {
            if ($i == "ssh2:") { kt = $(i + 1); fp = $(i + 2) }
        }
        # whole key ID (it can contain spaces): text between " ID " and " (serial"
        if (match($0, / ID .* \(serial /)) { cid = substr($0, RSTART + 4, RLENGTH - 13); if (cid == "") cid = "(empty)" }
        gsub(/\|/, "", user); gsub(/\|/, "", cid)
        k = ip SUBSEP user SUBSEP meth SUBSEP kt SUBSEP fp SUBSEP cid
        ok[k]++; if (!(k in okf)) okf[k] = m; okl[k] = m
        okmin[ip SUBSEP m] = 1
    } else if ($0 ~ /Failed |Invalid user|authentication failure/) {
        if ($0 ~ /Failed / && $0 ~ /message repeated/) next
        fail[ip]++; if (!(ip in ff)) ff[ip] = m; fl[ip] = m
        if (!((ip SUBSEP user) in fu)) { fu[ip SUBSEP user] = 1; fusers[ip]++ }
        uc[user]++
    }
}
END {
    for (k in ok) { split(k, a, SUBSEP); print "SSHOK|" a[1] "|" a[2] "|" a[3] "|" a[4] "|" a[5] "|" a[6] "|" ok[k] "|" okf[k] "|" okl[k] }
    for (ip in fail) print "SSHFAIL|" ip "|" fail[ip] "|" fusers[ip] "|" ff[ip] "|" fl[ip]
    for (u in uc) { x = u; gsub(/\|/, "", x); print "SSHUSER|" x "|" uc[u] }
    for (k in okmin) { split(k, a, SUBSEP); om[a[1]]++ }
    for (ip in om) print "SSHMIN|" ip "|" om[ip]
}'

# ---- Web servers (combined/common log format) ----
for f in "$R"/var/log/nginx/*access*log "$R"/var/log/apache2/*access*log "$R"/var/log/httpd/*access*log "$R"/var/log/lighttpd/access.log "$R"/var/log/caddy/*.log "$R"/var/www/*/logs/*access*log; do
    [ -f "$f" ] && tail -n "$N" "$f" 2>/dev/null
done | awk -v IPRE="$IPRE" '
$1 ~ "^" IPRE "$" {
    ip = $1; n[ip]++
    m = substr($4, 2, 17); if (!((ip SUBSEP m) in seen)) { seen[ip SUBSEP m] = 1; mins[ip]++ }
    if (!(ip in first)) first[ip] = m; last[ip] = m
    split($0, q, "\""); req = tolower(q[2]); split(q[3], st, " "); ua = q[6]; lua = tolower(ua)
    if (st[1] ~ /^4/) c4[ip]++
    # login/admin pages the scorer checks too (WordPress, phpMyAdmin, Tomcat): counted apart, not as attacks
    if (req ~ /wp-login|xmlrpc|phpmyadmin|manager\/html|cgi-bin/) probe[ip]++
    if (req ~ /\.\.\/|%2e%2e|etc\/passwd|union[ +%20]*select|select.*from|<script|%3cscript|cmd=|exec=|bin\/sh|bin%2fsh|jndi:|\$\{|\.env|\.git\/|\/shell|eval\(|base64_decode/) {
        atk[ip]++; if (!(ip in sample)) { s = q[2]; gsub(/\|/, "", s); sample[ip] = substr(s, 1, 70) }
    }
    if (lua ~ /sqlmap|nikto|nmap|gobuster|dirbuster|feroxbuster|ffuf|wfuzz|nuclei|hydra|masscan|zgrab|wpscan|burp|metasploit|zap/) { scan[ip]++; tool[ip] = ua }
    gsub(/\|/, "", ua); uac[ip SUBSEP substr(ua, 1, 60)]++
}
END {
    for (k in uac) { split(k, a, SUBSEP); if (uac[k] > best[a[1]]) { best[a[1]] = uac[k]; bua[a[1]] = a[2] } }
    for (ip in n) {
        t = tool[ip]; gsub(/\|/, "", t)
        print "WEB|" ip "|" n[ip] "|" c4[ip] + 0 "|" atk[ip] + 0 "|" scan[ip] + 0 "|" mins[ip] "|" first[ip] "|" last[ip] "|" bua[ip] "|" substr(t, 1, 40) "|" sample[ip] "|" probe[ip] + 0
    }
}'

# ---- FTP (vsftpd) and SMB (per-client samba logs) ----
for f in "$R"/var/log/vsftpd.log "$R"/var/log/xferlog; do [ -f "$f" ] && tail -n "$N" "$f"; done 2>/dev/null | awk -v IPRE="$IPRE" '
/OK LOGIN|FAIL LOGIN/ { if (match($0, IPRE)) { ip = substr($0, RSTART, RLENGTH); if ($0 ~ /OK LOGIN/) ok[ip]++; else bad[ip]++; all[ip] = 1 } }
END { for (ip in all) print "FTP|" ip "|" ok[ip] + 0 "|" bad[ip] + 0 }'
for f in "$R"/var/log/samba/log.*; do
    [ -f "$f" ] || continue
    ip=${f##*/log.}
    echo "$ip" | grep -Eq "^$IPRE$" && echo "SMB|$ip|$(wc -l < "$f" | tr -d ' ')"
done

# ---- live TCP connections (shells holding sockets = likely reverse/bind shells) ----
if [ -z "$R" ]; then
    lports=$({ ss -tln 2>/dev/null || netstat -tln 2>/dev/null; } | awk 'NR > 1 {n = split($4, a, ":"); print a[n]}' | sort -u | tr '\n' ' ')
    { if has ss; then ss -tnp 2>/dev/null | awk '$1 == "ESTAB" {print $4, $5, $6}'
      else netstat -tnp 2>/dev/null | awk '$6 == "ESTABLISHED" {print $4, $5, $7}'; fi; } |
    awk -v lp=" $lports " -v IPRE="$IPRE" '{
        nl = split($1, l, ":"); nr = split($2, r, ":"); ip = r[nr - 1]; sub(/^\[?(::ffff:)?/, "", ip); sub(/\]$/, "", ip)
        if (ip !~ "^" IPRE "$" || ip ~ /^127\./) next
        pr = $3; sub(/.*\(\("/, "", pr); sub(/".*/, "", pr); sub(/^[0-9]+\//, "", pr); if (pr == "") pr = "?"
        dir = (index(lp, " " l[nl] " ") > 0) ? "in" : "out"
        print "CONN|" ip "|" dir "|" l[nl] "|" r[nr] "|" pr
    }' | sort -u
fi

# ---- firewall drops from firewall.sh (CCDC-DROP log prefix) ----
if [ -z "$R" ]; then
    { journalctl -k --no-pager -n 5000 2>/dev/null || dmesg 2>/dev/null; } | grep 'CCDC-DROP' |
    awk '{ d = ($0 ~ /CCDC-DROP-IN/) ? "in" : "out"; s = ""; t = ""; p = ""
           for (i = 1; i <= NF; i++) { if ($i ~ /^SRC=/) s = substr($i, 5); if ($i ~ /^DST=/) t = substr($i, 5); if ($i ~ /^DPT=/) p = substr($i, 5) }
           ip = (d == "in") ? s : t; k = ip SUBSEP d; c[k]++; if (index(ps[k], " " p " ") == 0) ps[k] = ps[k] " " p " " }
         END { for (k in c) { split(k, a, SUBSEP); x = ps[k]; gsub(/  +/, " ", x); print "DROP|" a[1] "|" a[2] "|" c[k] "|" x } }'
fi

# ---- login records outside the text logs ----
if [ -z "$R" ]; then
    last -i 2>/dev/null | awk -v IPRE="$IPRE" '$3 ~ "^" IPRE "$" && $3 != "0.0.0.0" {c[$3 SUBSEP $1]++} END {for (k in c) {split(k, a, SUBSEP); print "WTMP|" a[1] "|" a[2] "|" c[k]}}'
    lastb -i 2>/dev/null | awk -v IPRE="$IPRE" '$3 ~ "^" IPRE "$" {c[$3]++} END {for (ip in c) print "BTMP|" ip "|" c[ip]}'
fi

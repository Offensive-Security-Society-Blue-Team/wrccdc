#!/bin/sh
# vuln_hunt.sh v2 - READ-ONLY, tech-agnostic. Hunts attack PATTERNS, not products:
#   1. What isn't stock?        (custom services, containers, workloads, source code)
#   2. Who can become root?     (ssh trust, sudo, root-equal groups, suid/caps, writable root code,
#                                container escapes, k8s RBAC/anon access, CI runners, cron, NFS)
#   3. What is still default?   (default passwords, secrets in env, versions, firewall, risky listeners)
#   4. What was planted?        (shell/login/PAM/loader hooks, temp-dir binaries, reverse shells, web shells,
#                                immutable files, remote shells) with created/modified dates for the timeline
# Sections for Docker/Podman/Kubernetes/CI turn on only when detected.
#   ansible linux -m script -a "scripts/vuln_hunt.sh SMBlyRequired '2026-11-21 09:00'" > loot/hunt-$(date +%H%M).txt
#   arg 1 = default password to search for; arg 2 (optional) = game start time: each dated file is tagged BEFORE-START or after-start
#   grep -E '####|FLAG' loot/hunt-*.txt        <- the short list
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
DEF=${1:-SMBlyRequired}
START=${2:-}
START_TS=""; [ -n "$START" ] && START_TS=$(date -d "$START" +%s 2>/dev/null)
BADPAT='curl |wget |/dev/tcp|/dev/udp|base64 -d|base64 --decode|bash -i|sh -i|nc -e|ncat |socat |mkfifo|python[0-9.]* -c|perl -e|ruby -e|php -r|nohup |asciinema|chattr |\| *(ba)?sh( |$)'
# fd FILE -> [born MM-DD HH:MM, chg MM-DD HH:MM, BEFORE-START|after-start]
fd() {
    [ -e "$1" ] || return 0
    m=$(stat -c %Y "$1" 2>/dev/null); b=$(stat -c %W "$1" 2>/dev/null)
    case "$b" in ''|*[!0-9]*|0) b="";; esac
    t=${b:-$m}
    bs="?"; [ -n "$b" ] && bs=$(date -d "@$b" '+%m-%d %H:%M' 2>/dev/null)
    ms=$(date -d "@$m" '+%m-%d %H:%M' 2>/dev/null)
    tag=""; if [ -n "$START_TS" ] && [ -n "$t" ]; then if [ "$t" -lt "$START_TS" ]; then tag=", BEFORE-START"; else tag=", after-start"; fi; fi
    echo "[born $bs, chg $ms$tag]"
}
h=$(hostname -s 2>/dev/null || hostname)
has() { command -v "$1" >/dev/null 2>&1; }
flag() { echo "  FLAG: $*"; }
# owned FILE -> true if a package manager owns it (handles /lib vs /usr/lib merges)
owned() {
    for q in "$1" "$(readlink -f "$1" 2>/dev/null)" "/usr$1" "${1#/usr}"; do
        [ -n "$q" ] || continue
        if has dpkg; then dpkg -S "$q" >/dev/null 2>&1 && return 0
        elif has rpm; then rpm -qf "$q" >/dev/null 2>&1 && return 0
        elif has apk; then apk info --who-owns "$q" >/dev/null 2>&1 && return 0
        else return 0; fi
    done
    return 1
}
echo "################ $h"
tech=""; for t in docker podman kubectl k3s crictl gitea act_runner gitlab-runner java php nginx httpd apache2 mysqld mariadbd postgres redis-server mongod; do has "$t" && tech="$tech $t"; done
echo "detected:$tech"

echo "== 1. NOT STOCK: custom services"
for u in /etc/systemd/system/*.service /etc/containers/systemd/*.container; do
    [ -f "$u" ] && [ ! -L "$u" ] || continue
    echo "  $(basename "$u"): $(grep -hE '^(ExecStart|Exec|Image|User)=' "$u" | head -3 | tr '\n' ' ')"
done
has systemctl || ls /etc/init.d 2>/dev/null | tr '\n' ' ' | sed 's/^/  init.d: /'; echo
echo "== 1. NOT STOCK: custom code, source and docs on the box"
for d in /usr/local/bin /usr/local/sbin /usr/local/libexec /usr/local/src /opt /srv /var/www; do
    [ -d "$d" ] && echo "  $d: $(ls "$d" 2>/dev/null | head -30 | tr '\n' ' ')"
done
find /usr/local/src /opt /srv /var/www -maxdepth 4 -type f \( -name '*.go' -o -name '*.py' -o -name '*.php' -o -name '*.js' -o -name '*.rb' -o -name '*.java' -o -name '*.sh' -o -name 'README*' -o -name '*.md' -o -name 'Dockerfile' -o -name 'Containerfile' -o -name '*compose*.y*ml' -o -name '*.tf' \) 2>/dev/null | grep -vE '/(node_modules|vendor|\.git)/' | head -30 | sed 's/^/  src: /'

echo "== 2. ROOT VIA SSH"
sshd -T 2>/dev/null | grep -iE '^(permitrootlogin|passwordauthentication|trustedusercakeys|authorizedprincipalsfile|authorizedprincipalscommand |authorizedkeysfile)' | sed 's/^/  /'
sshd -T 2>/dev/null | grep -qi '^passwordauthentication yes' && sshd -T 2>/dev/null | grep -qi '^permitrootlogin yes' && flag "root can log in with a password over SSH"
tc=$(sshd -T 2>/dev/null | awk '/^trustedusercakeys/{print $2}')
[ -f "$tc" ] && flag "sshd trusts $(grep -c . "$tc") user CA(s) in $tc: find out who can sign with them"
pc=$(sshd -T 2>/dev/null | awk '/^authorizedprincipalscommand /{print $2}')
[ -x "$pc" ] && echo "  principals accepted for root: $($pc root 2>/dev/null | tr '\n' ' ')"
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
    [ -f "$f" ] || continue
    grep -vE '^[[:space:]]*(#|$)' "$f" | awk -v f="$f" '{ if ($1 ~ /^(ssh-|ecdsa-|sk-)/) print "  key " f ": " $1, $NF; else print "  OPTIONS " f ": " $1, $2 }'
    grep -q 'cert-authority' "$f" && flag "$f trusts a CA (cert-authority): who can sign for it?"
done

echo "== 2. ROOT VIA SUDO / GROUPS / ACCOUNTS"
grep -rhE '^[^#[:space:]]' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -vE '^(Defaults|@include)' | sed 's/^/  sudo: /'
grep -rhE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | while read -r l; do flag "NOPASSWD: $l"; done
grep -rhiE '^%domain[ \\]+users' /etc/sudoers.d/ 2>/dev/null | while read -r l; do flag "every domain user gets sudo: $l"; done
[ -f /etc/sssd/sssd.conf ] && grep -hE 'access_provider' /etc/sssd/sssd.conf | grep -q permit && flag "sssd access_provider=permit: every directory account can log in"
for g in docker lxd lxc disk; do
    m=$(awk -F: -v g="$g" '$1==g{print $4}' /etc/group)
    [ -n "$m" ] && flag "group $g is root-equivalent; members: $m"
done
awk -F: '$3==0 && $1!="root"{print "  FLAG: extra UID 0 account: " $1}' /etc/passwd
awk -F: '$3>0 && $3<1000 && $7 !~ /(nologin|false|sync|halt|shutdown)$/ {print "  FLAG: service account with a shell: " $1 " " $7}' /etc/passwd
awk -F: '$2==""{print "  FLAG: empty password: " $1}' /etc/shadow 2>/dev/null

echo "== 2. ROOT VIA SUID / CAPABILITIES / WRITABLE ROOT CODE"
SUID=$(find / -xdev -perm -4000 -type f 2>/dev/null)
echo "$SUID" | grep -vE '^/(usr/)?(s?bin|lib|lib64|libexec)/' | sed 's/^/  FLAG: suid outside system dirs: /'
echo "$SUID" | grep -E '/(find|vim?|nano|less|more|bash|sh|dash|python[0-9.]*|perl|ruby|php|node|nmap|cp|mv|tar|zip|awk|env|docker|systemctl|openssl|base64|tee)$' | sed 's/^/  FLAG: suid on a shell-capable binary (GTFOBins): /'
has getcap && getcap -r /usr /bin /sbin /opt /usr/local 2>/dev/null | grep -E 'cap_(setuid|setgid|dac_override|dac_read_search|sys_admin|sys_ptrace|chown|fowner)' | sed 's/^/  FLAG: dangerous file capability: /'
find /etc/cron* /etc/systemd/system /etc/init.d /usr/local/bin /usr/local/sbin /opt -xdev -perm -0002 -type f 2>/dev/null | head -20 | sed 's/^/  FLAG: world-writable file in a root code path: /'
[ -f /etc/exports ] && grep -E 'no_root_squash|\*\(' /etc/exports | sed 's/^/  FLAG: risky NFS export: /'

echo "== 2. CODE THAT RUNS AS ROOT ON A SCHEDULE OR ON DEMAND"
crontab -l 2>/dev/null | grep -vE '^[[:space:]]*(#|$)' | sed 's/^/  root cron: /'
grep -hvE '^[[:space:]]*(#|$|SHELL|PATH|MAILTO)' /etc/crontab /etc/cron.d/* 2>/dev/null | sed 's/^/  cron: /' | head -20
has systemctl && systemctl list-timers --all --no-legend 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i ~ /\.timer$/) print "  timer:", $i}'
ps -eo user,args 2>/dev/null | grep -iE 'act_runner|gitlab-runner|jenkins|Runner\.Listener|drone|buildkite|woodpecker|ansible-pull|salt-minion|puppet|chef-client' | grep -v grep | while read -r l; do flag "CI/config agent (whoever controls its repo/server controls this box): $l"; done

for eng in docker podman; do
    has "$eng" || continue
    echo "== 2. CONTAINERS ($eng): escape paths"
    $eng ps -q 2>/dev/null | while read -r id; do
        $eng inspect --format '{{.Name}} image={{.Config.Image}} user={{.Config.User}} priv={{.HostConfig.Privileged}} net={{.HostConfig.NetworkMode}} pid={{.HostConfig.PidMode}} caps={{.HostConfig.CapAdd}} mounts={{range .Mounts}}{{.Source}}:{{.Destination}},{{end}}' "$id" 2>/dev/null
    done | while read -r l; do
        echo "  $l"
        case "$l" in *priv=true*) flag "privileged container: ${l%% *}";; esac
        case "$l" in *mounts=/:*|*,/:*|*docker.sock*|*podman.sock*|*/etc:*|*/root:*) flag "host path mounted into container: ${l%% *}";; esac
        case "$l" in *pid=host*|*net=host*) flag "container shares host pid/net: ${l%% *}";; esac
        case "$l" in *SYS_ADMIN*|*ALL*) flag "container has dangerous caps: ${l%% *}";; esac
    done
    echo "== 3. CONTAINERS ($eng): secrets in environment (names only)"
    $eng ps -q 2>/dev/null | while read -r id; do
        n=$($eng inspect --format '{{.Name}}' "$id")
        $eng inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$id" 2>/dev/null | grep -iE '^[^=]*(pass|secret|token|key|cred)[^=]*=' | while IFS='=' read -r k v; do
            case "$v" in *"$DEF"*) flag "$n env $k = the default password";; *) echo "  $n env $k (set)";; esac
        done
    done
done
for s in /var/run/docker.sock /run/podman/podman.sock; do
    [ -S "$s" ] && ls -l "$s" | awk -v s="$s" '{print "  socket " s ": " $1, $3, $4}' && [ -n "$(find "$s" -perm -o+w 2>/dev/null)" ] && flag "$s is world-writable: any user is root"
done

KC=""; has kubectl && KC="kubectl"; has k3s && KC="k3s kubectl"
if [ -n "$KC" ]; then
    echo "== 2. KUBERNETES: who can become cluster-admin / reach the node"
    $KC get nodes --no-headers 2>/dev/null | sed 's/^/  node: /'
    $KC get clusterrolebindings -o jsonpath='{range .items[?(@.roleRef.name=="cluster-admin")]}{.metadata.name}{" -> "}{.subjects[*].kind}{":"}{.subjects[*].name}{"\n"}{end}' 2>/dev/null | sed 's/^/  cluster-admin: /'
    $KC get clusterrolebindings -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.subjects[*].name}{"\n"}{end}' 2>/dev/null | grep -E 'system:(anonymous|unauthenticated)|system:serviceaccounts( |$)' | sed 's/^/  FLAG: binding to anonymous or all service accounts: /'
    $KC get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" priv="}{.spec.containers[*].securityContext.privileged}{" hostPath="}{.spec.volumes[*].hostPath.path}{" hostNet="}{.spec.hostNetwork}{" hostPID="}{.spec.hostPID}{" sa="}{.spec.serviceAccountName}{"\n"}{end}' 2>/dev/null | while read -r l; do
        echo "  pod $l"
        case "$l" in *priv=true*|*hostPath=/*|*hostNet=true*|*hostPID=true*) flag "pod can reach the node: ${l%% *}";; esac
    done
    echo "  secrets: $($KC get secrets -A --no-headers 2>/dev/null | wc -l) (check for defaults)"
    for u in https://127.0.0.1:6443/api https://127.0.0.1:10250/pods http://127.0.0.1:10255/pods; do
        c=$(curl -sk -m3 -o /dev/null -w '%{http_code}' "$u" 2>/dev/null)
        echo "  anon $u -> $c"; [ "$c" = 200 ] && flag "unauthenticated access works: $u"
    done
fi

echo "== 3. DEFAULTS: files containing '$DEF'"
grep -rlI "$DEF" /etc /opt /srv /var/www /usr/local /root 2>/dev/null | head -25 | sed 's/^/  FLAG: default password in: /'
echo "== 3. DEFAULTS: versions (search these for CVEs)"
echo "  kernel $(uname -r) | $(ssh -V 2>&1) | $(openssl version 2>/dev/null) | $(sudo -V 2>/dev/null | head -1)"
for b in docker podman runc containerd kubectl k3s gitea php nginx httpd mysqld postgres redis-server java; do
    has "$b" && echo "  $b: $($b --version 2>/dev/null || $b -v 2>&1 || $b version 2>/dev/null | head -1)" | head -1
done
has pkexec && echo "  pkexec: $(pkexec --version 2>/dev/null)"
has apk && apk list --installed 2>/dev/null | grep -iE 'openssh|dropbear|luci|uhttpd' | sed 's/^/  /'
echo "== 3. DEFAULTS: firewall"
iptables -S 2>/dev/null | grep '^-P' | sed 's/^/  /'
iptables -S INPUT 2>/dev/null | grep -q '^-P INPUT ACCEPT' && [ "$(iptables -S INPUT 2>/dev/null | wc -l)" -le 1 ] && ! has firewall-cmd && flag "no host firewall rules (INPUT ACCEPT, empty)"
has firewall-cmd && echo "  firewalld: $(firewall-cmd --state 2>&1)"
has uci && uci show firewall 2>/dev/null | grep -E "zone.*\.(name|input)=" | sed 's/^/  /' && uci show firewall 2>/dev/null | grep -A3 "name='wan'" | grep -q "input='ACCEPT'" && flag "router WAN input is ACCEPT"
echo "== 3. LISTENERS ON ALL INTERFACES (risky ones flagged)"
{ ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null; } | awk '$4 ~ /^(0\.0\.0\.0|\*|\[::\]|::):/ {print $4, $NF}' | while read -r a p; do
    port=${a##*:}; echo "  $a $p"
    case "$port" in
        2375|2376) flag "Docker API exposed on $port";;
        2379|2380) flag "etcd exposed on $port";;
        10250|10255) flag "kubelet exposed on $port";;
        6379) flag "Redis exposed (often no auth)";;
        9200) flag "Elasticsearch exposed (often no auth)";;
        27017) flag "MongoDB exposed (often no auth)";;
        3306|5432) flag "database exposed on $port: check default/weak DB users";;
        5000|5001) flag "possible container registry on $port";;
        8080|8000|8081|8443|9000|3000) flag "custom/admin web service on $port: read its source/docs";;
    esac
done
echo "== 4. PLANTED PERSISTENCE (dates: born = created, chg = last modified$( [ -n "$START_TS" ] && echo ", vs start $START"))"
# login and shell hooks that run code
for f in /etc/profile /etc/profile.d/* /etc/bash.bashrc /etc/bashrc /etc/environment /root/.bashrc /root/.profile /root/.bash_profile /root/.bash_login /root/.zshrc /home/*/.bashrc /home/*/.profile /home/*/.bash_profile /etc/ssh/sshrc /root/.ssh/rc /home/*/.ssh/rc /etc/rc.local /etc/update-motd.d/*; do
    [ -f "$f" ] || continue
    case "$f" in /etc/update-motd.d/*) owned "$f" && continue;; esac
    grep -nE "$BADPAT" "$f" 2>/dev/null | grep -vE '^[0-9]+:[[:space:]]*#' | head -3 | while read -r l; do flag "code hook in $f $(fd "$f"): $l"; done
done
for f in /etc/ssh/sshrc /root/.ssh/rc /home/*/.ssh/rc; do [ -f "$f" ] && flag "ssh rc file runs on every login: $f $(fd "$f")"; done
# loader and PAM hooks
[ -s /etc/ld.so.preload ] && flag "ld.so.preload loads into every process $(fd /etc/ld.so.preload): $(tr '\n' ' ' < /etc/ld.so.preload)"
grep -rnE 'pam_exec|pam_script' /etc/pam.d/ 2>/dev/null | grep -vE '^[^:]*:[0-9]+:[[:space:]]*#' | head -5 | sed 's/^/  FLAG: PAM runs a program at login: /'
grep -rnE '^[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+pam_permit' /etc/pam.d/ 2>/dev/null | head -5 | sed 's/^/  FLAG: PAM lets anyone in without a password: /'
ref=$(ls /lib*/security/pam_unix.so /usr/lib*/security/pam_unix.so /lib/*/security/pam_unix.so /usr/lib/*/security/pam_unix.so 2>/dev/null | head -1)
[ -n "$ref" ] && for f in "$(dirname "$ref")"/*.so; do
    owned "$f" || flag "PAM module not owned by any package (likely backdoor): $f $(fd "$f")"
done
# cron, at, udev, user systemd: entries that fetch or open shells
grep -rnE "$BADPAT" /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /var/spool/cron 2>/dev/null | sort -u | head -10 | while read -r l; do flag "suspicious cron: $l"; done
has atq && [ -n "$(atq 2>/dev/null)" ] && flag "at jobs queued: $(atq 2>/dev/null | wc -l)"
grep -rnE 'RUN\+?=' /etc/udev/rules.d/ 2>/dev/null | head -5 | while read -r l; do flag "udev rule runs a program: $l"; done
for u in /etc/systemd/system/*.service /root/.config/systemd/user/*.service /home/*/.config/systemd/user/*.service; do
    [ -f "$u" ] || continue
    grep -qE '^Exec[A-Za-z]*=.*(/tmp/|/dev/shm/|/var/tmp/|/\.[A-Za-z0-9_-]+|curl|wget|/dev/tcp|base64|nc |ncat|socat|bash -i|python[0-9.]* -c)' "$u" && flag "service runs from a temp/hidden path or opens a shell: $u $(fd "$u")"
done
# immutable files (red team uses chattr +i to block your fixes)
has lsattr && for d in /etc /etc/ssh /etc/cron.d /etc/systemd/system /etc/pam.d /root /root/.ssh /usr/local/bin; do
    lsattr -d "$d" "$d"/* 2>/dev/null | awk '$1 ~ /i/ {print $2}'
done | sort -u | head -10 | while read -r f; do flag "immutable (chattr +i): $f $(fd "$f")"; done
# executables in temp dirs, processes running from temp or deleted files
find /tmp /var/tmp /dev/shm /run/user -xdev -maxdepth 2 -type f -perm -u+x 2>/dev/null | head -10 | while read -r f; do flag "executable in temp dir: $f ($(wc -c < "$f" 2>/dev/null) bytes) $(fd "$f")"; done
for p in /proc/[0-9]*; do
    e=$(readlink "$p/exe" 2>/dev/null) || continue
    case "$e" in /tmp/*|/var/tmp/*|/dev/shm/*|*"(deleted)"*|*/.*) flag "process ${p#/proc/} runs $e: $(tr '\0' ' ' < "$p/cmdline" 2>/dev/null | cut -c1-80)";; esac
done
# shells and interpreters holding network sockets = reverse/bind shells
{ ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null; } | grep -E '"(bash|sh|dash|ash|zsh|python[0-9.]*|perl|ruby|php|nc|ncat|socat|node|lua)"|/(bash|sh|python[0-9.]*|perl|nc|ncat|socat)$' | head -10 | while read -r l; do flag "shell/interpreter with a network socket: $l"; done
# browser shells and remote admin panels
ps -eo args 2>/dev/null | grep -iE 'shellinabox|ttyd|gotty|webmin|miniserv|cockpit-ws|wetty|sshwifty|filebrowser' | grep -v grep | head -5 | while read -r l; do flag "remote shell/admin panel running: $l"; done
# web shells in web roots
for w in /var/www /srv /usr/share/nginx /var/lib/tomcat*; do
    [ -d "$w" ] || continue
    grep -rlIE --include='*.php' --include='*.phtml' --include='*.jsp' --include='*.asp*' --include='*.py' --include='*.cgi' 'eval\(\$_(GET|POST|REQUEST|COOKIE)|(system|shell_exec|passthru|exec|popen|proc_open|assert)\(\$_(GET|POST|REQUEST|COOKIE)|base64_decode\(\$_|Runtime\.getRuntime\(\)\.exec\(request' "$w" 2>/dev/null | head -5 | while read -r f; do flag "possible web shell: $f $(fd "$f")"; done
done
# keys and accounts dated for the timeline
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys /etc/passwd /etc/shadow /etc/sudoers /etc/sudoers.d/* /etc/crontab /var/spool/cron/crontabs/root /var/spool/cron/root; do
    [ -f "$f" ] && echo "  dated: $f $(fd "$f")"
done
echo "== 4. LOGINS BEFORE AND DURING THE GAME (last 10)"
last -F -n 10 2>/dev/null | grep -vE '^(wtmp|$)' | sed 's/^/  /'
echo "################ end $h"
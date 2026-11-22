#!/bin/sh
# vuln_hunt.sh v2 - READ-ONLY, tech-agnostic. Hunts attack PATTERNS, not products:
#   1. What isn't stock?        (custom services, containers, workloads, source code)
#   2. Who can become root?     (ssh trust, sudo, root-equal groups, suid/caps, writable root code,
#                                container escapes, k8s RBAC/anon access, CI runners, cron, NFS)
#   3. What is still default?   (default passwords, secrets in env, versions, firewall, risky listeners)
# Sections for Docker/Podman/Kubernetes/CI turn on only when detected.
#   ansible linux -m script -a "scripts/vuln_hunt.sh SMBlyRequired" > loot/hunt-$(date +%H%M).txt
#   grep -E '####|FLAG' loot/hunt-*.txt        <- the short list
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
DEF=${1:-SMBlyRequired}
h=$(hostname -s 2>/dev/null || hostname)
has() { command -v "$1" >/dev/null 2>&1; }
flag() { echo "  FLAG: $*"; }
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
echo "################ end $h"

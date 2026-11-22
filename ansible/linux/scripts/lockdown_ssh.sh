#!/bin/sh
# lockdown_ssh.sh - close the red team SSH doors found at INV3. Safe to re-run.
#  1. move the planted /etc/ssh/.ssh key file (it worked for EVERY account)
#  2. remove red team keys from root (kali@kali, deploy@management)
#  3. make sshd read keys only from each user's own ~/.ssh/authorized_keys
#  4. block certificate logins as root (forged-root-cert)
#  5. check the config with sshd -t, then reload (restores the backup if it fails)
#  6. show live connections that are NOT our VPN address (192.168.220.3)
# Usage (from ansible/linux):
#   ansible haf,djupi -m script -a scripts/lockdown_ssh.sh     # try two boxes first
#   ansible linux -m script -a scripts/lockdown_ssh.sh | grep -E "=====|FIXED|FAILED|ok:"
# On a box:  sudo sh lockdown_ssh.sh      Help: sh lockdown_ssh.sh -h
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
usage() {
    [ -n "${1:-}" ] && echo "error: $1" >&2
    cat >&2 <<'USAGE'
usage: lockdown_ssh.sh     (no arguments; CHANGES sshd; run as root)
  ansible haf,djupi -m script -a scripts/lockdown_ssh.sh
  ansible linux -m script -a scripts/lockdown_ssh.sh | grep -E "=====|FIXED|FAILED|ok:"
  sudo sh lockdown_ssh.sh
USAGE
    [ -n "${1:-}" ] && exit 1
    exit 0
}
case "${1:-}" in -h|--help) usage ;; esac
[ $# -eq 0 ] || usage "this script takes no arguments (got: $*)"
[ "$(id -u)" -eq 0 ] || usage "must run as root"
Q=/root/quarantine; T=$(date +%H%M%S); C=/etc/ssh/sshd_config
mkdir -p "$Q"
echo "===== $(hostname) ====="

if [ -d /etc/ssh/.ssh ]; then
    mv /etc/ssh/.ssh "$Q/etc-ssh-dot-ssh.$T" && echo "FIXED: moved /etc/ssh/.ssh to $Q/etc-ssh-dot-ssh.$T"
else
    echo "ok: no /etc/ssh/.ssh"
fi

if [ -f /root/.ssh/authorized_keys ]; then
    cp /root/.ssh/authorized_keys "$Q/root_keys.$T"
    sed -i -e '/kali@kali/d' -e '/deploy@management/d' /root/.ssh/authorized_keys
    echo "root keys now: $(awk '{print $NF}' /root/.ssh/authorized_keys | tr '\n' ' ')"
fi

cp "$C" "$Q/sshd_config.$T"
EFF=$(sshd -T 2>/dev/null | awk 'tolower($1) == "authorizedkeysfile" { $1 = ""; sub(/^ /, ""); print }')
if [ "$EFF" != ".ssh/authorized_keys" ]; then
    { printf 'AuthorizedKeysFile .ssh/authorized_keys\nAuthorizedKeysCommand none\n'; cat "$C"; } > "$C.new" && cat "$C.new" > "$C"
    rm -f "$C.new"
    echo "FIXED: AuthorizedKeysFile was '$EFF'"
else
    echo "ok: AuthorizedKeysFile .ssh/authorized_keys"
fi

touch /etc/ssh/root_principals_none && chmod 644 /etc/ssh/root_principals_none
if ! grep -q root_principals_none "$C"; then
    printf '\nMatch User root\n    AuthorizedPrincipalsFile /etc/ssh/root_principals_none\n' >> "$C"
    echo "FIXED: certificate logins as root blocked"
else
    echo "ok: certificate logins as root already blocked"
fi

if sshd -t; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || rc-service sshd reload 2>/dev/null \
        || kill -HUP "$(cat /var/run/sshd.pid 2>/dev/null)" 2>/dev/null
    echo "sshd reloaded. root now uses: $(sshd -T -C user=root,host=x,addr=10.194.194.85 2>/dev/null | grep -iE '^(authorizedkeysfile|authorizedprincipalsfile) ' | tr '\n' ' ')"
else
    cat "$Q/sshd_config.$T" > "$C"
    echo "FAILED: sshd -t rejected the new config - old config restored, nothing changed"
fi

echo "-- logged in"; who
echo "-- live connections not from 192.168.220.3 (red team or scoring - check each)"
{ ss -tnp 2>/dev/null || netstat -tnp 2>/dev/null; } | grep ESTAB | grep -v '192.168.220.3' || echo "(none)"
true

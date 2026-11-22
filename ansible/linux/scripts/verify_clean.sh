#!/bin/sh
# verify_clean.sh [TEAM-KEY ...] - READ-ONLY. One line per box: CLEAN, or what the red team put back.
# Give it the team key blobs (the AAAA... part of each .pub line) and it also counts every key that is
# NOT a team key or a cert-authority line, in every authorized_keys file sshd reads (UNKNOWN-KEYS=n).
# Without keys it only checks for the known INV3 red team keys (RED-KEYS).
# Usage (from ansible/linux):
#   ansible linux -m script -a "scripts/verify_clean.sh $(awk '{print $2}' files/team_key.pub ~/.ssh/inv3.pub | sort -u | tr '\n' ' ')" | grep -E "certauth=|UNREACHABLE|FAILED"
#   ansible linux -m script -a scripts/verify_clean.sh | grep -E "certauth=|UNREACHABLE|FAILED"    # known red keys only
# On a box:  sudo sh verify_clean.sh AAAAC3Nza...      Help: sh verify_clean.sh -h
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
usage() {
    [ -n "${1:-}" ] && echo "error: $1" >&2
    cat >&2 <<'USAGE'
usage: verify_clean.sh [TEAM-KEY ...]     (READ-ONLY; key blobs = the AAAA... part of each team .pub line; run as root)
  ansible linux -m script -a "scripts/verify_clean.sh $(awk '{print $2}' files/team_key.pub ~/.ssh/inv3.pub | sort -u | tr '\n' ' ')" | grep -E "certauth=|UNREACHABLE|FAILED"
  ansible linux -m script -a scripts/verify_clean.sh | grep -E "certauth=|UNREACHABLE|FAILED"
  sudo sh verify_clean.sh AAAAC3NzaC1lZDI1NTE5AAAA...
Pass only the AAAA... blob, not the whole .pub line or the file name.
USAGE
    [ -n "${1:-}" ] && exit 1
    exit 0
}
case "${1:-}" in -h|--help) usage ;; esac
for a in "$@"; do case "$a" in AAAA*) ;; *) usage "not a key blob: $a" ;; esac; done
[ "$(id -u)" -eq 0 ] || usage "must run as root (otherwise root's keys can't be read and it would wrongly say CLEAN)"
bad=""
c=$(grep -c '^cert-authority' /root/.ssh/authorized_keys 2>/dev/null)
# every authorized_keys file sshd reads (AuthorizedKeysFile, with %h/%u filled in) + the INV3 hiding spot
akf=$(sshd -T 2>/dev/null | awk 'tolower($1) == "authorizedkeysfile" {for (i = 2; i <= NF; i++) print $i}')
keyfiles=$( { awk -F: '{print $1, $6}' /etc/passwd | while read -r u d; do
        for p in $akf .ssh/authorized_keys .ssh/authorized_keys2; do
            p=$(printf '%s' "$p" | sed -e "s|%h|$d|g" -e "s|%u|$u|g" -e 's|%%|%|g')
            case "$p" in /*) ;; *) p="$d/$p" ;; esac
            [ -f "$p" ] && echo "$p"
        done
    done; ls /etc/ssh/.ssh/authorized_keys* 2>/dev/null; } | sort -u)
if [ $# -gt 0 ]; then
    unknown=0; where=""
    for f in $keyfiles; do
        n=$(grep -vE '^[[:space:]]*(#|$)' "$f" | grep -v 'cert-authority' | awk '{for (i = 1; i <= NF; i++) if ($i ~ /^AAAA/) {print $i; break}}' \
            | while read -r b; do k=0; for t in "$@"; do [ "$b" = "$t" ] && k=1; done; [ $k = 1 ] || echo x; done | wc -l)
        [ "$n" -gt 0 ] && { unknown=$((unknown + n)); where="$where,$f"; }
    done
    [ "$unknown" -gt 0 ] && bad="$bad UNKNOWN-KEYS=$unknown(${where#,})"
fi
grep -qE 'kali@kali|deploy@management|IMzLWB2|IGvYTas' /root/.ssh/authorized_keys 2>/dev/null && bad="$bad RED-KEYS"
for f in /etc/cron.d/syshealth /etc/cron.d/sysintegrity /etc/systemd/system/health-check.service /etc/systemd/system/health-check.timer \
         /usr/libexec/devnode-syncd /etc/ssh/sshrc /etc/profile.d/motd-display.sh /etc/ssh/banner.txt /root/lockdown_thorska.sh /root/.sys_bak /etc/ssh/.ssh; do
    [ -e "$f" ] && bad="$bad $f"
done
pgrep devnode >/dev/null 2>&1 && bad="$bad DEVNODE-RUNNING"
grep -rhE '^[^#]*NOPASSWD:[[:space:]]*ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -q . && bad="$bad NOPASSWD-SUDO"
{ ss -tn 2>/dev/null || netstat -tn 2>/dev/null; } | grep -qE '10\.194\.194\.85|10\.197\.207\.23' && bad="$bad RED-SESSION"
echo "$(hostname): certauth=$c ${bad:-CLEAN}"

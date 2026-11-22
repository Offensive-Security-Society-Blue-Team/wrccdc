#!/bin/sh
# revoke_certs.sh [ID ...] - revoke forged SSH certificates by their key ID (default: forged-root-cert).
# Scoring certificates have other IDs, so they keep working. Safe to re-run; add IDs as you find them.
# Usage (from ansible/linux):
#   ansible linux -m script -a "scripts/revoke_certs.sh forged-root-cert"
#   ansible linux -m script -a "scripts/revoke_certs.sh forged-root-cert <new-id>"   # more forged IDs
# On a box:  sudo sh revoke_certs.sh forged-root-cert      Help: sh revoke_certs.sh -h
# Another CA:  CA_FP=SHA256:... sh revoke_certs.sh <id>
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
usage() {
    [ -n "${1:-}" ] && echo "error: $1" >&2
    cat >&2 <<'USAGE'
usage: revoke_certs.sh [ID ...]     (SSH cert key IDs to revoke, default forged-root-cert; CHANGES sshd; run as root)
  ansible linux -m script -a "scripts/revoke_certs.sh forged-root-cert"
  ansible linux -m script -a "scripts/revoke_certs.sh forged-root-cert <new-id>"
  sudo sh revoke_certs.sh forged-root-cert
See a cert's ID with: ssh-keygen -L -f <cert>-cert.pub | grep "Key ID"
USAGE
    [ -n "${1:-}" ] && exit 1
    exit 0
}
case "${1:-}" in -h|--help) usage ;; esac
for a in "$@"; do case "$a" in -*) usage "unknown option: $a (IDs only)" ;; esac; done
[ "$(id -u)" -eq 0 ] || usage "must run as root"
C=/etc/ssh/sshd_config; K=/etc/ssh/revoked_keys; S=/etc/ssh/revoked_ids.txt
Q=/root/quarantine; T=$(date +%H%M%S); mkdir -p "$Q"
echo "===== $(hostname) ====="
FP=${CA_FP:-SHA256:zDmNwlQW3BGI1VODbRYMyoHvwVpAt5v6IfxGspK5Ap4}   # CA that signed forged-root-cert
CA=/etc/ssh/redteam_signing_ca.pub; : > "$CA.tmp"
# collect every CA key sshd trusts (TrustedUserCAKeys + cert-authority lines), keep the one with fingerprint $FP
TU=$(sshd -T 2>/dev/null | awk 'tolower($1) == "trustedusercakeys" && $2 != "none" {print $2}')
for f in $TU /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
    [ -f "$f" ] || continue
    sed -n 's/^.*cert-authority[^ ]* \{1,\}//p; /^cert-authority/!{/^\(ssh-\|ecdsa-\|sk-\)/p}' "$f" | while read -r line; do
        echo "$line" > "$CA.one"
        [ "$(ssh-keygen -lf "$CA.one" 2>/dev/null | awk '{print $2}')" = "$FP" ] && cat "$CA.one" >> "$CA.tmp"
    done
done
rm -f "$CA.one"
if [ ! -s "$CA.tmp" ]; then rm -f "$CA.tmp"; echo "CA $FP not trusted on this box - forged certs can't log in here, nothing to do"; exit 0; fi
head -1 "$CA.tmp" > "$CA"; rm -f "$CA.tmp"
echo "CA found: $FP (trusted via: ${TU:-authorized_keys cert-authority})"
[ $# -gt 0 ] || set -- forged-root-cert
touch "$S"
for id in "$@"; do grep -qxF "id: $id" "$S" || echo "id: $id" >> "$S"; done
ssh-keygen -q -k -f "$K.new" -s "$CA" "$S" 2>&1 || { echo "FAILED to build revocation list"; rm -f "$K.new"; exit 0; }
mv "$K.new" "$K" && chmod 644 "$K"
echo "revoked IDs: $(sed 's/^id: //' "$S" | tr '\n' ' ')"
cp "$C" "$Q/sshd_config.$T"
if [ "$(sshd -T 2>/dev/null | awk 'tolower($1) == "revokedkeys" {print $2}')" != "$K" ]; then
    { printf 'RevokedKeys %s\n' "$K"; cat "$C"; } > "$C.new" && cat "$C.new" > "$C"; rm -f "$C.new"
    echo "FIXED: sshd now checks $K"
fi
if sshd -t; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || rc-service sshd reload 2>/dev/null || kill -HUP "$(cat /var/run/sshd.pid 2>/dev/null)" 2>/dev/null
    echo "sshd reloaded"
else
    cat "$Q/sshd_config.$T" > "$C"; echo "FAILED: sshd -t rejected it - old config restored"
fi
echo "-- live sessions from 10.194.194.85"
{ ss -tnp 2>/dev/null || netstat -tnp 2>/dev/null; } | grep '10\.194\.194\.85' || echo "(none)"
true

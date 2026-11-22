#!/bin/sh
# reissue_hostcert.sh - re-issue EXPIRED SSH host certificates from step-ca (renew can't), same key/ID/principals.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CA=https://ca.ice.land:9000; ROOT=/etc/step/root_ca.crt; PW=/etc/step/provisioner-password
echo "===== $(hostname -s)"
command -v step >/dev/null || { echo "no step CLI - skipped"; exit 0; }
[ -s "$PW" ] || { echo "no $PW - skipped"; exit 0; }
for c in /etc/ssh/ssh_host_*-cert.pub; do
    [ -f "$c" ] || continue
    pub="${c%-cert.pub}.pub"
    ID=$(ssh-keygen -L -f "$c" | awk -F'"' '/Key ID/{print $2}')
    PR=$(ssh-keygen -L -f "$c" | awk '/Principals:/{f=1;next} /Critical Options:/{f=0} f{print $1}')
    args=""; for p in $PR; do args="$args --principal $p"; done
    cp -p "$c" "$c.expired.$(date +%H%M%S)"
    # shellcheck disable=SC2086
    if step ssh certificate --host --sign $args --provisioner admin --provisioner-password-file "$PW" --ca-url "$CA" --root "$ROOT" --force "$ID" "$pub" >/dev/null 2>/tmp/hc.err; then
        echo "OK $(basename "$c"): $(ssh-keygen -L -f "$c" | grep Valid | sed 's/ *Valid: //')"
    else echo "FAILED $(basename "$c"): $(tail -1 /tmp/hc.err)"; fi
done
sshd -t && { systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || rc-service sshd reload >/dev/null; echo "sshd reloaded"; }
true

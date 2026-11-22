#!/bin/sh
# cleanup_persist.sh - removes the INV3 red team persistence: health-check timer/service,
# cron.d syshealth/sysintegrity, svc_health re-creation lines, deploy@management + kali@kali keys,
# the disguised implants (dbus_session via systemd-journal-flush-helper.service, kworker-gc.service,
# devnode-syncd, zz-udev-cache.conf drop-ins), and locks svc_health.
# Everything removed is copied to /root/quarantine/persist.<time>. Safe to re-run.
# Usage (from ansible/linux):
#   ansible linux -m script -a scripts/cleanup_persist.sh | grep -E "=====|REMOVED|LOCKED|CLEANED|cert-authority"
#   ansible thorska -m script -a scripts/cleanup_persist.sh       # one box
# On a box:  sudo sh cleanup_persist.sh      Help: sh cleanup_persist.sh -h
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
usage() {
    [ -n "${1:-}" ] && echo "error: $1" >&2
    cat >&2 <<'USAGE'
usage: cleanup_persist.sh     (no arguments; CHANGES the box; run as root)
  ansible linux -m script -a scripts/cleanup_persist.sh | grep -E "=====|REMOVED|LOCKED|CLEANED|cert-authority"
  ansible thorska -m script -a scripts/cleanup_persist.sh
  sudo sh cleanup_persist.sh
USAGE
    [ -n "${1:-}" ] && exit 1
    exit 0
}
case "${1:-}" in -h|--help) usage ;; esac
[ $# -eq 0 ] || usage "this script takes no arguments (got: $*)"
[ "$(id -u)" -eq 0 ] || usage "must run as root"
Q=/root/quarantine/persist.$(date +%H%M%S); mkdir -p "$Q"
BAD='id -u svc_health|svc_health ALL=|deploy@management|kali@kali|# system health monitor'
echo "===== $(hostname) ====="
for u in health-check.timer health-check.service; do
    if [ -f "/etc/systemd/system/$u" ]; then
        systemctl disable --now "$u" >/dev/null 2>&1
        mv "/etc/systemd/system/$u" "$Q/" && echo "REMOVED unit $u"
    fi
done
# INV3 implants hidden behind system-looking names (kvigindis, gufu, haf)
for u in systemd-journal-flush-helper.service kworker-gc.service devnode-syncd.service; do
    for d in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
        [ -f "$d/$u" ] && [ ! -L "$d/$u" ] || continue
        systemctl disable --now "$u" >/dev/null 2>&1
        mv "$d/$u" "$Q/$(echo "$d/$u" | tr / _)" && echo "REMOVED unit $d/$u"
    done
done
for f in /etc/systemd/system/*.service.d/zz-udev-cache.conf; do
    [ -f "$f" ] && mv "$f" "$Q/$(echo "$f" | tr / _)" && echo "REMOVED drop-in $f"
done
for b in /usr/local/sbin/dbus_session /usr/libexec/devnode-syncd; do
    [ -e "$b" ] || continue
    pkill -KILL -x "$(basename "$b")" 2>/dev/null
    mv "$b" "$Q/$(basename "$b").bin" && chmod 000 "$Q/$(basename "$b").bin" && echo "REMOVED + killed $b"
done
command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload 2>/dev/null
for f in /etc/cron.d/syshealth /etc/cron.d/sysintegrity; do
    [ -f "$f" ] && mv "$f" "$Q/" && echo "REMOVED $f"
done
for f in /etc/crontab /var/spool/cron/root /var/spool/cron/crontabs/root /etc/crontabs/root; do
    [ -f "$f" ] && grep -qE "$BAD" "$f" && { cp -p "$f" "$Q/$(echo "$f" | tr / _)"; sed -i -E "/$BAD/d" "$f"; echo "CLEANED $f"; }
done
for f in /root/.bashrc /root/.profile /root/.bash_profile /etc/bashrc /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh /home/*/.bashrc /home/*/.profile; do
    [ -f "$f" ] && grep -qE "$BAD" "$f" && { cp -p "$f" "$Q/$(echo "$f" | tr / _)"; sed -i -E "/$BAD/d" "$f"; echo "CLEANED $f"; }
done
for f in $(find / -xdev -name 'authorized_keys*' -type f 2>/dev/null | grep -v '^/root/quarantine' | xargs -r grep -lE 'deploy@management|kali@kali'); do
    cp -p "$f" "$Q/$(echo "$f" | tr / _)"; sed -i -E '/deploy@management|kali@kali/d' "$f"; echo "KEYS REMOVED from $f"
done
if id svc_health >/dev/null 2>&1; then
    pkill -KILL -u svc_health 2>/dev/null
    usermod -L -s /sbin/nologin svc_health 2>/dev/null || passwd -l svc_health >/dev/null 2>&1
    # busybox (Alpine) has no usermod: set the shell by hand so it can't come back with keys
    grep -q '^svc_health:.*:/bin/[a-z]*sh$' /etc/passwd && sed -i 's#^\(svc_health:.*:\)[^:]*$#\1/sbin/nologin#' /etc/passwd
    [ -f /etc/sudoers.d/svc_health ] && mv /etc/sudoers.d/svc_health "$Q/sudoers_svc_health"
    [ -f /home/svc_health/.ssh/authorized_keys ] && mv /home/svc_health/.ssh/authorized_keys "$Q/svc_health_authorized_keys"
    echo "LOCKED svc_health (no login, no keys, no sudo)"
fi
command -v visudo >/dev/null 2>&1 && { visudo -c >/dev/null 2>&1 && echo "sudoers OK" || echo "WARNING: visudo -c failed - check sudoers"; }
echo "scoring cert-authority lines in root keys: $(grep -c '^cert-authority' /root/.ssh/authorized_keys 2>/dev/null)"
id temp 2>/dev/null | grep -q wheel && echo "NOTE: user temp is in wheel - ask captain before removing"
echo "saved to $Q"; rmdir "$Q" 2>/dev/null
true

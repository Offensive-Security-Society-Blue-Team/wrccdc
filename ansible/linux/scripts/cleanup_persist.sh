#!/bin/sh
# cleanup_persist.sh - removes the INV3 red team persistence: health-check timer/service,
# cron.d syshealth/sysintegrity, svc_health re-creation lines, deploy@management + kali@kali keys,
# and locks svc_health. Everything removed is copied to /root/quarantine/persist.<time>. Safe to re-run.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Q=/root/quarantine/persist.$(date +%H%M%S); mkdir -p "$Q"
BAD='id -u svc_health|svc_health ALL=|deploy@management|kali@kali|# system health monitor'
echo "===== $(hostname) ====="
for u in health-check.timer health-check.service; do
    if [ -f "/etc/systemd/system/$u" ]; then
        systemctl disable --now "$u" >/dev/null 2>&1
        mv "/etc/systemd/system/$u" "$Q/" && echo "REMOVED unit $u"
    fi
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
    [ -f /etc/sudoers.d/svc_health ] && mv /etc/sudoers.d/svc_health "$Q/sudoers_svc_health"
    [ -f /home/svc_health/.ssh/authorized_keys ] && mv /home/svc_health/.ssh/authorized_keys "$Q/svc_health_authorized_keys"
    echo "LOCKED svc_health (no login, no keys, no sudo)"
fi
command -v visudo >/dev/null 2>&1 && { visudo -c >/dev/null 2>&1 && echo "sudoers OK" || echo "WARNING: visudo -c failed - check sudoers"; }
echo "scoring cert-authority lines in root keys: $(grep -c '^cert-authority' /root/.ssh/authorized_keys 2>/dev/null)"
id temp 2>/dev/null | grep -q wheel && echo "NOTE: user temp is in wheel - ask captain before removing"
echo "saved to $Q"; rmdir "$Q" 2>/dev/null
true

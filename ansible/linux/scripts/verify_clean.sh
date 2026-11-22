#!/bin/sh
# verify_clean.sh - READ-ONLY. One line per box: CLEAN, or what the red team put back.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
bad=""
c=$(grep -c '^cert-authority' /root/.ssh/authorized_keys 2>/dev/null)
grep -qE 'kali@kali|deploy@management|IMzLWB2|IGvYTas' /root/.ssh/authorized_keys 2>/dev/null && bad="$bad RED-KEYS"
for f in /etc/cron.d/syshealth /etc/cron.d/sysintegrity /etc/systemd/system/health-check.service /etc/systemd/system/health-check.timer \
         /usr/libexec/devnode-syncd /etc/ssh/sshrc /etc/profile.d/motd-display.sh /etc/ssh/banner.txt /root/lockdown_thorska.sh /root/.sys_bak /etc/ssh/.ssh; do
    [ -e "$f" ] && bad="$bad $f"
done
pgrep devnode >/dev/null 2>&1 && bad="$bad DEVNODE-RUNNING"
grep -rhE '^[^#]*NOPASSWD:[[:space:]]*ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -q . && bad="$bad NOPASSWD-SUDO"
{ ss -tn 2>/dev/null || netstat -tn 2>/dev/null; } | grep -qE '10\.194\.194\.85|10\.197\.207\.23' && bad="$bad RED-SESSION"
echo "$(hostname): certauth=$c ${bad:-CLEAN}"

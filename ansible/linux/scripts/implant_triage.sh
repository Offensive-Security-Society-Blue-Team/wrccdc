#!/bin/sh
# implant_triage.sh [name] - READ-ONLY. Finds in-memory (fileless) programs and a
# planted binary (default name: dbus_session): what runs, who started it, where it
# connects, and what restarts it. Changes nothing.
# Run on all boxes:  ansible linux -m script -a "scripts/implant_triage.sh dbus_session"
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
N=${1:-dbus_session}
echo "===== $(hostname) ====="
NET=$( { ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null; } )

echo "-- programs running from memory (exe = memfd, deleted)"
found=0
for p in /proc/[0-9]*; do
    e=$(readlink "$p/exe" 2>/dev/null) || continue
    case "$e" in
        *memfd:*)
            found=1; pid=${p#/proc/}
            ppid=$(awk '/^PPid:/ {print $2}' "$p/status")
            echo "[!] pid=$pid user=$(stat -c %U "$p") started=$(ps -o lstart= -p "$pid" 2>/dev/null) ppid=$ppid parent=$(tr '\0' ' ' < "/proc/$ppid/cmdline" 2>/dev/null | cut -c1-80)"
            echo "    exe=$e  cmd=$(tr '\0' ' ' < "$p/cmdline" | cut -c1-100)"
            printf '%s\n' "$NET" | grep -E "pid=$pid,|[[:space:]]$pid/" | sed 's/^/    net: /'
            ;;
    esac
done
[ "$found" -eq 1 ] || echo "(none)"

echo "-- '$N' files"
find / -xdev -name "$N*" -type f 2>/dev/null | while read -r f; do
    echo "[!] $f  $(ls -l "$f" | awk '{print $1, $3, $5, $6, $7, $8}')  sha256=$(sha256sum "$f" 2>/dev/null | cut -c1-16)"
done

echo "-- running '$N' processes"
found=0
for p in /proc/[0-9]*; do
    e=$(readlink "$p/exe" 2>/dev/null) || continue
    case "$e" in
        */"$N"|*/"$N"" (deleted)")
            found=1; pid=${p#/proc/}
            echo "[!] pid=$pid exe=$e cmd=$(tr '\0' ' ' < "$p/cmdline" | cut -c1-100)"
            printf '%s\n' "$NET" | grep -E "pid=$pid,|[[:space:]]$pid/" | sed 's/^/    net: /'
            ;;
    esac
done
[ "$found" -eq 1 ] || echo "(none)"

echo "-- what starts it (cron, systemd, init, shell startup files)"
grep -rln "$N" /etc/cron* /var/spool/cron /etc/crontabs /etc/systemd /lib/systemd/system /usr/lib/systemd/system \
    /etc/init.d /etc/local.d /etc/rc.local /etc/profile /etc/profile.d /etc/bash.bashrc /etc/environment \
    /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile /etc/ld.so.preload 2>/dev/null \
    | while read -r f; do echo "[!] $f:"; grep -n "$N" "$f" | sed 's/^/      /'; done
true

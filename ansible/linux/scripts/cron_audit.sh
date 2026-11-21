#!/bin/sh
# cron_audit.sh - READ-ONLY audit of scheduled jobs and the other places
# attackers hide "run this again later" persistence.
#
# Usage:   sudo sh cron_audit.sh | tee "cron_audit_$(hostname)_$(date +%H%M).txt"
#          sudo RECENT_DAYS=1 sh cron_audit.sh     # change the "recently modified" window
# Output:  lines starting with [!] deserve a closer look. A flag is a lead,
#          not proof - some legit jobs use curl/wget, for example.
# Works on: Debian/Ubuntu, RHEL/CentOS/Rocky, Alpine (busybox). POSIX sh only.
# Changes NOTHING on the system.

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

RECENT_DAYS=${RECENT_DAYS:-2}

flag()    { echo "[!] $*"; }
section() { printf '\n===== %s =====\n' "$1"; }
have()    { command -v "$1" >/dev/null 2>&1; }
mtime()   { ls -ld "$1" 2>/dev/null | awk '{print $6, $7, $8}'; }
owner()   { ls -ld "$1" 2>/dev/null | awk '{print $3}'; }

# Things that show up in reverse shells, droppers and backdoors.
SUSPICIOUS='(^|[^a-z])(nc|ncat|netcat|socat|telnet)[[:space:]]|/dev/(tcp|udp)/|(bash|sh) -i|mkfifo|python[0-9.]* -c|perl -e|ruby -e|php -r|base64|curl[[:space:]]|wget[[:space:]]|chmod [ugo]*\+s|chmod [0-7]?[4-7][0-7]{3}|/tmp/|/dev/shm|/var/tmp|nohup|\|[[:space:]]*(ba)?sh'
# Reverse-shell signatures only - for places (init.d) where /tmp, curl etc. are normal.
STRONG='(^|[^a-z])(nc|ncat|netcat|socat|telnet)[[:space:]]|/dev/(tcp|udp)/|(bash|sh) -i|mkfifo|python[0-9.]* -c|perl -e|ruby -e|php -r|/dev/shm|\|[[:space:]]*(ba)?sh[[:space:]]*$'
# Extra patterns that only make sense inside shell startup files.
HOOKS='PROMPT_COMMAND|LD_PRELOAD|trap[[:space:]]|alias[[:space:]]+(sudo|su|ls|ps|ss|netstat|cat|passwd|ssh)='

[ "$(id -u)" -eq 0 ] || echo "[warn] not root: other users' crontabs will be unreadable"
echo "host: $(hostname)   date: $(date)   'recent' = modified in last $RECENT_DAYS day(s)"

# Print the active (non-comment) lines of a crontab-style file, flagging
# suspicious ones. Also flags files not owned by root.
show_tab() {
    f=$1; label=${2:-$1}
    [ -f "$f" ] || return 0
    o=$(owner "$f")
    hdr="--- $label   (owner $o, modified $(mtime "$f"))"
    if [ "$o" != root ] && [ -z "$2" ]; then flag "$hdr  <- not owned by root"; else echo "$hdr"; fi
    grep -vE '^[[:space:]]*(#|$)' "$f" | while IFS= read -r l; do
        if printf '%s\n' "$l" | grep -qE "$SUSPICIOUS"; then flag "    $l"; else echo "    $l"; fi
    done
}

# grep a list of files for suspicious lines, printing file:line:text.
scan_files() {
    pat=$1; shift
    for f in "$@"; do
        [ -f "$f" ] || continue
        # skip commented-out lines and distro-default color aliases
        grep -nE "$pat" "$f" 2>/dev/null \
          | grep -vE '^[0-9]+:[[:space:]]*#' \
          | grep -vE "alias ls='ls --color=auto'" \
          | while IFS= read -r m; do flag "$f:$m"; done
    done
}

# Flag files under the given paths modified in the last RECENT_DAYS days.
recent() {
    for d in "$@"; do
        [ -e "$d" ] || continue
        find "$d" -type f -mtime "-$RECENT_DAYS" 2>/dev/null | while read -r f; do
            flag "recently modified: $f   ($(mtime "$f"))"
        done
    done
}

# ---------------------------------------------------------------------------
section "System crontab + /etc/cron.d"
show_tab /etc/crontab
for f in /etc/cron.d/*; do show_tab "$f"; done

section "Periodic job scripts (cron.hourly/daily/weekly/monthly)"
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/periodic/*; do
    [ -d "$d" ] || continue
    echo "--- $d: $(ls "$d" 2>/dev/null | tr '\n' ' ')"
    for f in "$d"/*; do
        [ -f "$f" ] || continue
        [ "$(owner "$f")" = root ] || flag "$f not owned by root"
    done
    scan_files "$SUSPICIOUS" "$d"/*
done
recent /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/periodic

section "Per-user crontabs (crontab -e)"
# Debian: /var/spool/cron/crontabs  RHEL: /var/spool/cron  Alpine: /etc/crontabs
# Reading the spool directly also catches crontabs for users not in /etc/passwd.
found=0
for dir in /var/spool/cron/crontabs /var/spool/cron /etc/crontabs; do
    [ -d "$dir" ] || continue
    for f in "$dir"/*; do
        [ -f "$f" ] || continue
        found=1
        u=$(basename "$f")
        # Alpine ships a default root crontab that only runs /etc/periodic
        show_tab "$f" "user crontab: $u ($f)"
        id "$u" >/dev/null 2>&1 || flag "    ^ crontab for '$u', who is not a real account"
    done
done
[ "$found" -eq 1 ] || echo "(no per-user crontabs found)"

section "anacron"
show_tab /etc/anacrontab

section "at jobs (one-time scheduled commands)"
if have atq; then
    q=$(atq 2>/dev/null)
    if [ -n "$q" ]; then
        flag "pending at jobs (inspect with: at -c <job#>):"
        echo "$q" | sed 's/^/    /'
    else
        echo "(no pending at jobs)"
    fi
else
    echo "(at not installed)"
fi
for d in /var/spool/cron/atjobs /var/spool/at; do
    [ -d "$d" ] && ls -la "$d" 2>/dev/null | grep -vE ' \.\.?$|^total' | sed "s#^#    $d: #"
done

# ---------------------------------------------------------------------------
section "systemd timers"
if have systemctl && [ -d /run/systemd/system ]; then
    systemctl list-timers --all --no-pager 2>/dev/null
else
    echo "(systemd not running)"
fi

section "Locally-created systemd units (/etc/systemd/system, not symlinks)"
# Package-installed units live in /lib or /usr/lib; /etc/systemd/system
# mostly holds symlinks. A real FILE here was put there by a person.
if [ -d /etc/systemd/system ]; then
    find /etc/systemd/system -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' \) 2>/dev/null \
    | while read -r f; do
        echo "--- $f   (modified $(mtime "$f"))"
        grep -E '^[[:space:]]*(Exec[A-Za-z]*|User|OnCalendar|OnBootSec|OnUnitActiveSec)=' "$f" | while IFS= read -r l; do
            if printf '%s\n' "$l" | grep -qE "$SUSPICIOUS"; then flag "    $l"; else echo "    $l"; fi
        done
    done
fi
recent /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system
for d in /root/.config/systemd/user /home/*/.config/systemd/user; do
    [ -d "$d" ] && flag "user-level systemd units in $d: $(ls "$d" | tr '\n' ' ')"
done

section "Boot scripts (rc.local, init.d, OpenRC local.d)"
for f in /etc/rc.local /etc/rc.d/rc.local; do
    [ -f "$f" ] || continue
    show_tab "$f"
    [ -x "$f" ] && echo "    ($f is executable - it runs at boot)"
done
for f in /etc/local.d/*.start; do show_tab "$f"; done
scan_files "$STRONG" /etc/init.d/*
recent /etc/init.d /etc/local.d

# ---------------------------------------------------------------------------
section "Shell startup files (run every time someone logs in)"
set --
for f in /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc /etc/bashrc /etc/environment; do
    set -- "$@" "$f"
done
for h in /root $(awk -F: '$6 ~ /^\/home\// {print $6}' /etc/passwd) /home/*; do
    for n in .bashrc .bash_profile .bash_login .profile .bash_logout .zshrc; do
        set -- "$@" "$h/$n"
    done
done
scan_files "$SUSPICIOUS|$HOOKS" $(printf '%s\n' "$@" | sort -u)
echo "(no output above this line in this section = nothing matched)"

section "Library preloading"
if [ -s /etc/ld.so.preload ]; then
    flag "/etc/ld.so.preload exists - every program loads these libraries:"
    sed 's/^/    /' /etc/ld.so.preload
else
    echo "(no /etc/ld.so.preload - good)"
fi

echo
echo "done. grep '^\[!\]' to see only flagged lines."

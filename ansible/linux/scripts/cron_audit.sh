#!/bin/sh
# cron_audit.sh - READ-ONLY audit of scheduled jobs and the other places
# attackers hide "run this again later" persistence.
#
# Usage:   ansible-playbook 01_audit.yml    (every box, from ansible/linux)
#          sudo sh cron_audit.sh | tee "cron_audit_$(hostname)_$(date +%H%M).txt"
#          sudo RECENT_DAYS=1 sh cron_audit.sh     # change the "recently modified" window
#          sh cron_audit.sh -h                 (prints these examples)
# Output:  lines starting with [!] deserve a closer look. A flag is a lead,
#          not proof - some legit jobs use curl/wget, for example.
# Works on: Debian/Ubuntu, RHEL/CentOS/Rocky, Alpine (busybox). POSIX sh only.
# Changes NOTHING on the system.

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

usage() {
    [ -n "${1:-}" ] && echo "error: $1" >&2
    cat >&2 <<'USAGE'
usage: cron_audit.sh        (no arguments; READ-ONLY; run as root for full results)
  sudo sh cron_audit.sh | tee "cron_audit_$(hostname)_$(date +%H%M).txt"
  sudo RECENT_DAYS=1 sh cron_audit.sh       # tighter "recently modified" window (days, default 2)
  ansible-playbook 01_audit.yml                # every box, from ansible/linux
USAGE
    [ -n "${1:-}" ] && exit 1
    exit 0
}
case "${1:-}" in -h|--help) usage ;; esac
[ $# -eq 0 ] || usage "this script takes no arguments (got: $*)"
case "${RECENT_DAYS:-2}" in *[!0-9]*|"") usage "RECENT_DAYS must be a whole number of days (got: $RECENT_DAYS)" ;; esac

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

[ "$(id -u)" -eq 0 ] || echo "[warn] not root: other users' crontabs will be unreadable (run: sudo sh cron_audit.sh)"
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

section "systemd drop-ins (*.service.d/*.conf: add commands to an EXISTING service)"
# INV3: zz-udev-cache.conf was dropped into ssh/sshd/nginx .service.d - it runs with that service.
if [ -d /etc/systemd/system ]; then
    found=0
    for f in /etc/systemd/system/*.d/*.conf /run/systemd/system/*.d/*.conf; do
        [ -f "$f" ] || continue
        found=1; echo "--- $f   (modified $(mtime "$f"))"
        grep -E '^[[:space:]]*(Exec[A-Za-z]*|Environment[A-Za-z]*|User)=' "$f" | while IFS= read -r l; do flag "    $l"; done
    done
    [ "$found" -eq 1 ] || echo "(none)"
fi

section "Units in /usr/lib or /lib that no package installed"
# INV3: devnode-syncd.service sat in /usr/lib/systemd/system next to real units, owned by no package.
owner_check() {  # prints the files from stdin that no package owns
    if have dpkg; then xargs -r dpkg -S 2>&1 >/dev/null | sed -n 's/^dpkg-query: no path found matching pattern //p'
    elif have rpm; then xargs -r rpm -qf 2>&1 | sed -n -e 's/^file \(.*\) is not owned by any package$/\1/p' -e 's/^error: file \(.*\): No such file or directory$/\1/p'
    elif have apk; then while read -r f; do apk info -W "$f" 2>/dev/null | grep -q 'owned by' || echo "$f"; done
    else cat >/dev/null; echo "(no dpkg/rpm/apk: cannot check)"; fi
}
if [ -d /usr/lib/systemd/system ] || [ -d /lib/systemd/system ]; then
    # /lib and /usr/lib are often the same folder and the package database knows only one spelling,
    # so ask about both and call it orphaned only if NEITHER is owned.
    orphans=$(find /usr/lib/systemd/system /lib/systemd/system -maxdepth 1 -type f \( -name '*.service' -o -name '*.timer' \) 2>/dev/null \
        | sed 's|.*/||' | sort -u | sed 's|^|/lib/systemd/system/|; p; s|^/lib/|/usr/lib/|' | owner_check \
        | sed 's|^/usr/lib/|/lib/|' | sort | uniq -c | awk '$1 >= 2 || /^ *[0-9]+ \(no / {sub(/^ *[0-9]+ /, ""); print}' \
        | while read -r f; do case "$f" in "(no "*) echo "$f" ;; *) [ -f "/usr$f" ] && echo "/usr$f" || echo "$f" ;; esac; done)
    if [ -n "$orphans" ]; then
        printf '%s\n' "$orphans" | while read -r f; do
            case "$f" in "(no "*) echo "$f"; continue ;; esac
            flag "not from any package: $f   (modified $(mtime "$f"))"
            grep -E '^[[:space:]]*Exec[A-Za-z]*=' "$f" 2>/dev/null | sed 's/^/        /'
        done
    else
        echo "(every unit belongs to a package)"
    fi
fi

section "CI/CD runners (run whatever a repo push or workflow schedule says)"
# INV3: Gitea's act_runner on thorska ran a workflow every 5 min as root; a red team commit
# to that repo re-added their SSH keys each time.
found=0; runner=0
for p in /proc/[0-9]*; do
    c=$(cat "$p/comm" 2>/dev/null)
    case "$c" in act_runner|gitea-runner|forgejo-runne*|gitlab-runner|Runner.Listener|Runner.Worker|jenkins-agent|buildkite-agen*|drone-runner*)
        found=1; runner=1; flag "runner running: pid ${p#/proc/} ($c) user=$(stat -c %U "$p" 2>/dev/null) cmd: $(tr '\0' ' ' < "$p/cmdline" 2>/dev/null | cut -c1-100)" ;;
    esac
done
for f in /etc/systemd/system/*runner*.service /usr/lib/systemd/system/*runner*.service /etc/act_runner/config.yaml /etc/gitea-runner/config.yaml \
         /etc/gitlab-runner/config.toml /root/.runner /var/lib/act_runner/.runner /opt/*/.runner; do
    [ -f "$f" ] && { found=1; runner=1; echo "runner config: $f   (modified $(mtime "$f"))"; }
done
# workflow files on this box with a schedule or that touch keys/users/sudo
for f in $(find /root /home /opt /srv /var/lib -maxdepth 6 \( -path '*/.gitea/workflows/*' -o -path '*/.github/workflows/*' -o -path '*/.forgejo/workflows/*' \
        -o -name '.gitlab-ci.yml' \) -type f 2>/dev/null | head -n 50); do
    found=1
    # without a runner on this box a workflow file is just part of a checkout: it never runs here
    [ "$runner" -eq 1 ] || { echo "workflow (no runner here, doesn't run on this box): $f"; continue; }
    if grep -qE 'authorized_keys|useradd|sudoers|chpasswd|/dev/tcp|curl[[:space:]].*\|[[:space:]]*(ba)?sh' "$f" 2>/dev/null; then flag "workflow touches keys/users/sudo or pipes to a shell: $f"
    elif grep -qE '^[[:space:]]*(schedule|-[[:space:]]*cron)[[:space:]]*:' "$f" 2>/dev/null; then flag "workflow runs on a schedule: $f ($(grep -hoE "cron:[[:space:]]*['\"][^'\"]+" "$f" | head -n1))"
    else echo "workflow: $f"; fi
done
[ "$found" -eq 1 ] || echo "(no CI runner or workflow files found)"
echo "(a runner can be a scored service: check which repo it pulls and who pushed last - git log -1 in its checkout)"

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

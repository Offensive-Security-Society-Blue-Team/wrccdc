#!/bin/sh
# baseline.sh - snapshot what "normal" looks like on a box, then diff later to see exactly what changed:
# listening ports, outbound destinations, users, privileged groups, sudo rules, cron/timers, services,
# kernel modules, SUID/SGID files, SSH keys (by fingerprint), running executables, hashes of auth/config files,
# effective sshd settings, firewall rules. Plus a package-integrity check for tampered binaries/libraries/PAM.
#   baseline.sh snap            take a snapshot (the first one on a box is kept as T0)
#   baseline.sh diff [NAME]     compare now against T0 (or against snapshot NAME; 'baseline.sh list' shows names)
#   baseline.sh verify          ask the package manager which installed files were modified
#   baseline.sh list            list snapshots
# Run 'snap' at minute zero (with vuln_hunt), then 'diff' every 15-30 minutes or after each red-team alert.
# Ideas: DSU ace initial/baselines.sh, Cal Poly Pomona blue misc/netdiff.sh + userdiff.sh. Our own code.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C; export LC_ALL
BASE=/root/.ccdc-baseline
h=$(hostname -s 2>/dev/null || hostname)
has() { command -v "$1" >/dev/null 2>&1; }
say() { echo "[$h] $*"; }
[ "$(id -u)" = 0 ] || { say "run as root"; exit 1; }
umask 077; mkdir -p "$BASE"

snapshot() { # $1 = directory to fill
    d=$1; mkdir -p "$d"
    if has ss; then ss -tulnp 2>/dev/null | awk 'NR > 1 {pr = $7; sub(/.*\(\("/, "", pr); sub(/".*/, "", pr); print $1, $5, pr}'
    else netstat -tulnp 2>/dev/null | awk 'NR > 2 {pr = $NF; sub(/^[0-9]+\//, "", pr); print $1, $4, pr}'; fi | sort -u > "$d/listening"
    { ss -tnp 2>/dev/null | awk '$1 == "ESTAB" {print $5, $6}'; netstat -tnp 2>/dev/null | awk '$6 == "ESTABLISHED" {print $5, $7}'; } |
        awk '{ n = split($1, a, ":"); ip = $1; sub(/:[0-9]+$/, "", ip); pr = $2; sub(/.*\(\("/, "", pr); sub(/".*/, "", pr); sub(/^[0-9]+\//, "", pr)
               if (ip !~ /^(127\.|\[::1\]|::1)/) print ip, pr }' | sort -u > "$d/connections"
    awk -F: '{print $1 ":" $3 ":" $4 ":" $6 ":" $7}' /etc/passwd | sort > "$d/users"
    grep -E '^(root|sudo|wheel|admin|adm|docker|lxd|disk|shadow|libvirt|kvm)' /etc/group | cut -d: -f1,4 | sort > "$d/groups"
    for f in /etc/sudoers /etc/sudoers.d/*; do [ -f "$f" ] && grep -vE '^[[:space:]]*(#|$)' "$f" | sed "s|^|$f: |"; done | sort > "$d/sudoers"
    { for f in /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/* /etc/anacrontab; do
          [ -f "$f" ] && grep -vE '^[[:space:]]*(#|$)' "$f" | sed "s|^|$f: |"; done
      ls /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null | sed 's|^|cron-dir: |'
      has systemctl && systemctl list-timers --all --no-legend 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i ~ /\.timer$/) print "timer: " $i}'
      has atq && atq 2>/dev/null | sed 's/^/at: /'; } | sort -u > "$d/cron"
    if has systemctl; then
        { systemctl list-unit-files --state=enabled --no-legend 2>/dev/null | awk '{print "enabled: " $1}'
          systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print "running: " $1}'; } | sort -u > "$d/services"
    else rc-status -a 2>/dev/null | awk '/started/ {print "running: " $1}' | sort -u > "$d/services"; fi
    { lsmod 2>/dev/null || cat /proc/modules 2>/dev/null; } | awk 'NR > 1 || !/^Module/ {print $1}' | grep -v '^Module$' | sort -u > "$d/modules"
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort > "$d/suid"
    for f in /root/.ssh/authorized_keys /root/.ssh/authorized_keys2 /home/*/.ssh/authorized_keys /home/*/.ssh/authorized_keys2; do
        [ -f "$f" ] || continue
        if has ssh-keygen; then ssh-keygen -lf "$f" 2>/dev/null | awk -v f="$f" '{c = ""; for (i = 3; i < NF; i++) c = c " " $i; print f ": " $2 c}'
        else grep -vE '^[[:space:]]*(#|$)' "$f" | awk -v f="$f" '{print f ": " $NF}'; fi
        grep -c 'cert-authority' "$f" | awk -v f="$f" '$1 > 0 {print f ": cert-authority lines=" $1}'
    done | sort -u > "$d/keys"
    for p in /proc/[0-9]*; do readlink "$p/exe" 2>/dev/null; done | sort -u > "$d/executables"
    for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/sudoers.d/* /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* \
             /etc/pam.d/* /etc/ld.so.preload /etc/ld.so.conf /etc/ld.so.conf.d/* /etc/profile /etc/profile.d/* /etc/bash.bashrc /etc/bashrc \
             /root/.bashrc /root/.profile /root/.bash_profile /etc/rc.local /etc/hosts /etc/resolv.conf /etc/nsswitch.conf /etc/environment; do
        [ -f "$f" ] && { sha256sum "$f" 2>/dev/null || md5sum "$f"; }
    done | awk '{print $2, substr($1, 1, 16)}' | sort > "$d/filehashes"
    has sshd && sshd -T 2>/dev/null | sort > "$d/sshd"
    { iptables-save 2>/dev/null | sed -E 's/\[[0-9]+:[0-9]+\]//' | grep -vE '^#'; nft list ruleset 2>/dev/null | grep -vE 'counter packets|^#'; } > "$d/firewall"
}

latest_t0() { [ -e "$BASE/T0" ] && readlink "$BASE/T0"; }
case "${1:-snap}" in
    snap)
        name=$(date +%Y%m%d-%H%M%S); snapshot "$BASE/$name"
        if [ ! -e "$BASE/T0" ]; then ln -s "$name" "$BASE/T0"; say "snapshot $name saved as T0 (the reference). Later: baseline.sh diff"
        else say "snapshot $name saved (T0 = $(latest_t0))"; fi ;;
    list)
        for p in "$BASE"/*; do n=${p##*/}; [ -d "$p" ] && [ "$n" != T0 ] && say "$n$( [ "$n" = "$(latest_t0)" ] && echo '  <- T0')"; done ;;
    diff)
        ref=${2:-T0}; [ -d "$BASE/$ref" ] || { say "no snapshot '$ref' yet: run 'baseline.sh snap' first"; exit 1; }
        now="$BASE/.now"; rm -rf "$now"; snapshot "$now"
        changes=0
        for c in listening connections users groups sudoers cron services modules suid keys executables filehashes sshd firewall; do
            [ -f "$BASE/$ref/$c" ] && [ -f "$now/$c" ] || continue
            add=$(comm -13 "$BASE/$ref/$c" "$now/$c"); del=$(comm -23 "$BASE/$ref/$c" "$now/$c")
            [ -z "$add$del" ] && continue
            changes=$((changes + 1))
            if [ "$c" = filehashes ]; then
                echo "$add" | awk 'NF {print $1}' | sort -u | while read -r f; do say "CHANGED  file: $f"; done
            else
                echo "$add" | awk 'NF' | head -25 | while read -r l; do say "+ $c: $l"; done
                echo "$del" | awk 'NF' | head -25 | while read -r l; do say "- $c: $l"; done
            fi
        done
        rm -rf "$now"
        [ "$changes" = 0 ] && say "no changes since $ref" || say "$changes categories changed since $ref. '+' = new since then. Investigate before deleting: some changes are yours." ;;
    verify)
        if has dpkg; then say "dpkg --verify (MD5 of every packaged file; takes a minute)"; dpkg --verify > "$BASE/.raw" 2>/dev/null
        elif has rpm; then say "rpm -Va (checksums of every packaged file; takes a minute)"; rpm -Va --nomtime > "$BASE/.raw" 2>/dev/null
        elif has apk; then say "apk audit --system"; apk audit --system 2>/dev/null | awk '{p = $2; sub(/^\//, "", p); print $1, "/" p}' > "$BASE/.raw"
        else say "no dpkg, rpm or apk: can't verify packages"; exit 0; fi
        # "FLAG PATH" for changed/missing packaged files; docs, man pages and locales don't matter
        # apk: U = changed since installed, A = in a system folder but no package installed it
        awk '$2 != "c" && ($1 ~ /5|missing|^[UA]$/) {print ($1 == "missing" ? "missing" : ($1 == "A" ? "added" : "changed")), $NF}' "$BASE/.raw" |
            grep -vE ' /usr/share/(man|doc|locale|info|lintian|help|bug|gtk-doc|i18n)/|\.pyc$|/__pycache__/' | sort -u > "$BASE/.verify"
        conf=$(awk '$2 == "c"' "$BASE/.raw" | wc -l | tr -d ' '); rm -f "$BASE/.raw"
        CRIT=' /(usr/)?(s?bin|libexec)/| /(usr/)?lib(64)?/([^/]+/)?security/| /(usr/)?lib(64)?/.*\.so(\.[0-9]+)*$'
        crit=$(grep -E "$CRIT" "$BASE/.verify")
        [ -n "$crit" ] && echo "$crit" | while read -r flag f; do
            case "$flag" in
                changed) say "TAMPERED? $f (differs from its package)" ;;
                added) say "NO PACKAGE $f (new file in a system folder: dropped by someone?)" ;;
                *) say "MISSING   $f (packaged file deleted)" ;;
            esac
        done | head -40
        say "$(echo "$crit" | grep -c .) binaries/libraries/PAM modules changed, missing or not from a package, $(grep -cvE "$CRIT" "$BASE/.verify") other packaged files, $conf config files (config changes are normal after hardening)."
        echo "$crit" | grep -q '^changed' && say "A changed sshd, sudo, su, login, PAM module or libc is a backdoor until proven otherwise: compare with a clean box, reinstall the package if you have the .deb/.rpm."
        rm -f "$BASE/.verify" ;;
    -h|--help) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 0 ;;
    *) echo "error: unknown command: $1 (snap | diff [NAME] | verify | list)" >&2; sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 1 ;;
esac
exit 0

#!/bin/sh
# user_audit.sh - READ-ONLY audit of local accounts, privileges and SSH access.
#
# Usage:   sudo sh user_audit.sh | tee "user_audit_$(hostname)_$(date +%H%M).txt"
# Output:  lines starting with [!] deserve a closer look. A flag is a lead,
#          not proof of compromise - confirm before you lock/remove anything.
# Works on: Debian/Ubuntu, RHEL/CentOS/Rocky, Alpine (busybox). POSIX sh only.
# Changes NOTHING on the system.

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

flag()    { echo "[!] $*"; }
section() { printf '\n===== %s =====\n' "$1"; }
have()    { command -v "$1" >/dev/null 2>&1; }
mtime()   { ls -ld "$1" 2>/dev/null | awk '{print $6, $7, $8}'; }

# Shells that mean "this account cannot get an interactive login"
NOLOGIN='(nologin|false|sync|shutdown|halt)$'

[ "$(id -u)" -eq 0 ] || echo "[warn] not root: shadow, sudoers and other users' keys will be incomplete"
echo "host: $(hostname)   date: $(date)   kernel: $(uname -r)"

# UID_MIN = where "real human" UIDs start on this distro (1000 modern, 500 old RHEL)
UID_MIN=$(awk '$1 == "UID_MIN" {print $2}' /etc/login.defs 2>/dev/null)
[ -n "$UID_MIN" ] || UID_MIN=1000

# ---------------------------------------------------------------------------
section "Accounts that can log in (shell is not nologin/false)"
awk -F: -v re="$NOLOGIN" '$7 !~ re {
    printf "%-16s uid=%-6s gid=%-6s home=%-22s shell=%s\n", $1, $3, $4, $6, $7 }' /etc/passwd

section "UID 0 accounts (only root should be here)"
awk -F: '$3 == 0 { if ($1 == "root") print "root (ok)"; else print "[!] UID 0 account: " $1 }' /etc/passwd

section "Duplicate UIDs / usernames"
cut -d: -f3 /etc/passwd | sort | uniq -d | while read -r id; do
    flag "UID $id is shared by: $(awk -F: -v i="$id" '$3 == i {printf "%s ", $1}' /etc/passwd)"
done
cut -d: -f1 /etc/passwd | sort | uniq -d | while read -r n; do
    flag "username listed twice: $n"
done

section "System accounts (uid < $UID_MIN) that have a login shell"
# Service accounts (www-data, mysql, ...) should NOT have a real shell.
awk -F: -v min="$UID_MIN" -v re="$NOLOGIN" \
    '$3 < min && $3 != 0 && $7 !~ re { print "[!] " $1 " (uid " $3 ") shell=" $7 }' /etc/passwd

section "Accounts with unusual home directories"
awk -F: -v re="$NOLOGIN" '$7 !~ re && $6 ~ /^\/(tmp|var\/tmp|dev)/ { print "[!] " $1 " home=" $6 }' /etc/passwd
for d in /home/*; do
    [ -d "$d" ] || continue
    awk -F: -v d="$d" '$6 == d {f=1} END {exit !f}' /etc/passwd || \
        flag "$d does not belong to any account (deleted user? leftover?)"
done

# ---------------------------------------------------------------------------
section "Password status (/etc/shadow)"
if [ -r /etc/shadow ]; then
    TODAY=$(( $(date +%s) / 86400 ))
    # field 2 = hash: "" no password, "!" or "*" = locked / no password login
    # field 3 = day (since 1970) the password was last changed
    awk -F: -v today="$TODAY" '
    {
        u = $1; h = $2
        if (h == "") { print "[!] " u ": NO PASSWORD (empty field) - anyone can log in"; next }
        if (h ~ /^[!*]/) next
        t = "unknown"; weak = 0
        if      (h ~ /^\$1\$/)     { t = "MD5";      weak = 1 }
        else if (h ~ /^\$5\$/)       t = "SHA-256"
        else if (h ~ /^\$6\$/)       t = "SHA-512"
        else if (h ~ /^\$y\$/)       t = "yescrypt"
        else if (h ~ /^\$2[aby]\$/)  t = "bcrypt"
        else if (length(h) == 13)  { t = "DES";      weak = 1 }
        age = ($3 == "") ? "?" : today - $3
        line = sprintf("%-16s usable password  hash=%-9s changed %s day(s) ago", u, t, age)
        if (weak)          line = "[!] " line "  <- weak hash type"
        else if (age == 0) line = "[!] " line "  <- changed TODAY (was that you?)"
        print line
    }' /etc/shadow
else
    echo "cannot read /etc/shadow (not root? FreeBSD uses /etc/master.passwd)"
fi

# ---------------------------------------------------------------------------
section "Members of privileged groups"
echo "(docker, lxd, libvirt and disk membership is effectively root)"
for g in root sudo wheel admin adm docker lxd libvirt disk shadow; do
    line=$(grep "^$g:" /etc/group 2>/dev/null)
    [ -n "$line" ] || continue
    gid=$(echo "$line" | cut -d: -f3)
    members=$(echo "$line" | cut -d: -f4)
    primary=$(awk -F: -v g="$gid" '$4 == g {printf "%s ", $1}' /etc/passwd)
    out="$g (gid $gid): members=[$members] primary-group-of=[${primary% }]"
    case "$g" in
        root|sudo|wheel|admin|docker|lxd|libvirt|disk)
            [ -n "$members" ] && { flag "$out"; continue; } ;;
    esac
    echo "$out"
done

section "sudo rules (comments and Defaults stripped)"
# '#include' / '#includedir' look like comments but ARE directives - keep them.
for f in /etc/sudoers /etc/sudoers.d/*; do
    [ -f "$f" ] || continue
    echo "--- $f   (modified $(mtime "$f"))"
    grep -E '^[[:space:]]*[#@]include' "$f" | while IFS= read -r l; do
        case "$l" in
            *"/etc/sudoers.d"*) echo "    $l" ;;
            *) flag "    unusual include: $l" ;;
        esac
    done
    grep -vE '^[[:space:]]*(#|$)' "$f" | grep -vE '^[[:space:]]*(Defaults|@include)' \
      | while IFS= read -r l; do
        case "$l" in
            *NOPASSWD*) flag "    $l   <- no password needed" ;;
            *)          echo "    $l" ;;
        esac
    done
done

# ---------------------------------------------------------------------------
section "sshd: effective settings"
# 'sshd -T' prints the config sshd ACTUALLY uses (after drop-ins and
# first-match-wins), which can differ from what you read in sshd_config.
SSHD_T=""
have sshd && SSHD_T=$(sshd -T 2>/dev/null)
if [ -n "$SSHD_T" ]; then
    echo "$SSHD_T" | awk '
    $1 ~ /^(port|listenaddress|permitrootlogin|passwordauthentication|pubkeyauthentication|permitemptypasswords|authorizedkeysfile|authorizedkeyscommand|authorizedkeyscommanduser|allowusers|denyusers|allowgroups|usepam)$/ {
        line = $0
        if ($1 == "permitemptypasswords" && $2 == "yes")                     line = "[!] " line
        if ($1 == "authorizedkeyscommand" && $2 != "none")                   line = "[!] " line "   <- keys come from a program"
        if ($1 == "authorizedkeysfile" && $0 != "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2" \
                                        && $0 != "authorizedkeysfile .ssh/authorized_keys") line = "[!] " line "   <- non-default key location"
        print line
    }'
    AKF=$(echo "$SSHD_T" | awk '$1 == "authorizedkeysfile" { $1 = ""; print }')
else
    echo "(sshd -T unavailable - showing raw config lines instead)"
    grep -hiE '^[[:space:]]*(Port|PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|AuthorizedKeys|AllowUsers|DenyUsers|Include)' \
        /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null
    AKF=$(grep -hiE '^[[:space:]]*AuthorizedKeysFile' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null \
          | head -n1 | awk '{ $1 = ""; print }')
fi
[ -n "$AKF" ] || AKF=".ssh/authorized_keys .ssh/authorized_keys2"
ls /etc/ssh/sshd_config.d/ >/dev/null 2>&1 && echo "drop-in files: $(ls /etc/ssh/sshd_config.d/ | tr '\n' ' ')"

section "SSH authorized keys per account"
echo "(every key here should be one your team knows about)"
awk -F: '{print $1 ":" $6}' /etc/passwd | while IFS=: read -r u h; do
    [ -n "$h" ] || continue
    for p in $AKF; do
        # expand sshd tokens: %h = home, %u = user, %% = %
        p=$(echo "$p" | sed -e "s#%h#$h#g" -e "s#%u#$u#g" -e 's#%%#%#g')
        case "$p" in /*) f=$p ;; *) f="$h/$p" ;; esac
        [ -s "$f" ] || continue
        n=$(grep -cvE '^[[:space:]]*(#|$)' "$f")
        flag "$u: $n key(s) in $f   (modified $(mtime "$f"))"
        grep -vE '^[[:space:]]*(#|$)' "$f" | while IFS= read -r k; do
            if have ssh-keygen; then
                fp=$(echo "$k" | ssh-keygen -lf - 2>/dev/null)
                echo "      ${fp:-$(echo "$k" | cut -c1-60)...}"
            else
                # show type + comment, not the whole key
                echo "      $(echo "$k" | awk '{print $1, "...", $NF}')"
            fi
            case "$k" in *command=*|*environment=*) flag "      ^ key has forced command/environment options" ;; esac
        done
    done
done

section "Stray authorized_keys files anywhere on / (same filesystem)"
echo "(files outside a known account's ~/.ssh are flagged)"
HOMES=$(awk -F: '{print $6}' /etc/passwd)
find / -xdev -name 'authorized_keys*' -type f 2>/dev/null | while read -r f; do
    info="$f   (owner $(ls -ld "$f" | awk '{print $3}'), modified $(mtime "$f"))"
    ok=0
    for h in $HOMES; do
        case "$f" in "$h"/.ssh/*) ok=1; break ;; esac
    done
    if [ "$ok" -eq 1 ]; then echo "  $info"; else flag "$info"; fi
done

# ---------------------------------------------------------------------------
section "Account files: last modified + immutable flags"
for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers; do
    [ -e "$f" ] && printf '  %-14s %s\n' "$(mtime "$f")" "$f"
done
if have lsattr; then
    for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /root/.ssh/authorized_keys; do
        [ -e "$f" ] || continue
        a=$(lsattr "$f" 2>/dev/null | cut -d' ' -f1)
        case "$a" in *i*|*a*) flag "$f has immutable/append-only attribute ($a) - password/key changes will fail" ;; esac
    done
fi

# ---------------------------------------------------------------------------
section "Logged in right now"
who 2>/dev/null || echo "(who unavailable)"

section "Recent logins (last 25)"
{ last -n 25 2>/dev/null || last 2>/dev/null | head -n 25; } | grep -v '^$'

section "Recent FAILED logins (last 25)"
if have lastb; then lastb -n 25 2>/dev/null | grep -v '^$'; else echo "(lastb unavailable)"; fi

echo
echo "done. grep '^\[!\]' to see only flagged lines."

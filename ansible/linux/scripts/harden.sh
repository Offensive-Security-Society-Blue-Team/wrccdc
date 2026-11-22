#!/bin/sh
# harden.sh - runs ON each box (pushed by harden_run.sh, or: ansible ... -m script -a "scripts/harden.sh ...").
# Safe by default: everything that broke scoring or teammates at Inv3 is OFF unless you pass its flag.
# Prints passwords only as "PW|host|user|password" lines for the laptop wrapper to capture. Never writes them to disk here.
#
# Options:
#   --keys-b64 B64      team public keys (base64 of the .pub lines); added to root's authorized_keys
#   --rotate LIST       comma list of local users to give new random passwords (default: root)
#   --all-local         also rotate every local login account with UID >= 1000
#   --exclude LIST      never rotate these (SCORED USERS GO HERE: change those only through PCRs)
#   --no-password-login set PasswordAuthentication no   (OFF by default: locked teammates out at Inv3)
#   --root-keys-only    set PermitRootLogin prohibit-password (keys and certs still work; passwords don't)
#   --no-forwarding     disable SSH TCP/agent forwarding (breaks ssh -J jump hosts through this box)
#   --strip-nopasswd    comment out NOPASSWD sudo rules (check they aren't a scored service first)
#   --allowlist-keys    root's authorized_keys keeps ONLY cert-authority lines + the team keys
#   --check             dry run: report what would change, change nothing
#   -h, --help          print the examples below
#
# Usage (from ansible/linux). ANSIBLE_LOG_PATH=/dev/null keeps the new passwords out of logs/ansible.log.
#   ANSIBLE_LOG_PATH=/dev/null ansible haf -m script -a "scripts/harden.sh --check"               # dry run, one box
#   ANSIBLE_LOG_PATH=/dev/null ansible linux -m script -a "scripts/harden.sh --keys-b64 $(base64 -w0 files/team_key.pub) --exclude jsmith,akim" | grep '^PW|'
#   ANSIBLE_LOG_PATH=/dev/null ansible linux -m script -a "scripts/harden.sh --rotate '' --root-keys-only"   # no password changes
# On a box:  sudo sh harden.sh --check
# NOTE: with no --rotate, root gets a new password. Use --rotate '' when 04_passwords.yml handles passwords.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
usage() {
    [ -n "${1:-}" ] && echo "error: $1" >&2
    cat >&2 <<'USAGE'
usage: harden.sh [--check] [--keys-b64 B64] [--rotate u1,u2 | --rotate ''] [--all-local] [--exclude u1,u2]
                 [--no-password-login] [--root-keys-only] [--no-forwarding] [--strip-nopasswd] [--allowlist-keys]
  (CHANGES the box unless --check; run as root; with no --rotate, ROOT GETS A NEW PASSWORD)
  ANSIBLE_LOG_PATH=/dev/null ansible haf -m script -a "scripts/harden.sh --check"
  ANSIBLE_LOG_PATH=/dev/null ansible linux -m script -a "scripts/harden.sh --keys-b64 $(base64 -w0 files/team_key.pub) --exclude jsmith,akim" | grep '^PW|'
  ANSIBLE_LOG_PATH=/dev/null ansible linux -m script -a "scripts/harden.sh --rotate '' --root-keys-only"
  sudo sh harden.sh --check
USAGE
    [ -n "${1:-}" ] && exit 1
    exit 0
}
needval() { [ $# -ge 2 ] || usage "$1 needs a value"; }
umask 077
KEYS_B64=""; ROTATE="root"; ALL_LOCAL=0; EXCLUDE=""; NOPW=0; ROOTKEYS=0; NOFWD=0; STRIPNP=0; ALLOWLIST=0; CHECK=0
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage ;;
        --keys-b64) needval "$@"; [ -n "$2" ] || usage "--keys-b64 is empty (try: --keys-b64 \$(base64 -w0 files/team_key.pub))"; KEYS_B64=$2; shift ;;
        --rotate) needval "$@"; ROTATE=$2; shift ;;
        --all-local) ALL_LOCAL=1 ;;
        --exclude) needval "$@"; EXCLUDE=$2; shift ;;
        --no-password-login) NOPW=1 ;;
        --root-keys-only) ROOTKEYS=1 ;;
        --no-forwarding) NOFWD=1 ;;
        --strip-nopasswd) STRIPNP=1 ;;
        --allowlist-keys) ALLOWLIST=1 ;;
        --check) CHECK=1 ;;
        *) usage "unknown option: $1" ;;
    esac
    shift
done
h=$(hostname -s 2>/dev/null || hostname)
TS=$(date +%Y%m%d-%H%M%S)
BK=/root/.ccdc-harden/$TS
has() { command -v "$1" >/dev/null 2>&1; }
say() { echo "[$h] $*"; }
did() { if [ "$CHECK" = 1 ]; then echo "[$h] WOULD: $*"; else echo "[$h] DONE: $*"; fi; }
review() { echo "[$h] REVIEW: $*"; }
inlist() { case ",$2," in *",$1,"*) return 0;; esac; return 1; }
[ "$(id -u)" = 0 ] || usage "must run as root"
[ "$CHECK" = 1 ] && say "CHECK MODE: nothing will be changed"

# ---- 0. backup everything this script can touch -----------------------------------------
if [ "$CHECK" = 0 ]; then
    mkdir -p "$BK"
    tar -czpf "$BK/etc-before.tgz" /etc/ssh /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/sudoers.d \
        /etc/sysctl.d /etc/profile.d /root/.ssh 2>/dev/null
    say "backup: $BK/etc-before.tgz  (undo: tar -xzpf $BK/etc-before.tgz -C /  -- also restores OLD passwords)"
fi

# ---- 1. team keys into root's authorized_keys --------------------------------------------
AK=/root/.ssh/authorized_keys
KEYFILE=$BK/team-keys.pub; [ "$CHECK" = 1 ] && KEYFILE=/tmp/.ccdc-keys.$$
haskey=0
if [ -n "$KEYS_B64" ]; then
    echo "$KEYS_B64" | base64 -d 2>/dev/null | grep -E '^(ssh-|ecdsa-|sk-)' > "$KEYFILE"
    if [ ! -s "$KEYFILE" ]; then
        say "FAILED: could not decode team keys; skipping key install"
    else
        [ "$CHECK" = 0 ] && { mkdir -p /root/.ssh; chmod 700 /root/.ssh; touch "$AK"; chmod 600 "$AK"; }
        while read -r t b c; do
            if grep -qF "$b" "$AK" 2>/dev/null; then haskey=1; say "key already present: $t ${c:-}"
            else
                [ "$CHECK" = 0 ] && echo "$t $b ${c:-}" >> "$AK" && haskey=1
                did "added team key $t ${c:-}"
            fi
        done < "$KEYFILE"
        [ "$CHECK" = 1 ] && haskey=1
    fi
fi
# anything else in root's keys is either scoring (cert-authority) or unknown
if [ -f "$AK" ]; then
    grep -vE '^[[:space:]]*(#|$)' "$AK" | while read -r l; do
        case "$l" in *cert-authority*) say "keeping CA line (may be scoring): $(echo "$l" | cut -c1-60)..."; continue;; esac
        b=$(echo "$l" | awk '{for(i=1;i<=NF;i++) if ($i ~ /^AAAA/) {print $i; exit}}')
        [ -s "$KEYFILE" ] && grep -qF "$b" "$KEYFILE" && continue
        review "unknown key in $AK: $(echo "$l" | awk '{print $1}') ...${b#"${b%??????????}"} $(echo "$l" | awk '{print $NF}')"
    done
    if [ "$ALLOWLIST" = 1 ] && [ -s "$KEYFILE" ]; then
        if [ "$CHECK" = 0 ]; then
            { grep -E 'cert-authority' "$AK"; while read -r t b c; do echo "$t $b ${c:-}"; done < "$KEYFILE"; } > "$AK.new" && mv "$AK.new" "$AK" && chmod 600 "$AK"
        fi
        did "root authorized_keys reduced to cert-authority lines + team keys (old copy in backup)"
    fi
fi
[ "$CHECK" = 1 ] && rm -f "$KEYFILE"

# ---- 2. password rotation (only if a team key is in place, so you can't lock yourself out) --
newpw() { tr -dc 'A-Za-z0-9' < /dev/urandom 2>/dev/null | head -c 20; }
setpw() {  # user pass
    if has chpasswd && echo "$1:$2" | chpasswd 2>/dev/null; then return 0; fi
    printf '%s\n%s\n' "$2" "$2" | passwd "$1" >/dev/null 2>&1
}
targets=$(echo "$ROTATE" | tr ',' ' ')
if [ "$ALL_LOCAL" = 1 ]; then
    targets="$targets $(awk -F: '$3>=1000 && $3<60000 && $7 !~ /(nologin|false)$/ {print $1}' /etc/passwd)"
fi
if [ "$haskey" != 1 ] && [ -z "$KEYS_B64" ] && grep -qE '^(ssh-|ecdsa-)' "$AK" 2>/dev/null; then haskey=1; fi
if [ "$haskey" != 1 ]; then
    say "SKIPPED password rotation: no team key confirmed in $AK (rotating would risk a lockout)"
else
    for u in $(echo "$targets" | tr ' ' '\n' | awk 'NF && !seen[$0]++'); do
        if inlist "$u" "$EXCLUDE"; then say "skip $u (excluded: change scored users through PCRs)"; continue; fi
        grep -q "^$u:" /etc/passwd || { say "skip $u (not a local account; domain users change in AD)"; continue; }
        if [ "$CHECK" = 1 ]; then did "new password for $u"; continue; fi
        p=$(newpw)
        if [ ${#p} -eq 20 ] && setpw "$u" "$p"; then echo "PW|$h|$u|$p"; did "new password for $u"
        else say "FAILED: password change for $u"; fi
    done
fi

# ---- 3. accounts: lock empty passwords, report the rest -----------------------------------
awk -F: '$2==""{print $1}' /etc/shadow 2>/dev/null | while read -r u; do
    [ "$CHECK" = 0 ] && passwd -l "$u" >/dev/null 2>&1
    did "locked $u (had an EMPTY password: SSH bypass risk)"
done
awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd | while read -r u; do review "extra UID 0 account: $u (not removed)"; done
awk -F: '$3>0 && $3<1000 && $7 !~ /(nologin|false|sync|halt|shutdown)$/ {print $1" "$7}' /etc/passwd | while read -r l; do
    review "service account with a shell: $l (ask black team before changing; some are scored)"
done

# ---- 4. sudo ------------------------------------------------------------------------------
for f in /etc/sudoers /etc/sudoers.d/*; do
    [ -f "$f" ] || continue
    grep -nE '^[^#]*NOPASSWD' "$f" | while read -r l; do review "NOPASSWD in $f: $l"; done
    if [ "$STRIPNP" = 1 ] && grep -qE '^[^#]*NOPASSWD' "$f"; then
        if [ "$CHECK" = 0 ]; then
            cp -p "$f" "$f.ccdc-tmp" && sed -i 's/^\([^#]*NOPASSWD.*\)$/# ccdc-harden: \1/' "$f.ccdc-tmp"
            if visudo -cf "$f.ccdc-tmp" >/dev/null 2>&1; then mv "$f.ccdc-tmp" "$f"; chmod 440 "$f"; did "commented out NOPASSWD in $f"
            else rm -f "$f.ccdc-tmp"; say "FAILED: visudo rejected edit of $f; left unchanged"; fi
        else did "comment out NOPASSWD in $f"; fi
    fi
done

# ---- 5. sshd: prepend hardening (first value wins), validate, roll back if invalid ----------
SSHD=$(command -v sshd || echo /usr/sbin/sshd)
CFG=/etc/ssh/sshd_config
if [ -x "$SSHD" ] && [ -f "$CFG" ]; then
    block="# BEGIN ccdc-harden $TS
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 30
MaxStartups 10:30:60
X11Forwarding no
PermitUserEnvironment no
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
IgnoreRhosts yes
HostbasedAuthentication no
PermitTunnel no
GatewayPorts no
UseDNS no"
    [ "$NOPW" = 1 ] && block="$block
PasswordAuthentication no
KbdInteractiveAuthentication no"
    [ "$ROOTKEYS" = 1 ] && block="$block
PermitRootLogin prohibit-password"
    [ "$NOFWD" = 1 ] && block="$block
AllowTcpForwarding no
AllowAgentForwarding no"
    block="$block
# END ccdc-harden"
    if [ "$NOPW" = 1 ] && [ "$haskey" != 1 ]; then
        say "SKIPPED --no-password-login: no team key confirmed"; block=$(echo "$block" | grep -vE '^(PasswordAuthentication|KbdInteractive)')
    fi
    if grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$CFG" && [ -d /etc/ssh/sshd_config.d ]; then
        target=/etc/ssh/sshd_config.d/00-ccdc-harden.conf
    else
        target=$CFG
    fi
    if [ "$CHECK" = 1 ]; then
        did "write sshd hardening to $target: $(echo "$block" | grep -v '^#' | tr '\n' ';')"
    else
        cp -p "$CFG" "$BK/sshd_config.before" 2>/dev/null
        [ -f /etc/ssh/sshd_config.d/00-ccdc-harden.conf ] && cp -p /etc/ssh/sshd_config.d/00-ccdc-harden.conf "$BK/00-ccdc-harden.conf.before"
        if [ "$target" = "$CFG" ]; then
            sed '/^# BEGIN ccdc-harden/,/^# END ccdc-harden/d' "$CFG" > "$CFG.ccdc-tmp"
            { echo "$block"; cat "$CFG.ccdc-tmp"; } > "$CFG.ccdc-new" && rm -f "$CFG.ccdc-tmp"
            chmod --reference="$CFG" "$CFG.ccdc-new" 2>/dev/null || chmod 600 "$CFG.ccdc-new"
            mv "$CFG.ccdc-new" "$CFG"
        else
            echo "$block" > "$target"; chmod 600 "$target"
        fi
        if "$SSHD" -t 2>/dev/null; then
            { systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || rc-service sshd reload 2>/dev/null \
              || /etc/init.d/sshd reload 2>/dev/null || kill -HUP "$(cat /var/run/sshd.pid 2>/dev/null)" 2>/dev/null; } \
              && did "sshd hardened and reloaded (existing sessions stay up)" || say "WARN: sshd config written but reload failed; reload it by hand"
        else
            say "FAILED: sshd -t rejected the new config; rolling back"
            cp -p "$BK/sshd_config.before" "$CFG"
            if [ -f "$BK/00-ccdc-harden.conf.before" ]; then cp -p "$BK/00-ccdc-harden.conf.before" /etc/ssh/sshd_config.d/00-ccdc-harden.conf
            else rm -f /etc/ssh/sshd_config.d/00-ccdc-harden.conf; fi
        fi
    fi
    "$SSHD" -T 2>/dev/null | grep -iE '^(permitrootlogin|passwordauthentication) ' | while read -r l; do say "sshd now: $l"; done
    "$SSHD" -T 2>/dev/null | awk '/^authorizedkeyscommand / && $2 != "none" {print}' | while read -r l; do review "sshd fetches keys from a program: $l (red team trick; check it)"; done
    "$SSHD" -T 2>/dev/null | awk '/^authorizedkeysfile / {for (i = 2; i <= NF; i++) if ($i != ".ssh/authorized_keys" && $i != ".ssh/authorized_keys2" && $i != "%h/.ssh/authorized_keys" && $i != "%h/.ssh/authorized_keys2") print $i}' | while read -r l; do review "extra AuthorizedKeysFile location: $l (hidden key file?)"; done
else
    say "no OpenSSH server found (dropbear?); sshd step skipped"
fi

# ---- 6. kernel settings (never touches ip_forward: routers and containers need it) ---------
SYSF=/etc/sysctl.d/99-ccdc-harden.conf
set_sysctl() {
    for kv in "kernel.dmesg_restrict=1" "kernel.kptr_restrict=1" "kernel.yama.ptrace_scope=1" "fs.protected_symlinks=1" \
              "fs.protected_hardlinks=1" "fs.suid_dumpable=0" "net.ipv4.tcp_syncookies=1" "net.ipv4.conf.all.accept_redirects=0" \
              "net.ipv4.conf.default.accept_redirects=0" "net.ipv4.conf.all.send_redirects=0" "net.ipv4.conf.all.accept_source_route=0" \
              "net.ipv4.icmp_echo_ignore_broadcasts=1" "net.ipv6.conf.all.accept_redirects=0"; do
        k=${kv%%=*}; [ -e "/proc/sys/$(echo "$k" | tr . /)" ] || continue
        echo "$kv"
    done
}
if [ "$CHECK" = 1 ]; then did "kernel settings: $(set_sysctl | tr '\n' ' ')"
else
    mkdir -p /etc/sysctl.d; set_sysctl > "$SYSF"; chmod 644 "$SYSF"
    n=0; while IFS='=' read -r k v; do sysctl -w "$k=$v" >/dev/null 2>&1 && n=$((n+1)); done < "$SYSF"
    did "applied $n kernel settings ($SYSF, survives reboot)"
fi

# ---- 7. permissions on sensitive files ----------------------------------------------------
if [ "$CHECK" = 0 ]; then
    chmod 644 /etc/passwd /etc/group 2>/dev/null
    if grep -q '^shadow:' /etc/group; then chown root:shadow /etc/shadow; chmod 640 /etc/shadow; else chmod 600 /etc/shadow; fi
    chmod 700 /root 2>/dev/null; chmod 440 /etc/sudoers 2>/dev/null
    for f in /etc/sudoers.d/*; do [ -f "$f" ] && chmod 440 "$f"; done
fi
did "set safe permissions on passwd/shadow/group/sudoers and /root"
find /etc /etc/cron* /etc/systemd/system /usr/local/bin /usr/local/sbin -xdev -type f -perm -0002 2>/dev/null | while read -r f; do
    [ "$CHECK" = 0 ] && chmod o-w "$f"; did "removed world-write from $f"
done

# ---- 8. shell history: undo the /dev/null trick and timestamp everything ------------------
if [ -L /root/.bash_history ]; then
    [ "$CHECK" = 0 ] && rm -f /root/.bash_history && touch /root/.bash_history && chmod 600 /root/.bash_history
    did "/root/.bash_history was a symlink (to $(readlink /root/.bash_history 2>/dev/null || echo ?)); restored a real file"
fi
if [ "$CHECK" = 0 ] && [ -d /etc/profile.d ]; then
    cat > /etc/profile.d/zz-ccdc-history.sh <<'EOF'
# ccdc-harden: keep timestamped shell history for incident response
if [ -n "$BASH_VERSION" ]; then
    HISTTIMEFORMAT='%F %T '; HISTSIZE=10000; HISTFILESIZE=20000; shopt -s histappend
    case "$PROMPT_COMMAND" in *"history -a"*) ;; *) PROMPT_COMMAND="history -a${PROMPT_COMMAND:+; $PROMPT_COMMAND}";; esac
fi
EOF
    chmod 644 /etc/profile.d/zz-ccdc-history.sh
fi
did "timestamped bash history for new logins (/etc/profile.d/zz-ccdc-history.sh)"

# ---- 8b. audit trail: who changed keys, accounts, sudo, cron, services (only if auditd is installed) --
if has auditctl; then
    RULES="-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /root/.ssh/ -p wa -k rootkeys
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /etc/systemd/system/ -p wa -k systemd
-w /etc/ld.so.preload -p wa -k preload
-w /etc/pam.d/ -p wa -k pam
-w /etc/profile.d/ -p wa -k profile"
    if [ "$CHECK" = 1 ]; then did "add $(echo "$RULES" | wc -l) auditd watches (keys, accounts, sudo, sshd, cron, systemd, PAM, preload, profile.d)"
    else
        [ -d /etc/audit/rules.d ] && echo "$RULES" > /etc/audit/rules.d/99-ccdc.rules && chmod 640 /etc/audit/rules.d/99-ccdc.rules
        n=0; echo "$RULES" | while read -r r; do
            p=$(echo "$r" | awk '{print $2}'); [ -e "$p" ] || continue
            # shellcheck disable=SC2086
            auditctl $r >/dev/null 2>&1
        done
        did "auditd watches on keys/accounts/sudo/sshd/cron/systemd/PAM (see changes: ausearch -k rootkeys -i | tail)"
    fi
else
    review "auditd not installed: no record of who edits keys/cron/sudo (Wazuh FIM on authorized_keys + sshd_config covers this too)"
fi

# ---- 9. things only a human should decide -------------------------------------------------
has lsattr && lsattr /etc/passwd /etc/shadow /etc/ssh/sshd_config /root/.ssh/authorized_keys /etc/resolv.conf 2>/dev/null | awk '$1 ~ /i/ {print $2}' | while read -r f; do review "immutable file (chattr +i, red team trick): $f"; done
ps -eo args 2>/dev/null | grep -iE 'shellinabox|ttyd|gotty|webmin|miniserv|cockpit-ws|telnetd' | grep -v grep | while read -r l; do review "remote shell/admin panel running: $l (stop it if not scored)"; done
grep -rnE 'pam_exec|^[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+pam_permit' /etc/pam.d/ 2>/dev/null | grep -v ':[0-9]*:[[:space:]]*#' | while read -r l; do review "PAM hook: $l"; done
for rc in /root/.bashrc /root/.bash_profile /root/.profile /etc/bash.bashrc /etc/bashrc /etc/profile; do
    [ -f "$rc" ] && grep -nE '^[[:space:]]*alias[[:space:]]+(sudo|su|ssh|ls|cd|ps|ss|netstat|cat|passwd|grep|find|top|kill|systemctl|crontab|who|w|last)=' "$rc" 2>/dev/null | grep -vE "=['\"]?(ls|grep|egrep|fgrep) --colou?r=auto['\"]?[[:space:]]*$" | while read -r l; do review "alias on a common command in $rc: $l (alias hijack?)"; done
done
echo "$PATH" | tr ':' '\n' | while read -r d; do
    [ -d "$d" ] || continue
    [ -n "$(find -L "$d" -maxdepth 0 \( -perm -0002 -o ! -user root \) 2>/dev/null)" ] && review "root PATH dir is writable by others or not owned by root: $d (PATH hijack)"
done
for t in nc ncat netcat socat nmap; do has "$t" && review "attack tool installed: $(command -v "$t") (remove if no scored service needs it)"; done
grep -vE '^[[:space:]]*(#|$)|[[:space:]](localhost|ip6-[a-z]+)([[:space:]]|$)|^(127\.|::1|fe00|ff0[0-9])' /etc/hosts 2>/dev/null | while read -r l; do say "info: /etc/hosts entry: $l (red team can redirect names here)"; done
[ -s /etc/ld.so.preload ] && review "/etc/ld.so.preload is not empty: $(tr '\n' ' ' < /etc/ld.so.preload)"
say "finished. Next: test a NEW ssh session to this box before closing any old one."

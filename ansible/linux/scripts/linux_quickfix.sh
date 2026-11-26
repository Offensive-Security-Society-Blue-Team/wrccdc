#!/bin/sh
# linux_quickfix.sh - CCDC "low-hanging fruit" CVE checker/mitigator for Linux. Default = AUDIT ONLY.
#   ansible linux -m script -a "scripts/linux_quickfix.sh"            audit every box
#   ansible linux -m script -a "scripts/linux_quickfix.sh --apply"    audit + SAFE mitigations
# Opt-in (can affect service): --regresshion (sshd LoginGraceTime 0), --sambacry (nt pipe support = no)
# Covers: PwnKit, Baron Samedit (sudo), regreSSHion, Log4Shell, xz backdoor, Shellshock, SambaCry,
# vsftpd 2.3.4 backdoor, Apache 2.4.49/50 path traversal, Dirty Pipe / Dirty COW (kernel), legacy r-services/telnet.
# PATCH-ONLY items need a package update or reboot; this script reports them so you know where to spend effort.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
APPLY=0; REGRESSHION=0; SAMBACRY=0
for a in "$@"; do case "$a" in --apply) APPLY=1;; --regresshion) REGRESSHION=1;; --sambacry) SAMBACRY=1;; esac; done
h=$(hostname -s 2>/dev/null || hostname)
TS=$(date +%Y%m%d-%H%M%S); BK=/root/.ccdc-quickfix/$TS
has() { command -v "$1" >/dev/null 2>&1; }
r() { printf '[%s] %-10s %-24s %s\n' "$h" "$1" "$2" "$3"; }
bk() { mkdir -p "$BK$(dirname "$1")" && cp -p "$1" "$BK$1"; }
# ver_ge A B: true if version A >= B (numeric dotted compare)
ver_ge() { awk -v a="$1" -v b="$2" 'BEGIN { n = split(a, x, "."); m = split(b, y, "."); if (m > n) n = m
    for (i = 1; i <= n; i++) { p = x[i] + 0; q = y[i] + 0; if (p > q) exit 0; if (p < q) exit 1 } exit 0 }'; }
[ "$(id -u)" = 0 ] || { r FAILED "-" "run as root"; exit 1; }
r INFO "mode" "$([ "$APPLY" = 1 ] && echo APPLY || echo AUDIT) | kernel $(uname -r)"

# ---- PwnKit CVE-2021-4034: any local user -> root via pkexec. Removing SUID is the official workaround --
pk=$(command -v pkexec)
if [ -n "$pk" ] && [ -u "$pk" ]; then
    if [ "$APPLY" = 1 ]; then chmod 0755 "$pk" && r FIXED "PwnKit (pkexec)" "SUID removed from $pk (patch polkit later)"
    else r VULN "PwnKit (pkexec)" "$pk is SUID; unless polkit is patched any user gets root (--apply removes SUID)"; fi
else r OK "PwnKit (pkexec)" "${pk:-not installed}${pk:+ (no SUID)}"; fi

# ---- Baron Samedit CVE-2021-3156: sudo heap overflow. Safe self-test, patch only ----------------------
if has sudoedit; then
    o=$(sudoedit -s / 2>&1 </dev/null | head -1)
    case "$o" in *"not a regular file"*) r PATCH-ONLY "Baron Samedit (sudo)" "VULNERABLE: update the sudo package";;
        *usage:*|*"Usage:"*|*"invalid option"*) r OK "Baron Samedit (sudo)" "patched";; *) r INFO "Baron Samedit (sudo)" "inconclusive: $o";; esac
fi

# ---- regreSSHion CVE-2024-6387: OpenSSH 8.5p1 to 9.7p1 on glibc ----------------------------------------
if has sshd; then
    v=$(sshd -V 2>&1 | grep -oE 'OpenSSH_[0-9]+\.[0-9]+' | head -1 | cut -d_ -f2)
    [ -z "$v" ] && v=$(ssh -V 2>&1 | grep -oE 'OpenSSH_[0-9]+\.[0-9]+' | head -1 | cut -d_ -f2)
    if [ -n "$v" ] && ver_ge "$v" 8.5 && ! ver_ge "$v" 9.8 && ldd "$(command -v sshd)" 2>/dev/null | grep -q 'libc.so.6'; then
        lgt=$(sshd -T 2>/dev/null | awk '/^logingracetime /{print $2}')
        if [ "$lgt" = 0 ]; then r OK "regreSSHion (sshd)" "OpenSSH $v, LoginGraceTime 0 (mitigated)"
        elif [ "$APPLY" = 1 ] && [ "$REGRESSHION" = 1 ]; then
            f=/etc/ssh/sshd_config.d/00-ccdc-0-cve.conf
            if grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config && [ -d /etc/ssh/sshd_config.d ]; then
                echo "LoginGraceTime 0" > "$f"; chmod 600 "$f"
            else bk /etc/ssh/sshd_config; { echo "LoginGraceTime 0 # ccdc-cve"; grep -v '# ccdc-cve' /etc/ssh/sshd_config; } > /tmp/.sc.$$ && cat /tmp/.sc.$$ > /etc/ssh/sshd_config; rm -f /tmp/.sc.$$; f=/etc/ssh/sshd_config; fi
            if sshd -t 2>/dev/null; then { systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || rc-service sshd reload 2>/dev/null; }
                r FIXED "regreSSHion (sshd)" "LoginGraceTime 0 (trade-off: idle unauthenticated connections can fill MaxStartups)"
            else r FAILED "regreSSHion (sshd)" "sshd -t rejected change; remove LoginGraceTime 0 from $f"; fi
        else r VULN "regreSSHion (sshd)" "OpenSSH $v in affected range; distro may have backported the fix. Update openssh, or --apply --regresshion"; fi
    else r OK "regreSSHion (sshd)" "OpenSSH ${v:-?} outside 8.5-9.7 (or not glibc)"; fi
fi

# ---- Log4Shell CVE-2021-44228: log4j-core < 2.17.1. Removing JndiLookup.class is Apache's workaround ----
find /opt /srv /var/lib /var/www /usr/share /usr/local /home /root -xdev -type f -name 'log4j-core-*.jar' 2>/dev/null | head -20 | while read -r j; do
    v=$(basename "$j" .jar | sed 's/^log4j-core-//')
    case "$v" in 1.*) r INFO "Log4j 1.x" "$j (end-of-life; not Log4Shell but has other CVEs)"; continue;; esac
    if ver_ge "$v" 2.17.1; then r OK "Log4Shell" "$j"; continue; fi
    if grep -aq 'org/apache/logging/log4j/core/lookup/JndiLookup.class' "$j"; then
        if [ "$APPLY" = 1 ] && has zip; then bk "$j"; zip -q -d "$j" 'org/apache/logging/log4j/core/lookup/JndiLookup.class' && r FIXED "Log4Shell" "removed JndiLookup from $j (restart that app)"
        else r VULN "Log4Shell" "$j ($v) still has JndiLookup.class$( [ "$APPLY" = 1 ] && echo ': install zip to fix' || echo ' (--apply removes it)')"; fi
    else r OK "Log4Shell" "$j ($v) JndiLookup already removed"; fi
done

# ---- xz backdoor CVE-2024-3094: xz/liblzma 5.6.0 or 5.6.1 ---------------------------------------------
if has xz; then
    v=$(xz --version 2>/dev/null | awk 'NR==1{print $NF}')
    case "$v" in 5.6.0|5.6.1) r PATCH-ONLY "xz backdoor" "xz $v is the backdoored release: downgrade/upgrade xz-libs, restart sshd";; *) r OK "xz backdoor" "xz $v";; esac
fi

# ---- Shellshock CVE-2014-6271 -----------------------------------------------------------------------------
if has bash; then
    if env 'x=() { :;}; echo SHELLSHOCK' bash -c ':' 2>/dev/null | grep -q SHELLSHOCK; then r PATCH-ONLY "Shellshock (bash)" "VULNERABLE: update bash; CGI scripts are the usual way in"
    else r OK "Shellshock (bash)" "patched"; fi
fi

# ---- SambaCry CVE-2017-7494: Samba 3.5.0 to 4.6.4 ------------------------------------------------------
if has smbd; then
    v=$(smbd -V 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [ -n "$v" ] && ver_ge "$v" 3.5.0 && ! ver_ge "$v" 4.6.5; then
        conf=$(smbd -b 2>/dev/null | awk '/CONFIGFILE/{print $2}'); conf=${conf:-/etc/samba/smb.conf}
        if grep -qiE '^[[:space:]]*nt pipe support[[:space:]]*=[[:space:]]*no' "$conf"; then r OK "SambaCry (smbd)" "Samba $v, nt pipe support = no"
        elif [ "$APPLY" = 1 ] && [ "$SAMBACRY" = 1 ]; then bk "$conf"; sed -i '/^\[global\]/a\   nt pipe support = no' "$conf"
            if testparm -s "$conf" >/dev/null 2>&1; then { systemctl reload smb 2>/dev/null || systemctl reload smbd 2>/dev/null; }; r FIXED "SambaCry (smbd)" "nt pipe support = no added"
            else cp -p "$BK$conf" "$conf"; r FAILED "SambaCry (smbd)" "testparm rejected change; restored"; fi
        else r VULN "SambaCry (smbd)" "Samba $v affected (--apply --sambacry; check scored SMB still works)"; fi
    else r OK "SambaCry (smbd)" "Samba ${v:-?}"; fi
fi

# ---- vsftpd 2.3.4 backdoor (smiley-face user opens a root shell on port 6200) ---------------------------
if has vsftpd; then
    v=$(vsftpd -v 0>&- 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [ "$v" = 2.3.4 ]; then r PATCH-ONLY "vsftpd backdoor" "vsftpd 2.3.4 is backdoored: replace the binary/package (stop it if FTP isn't scored)"
    else r OK "vsftpd backdoor" "vsftpd ${v:-?}"; fi
fi

# ---- Apache 2.4.49 / 2.4.50 path traversal + RCE (CVE-2021-41773/42013) ---------------------------------
for b in httpd apache2; do
    has "$b" || continue
    v=$($b -v 2>/dev/null | grep -oE 'Apache/[0-9.]+' | cut -d/ -f2)
    case "$v" in 2.4.49|2.4.50) r PATCH-ONLY "Apache traversal" "Apache $v: path traversal/RCE. Update; until then make sure <Directory /> has 'Require all denied'";;
        '') ;; *) r OK "Apache traversal" "Apache $v";; esac
done

# ---- Kernel local root (Dirty Pipe 5.8 to before 5.16.11/5.15.25/5.10.102; Dirty COW before 4.8.3) -------
k=$(uname -r | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+')
if [ -n "$k" ]; then
    dp=0
    ver_ge "$k" 5.8 && ! ver_ge "$k" 5.10.102 && dp=1
    ver_ge "$k" 5.11 && ! ver_ge "$k" 5.15.25 && dp=1
    ver_ge "$k" 5.16 && ! ver_ge "$k" 5.16.11 && dp=1
    if [ "$dp" = 1 ]; then
        r PATCH-ONLY "Dirty Pipe (kernel)" "kernel $k may be affected (distro kernels often backport): update kernel + reboot"
    elif ! ver_ge "$k" 4.8.3; then r PATCH-ONLY "Dirty COW (kernel)" "kernel $k predates the fix unless the distro backported it"
    else r OK "kernel local root" "$k outside Dirty Pipe / Dirty COW ranges"; fi
fi

# ---- Legacy cleartext remote shells ---------------------------------------------------------------------
for s in telnetd in.telnetd rshd in.rshd rlogind in.rlogind rexecd in.rexecd; do
    pgrep -x "$s" >/dev/null 2>&1 && r VULN "legacy service" "$s running (cleartext logins): stop it unless scored"
done
{ ss -tlnH 2>/dev/null || netstat -tln 2>/dev/null; } | grep -qE ':(23|512|513|514)[[:space:]]' && r VULN "legacy ports" "telnet/rexec/rlogin/rsh port listening"

[ -d "$BK" ] && r INFO "backups" "$BK"
r INFO "done" "VULN = fixable here, PATCH-ONLY = needs a package update or reboot"

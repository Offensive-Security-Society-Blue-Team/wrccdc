#!/bin/sh
# keys_apply.sh - runs ON each box (pushed by keys_pick.sh). Two modes:
#   --list                     print every authorized_keys entry on the box (read-only)
#   --keep-b64 B64 [--root-keys-only] [--check] [--force]
#                              keep ONLY the key blobs listed (base64 of one blob per line) in every
#                              authorized_keys file; everything else is removed (backed up first).
#                              Aborts if root would be left with no key and no CA line, unless --force.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 077
MODE=""; KEEP_B64=""; ROOTKEYS=0; CHECK=0; FORCE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --list) MODE=list ;;
        --keep-b64) MODE=apply; KEEP_B64=$2; shift ;;
        --root-keys-only) ROOTKEYS=1 ;;
        --check) CHECK=1 ;;
        --force) FORCE=1 ;;
    esac
    shift
done
h=$(hostname -s 2>/dev/null || hostname)
say() { echo "[$h] $*"; }
[ "$(id -u)" = 0 ] || { say "FAILED: must run as root"; exit 1; }

# every authorized_keys file sshd reads: "user file" per line. Covers each account's ~/.ssh, any
# AuthorizedKeysFile path (%h/%u filled in), and /etc/ssh/.ssh (the INV3 hiding spot).
# A file outside the account's home is shared by many accounts, so it is listed once as user "*".
keyfiles() {
    akf=$(sshd -T 2>/dev/null | awk 'tolower($1) == "authorizedkeysfile" {for (i = 2; i <= NF; i++) print $i}')
    {
        awk -F: '{print $1, $6}' /etc/passwd | while read -r u d; do
            for p in $akf .ssh/authorized_keys .ssh/authorized_keys2; do
                p=$(printf '%s' "$p" | sed -e "s|%h|$d|g" -e "s|%u|$u|g" -e 's|%%|%|g')
                case "$p" in /*) ;; *) p="$d/$p" ;; esac
                [ -f "$p" ] || continue
                case "$p" in "$d"/*) echo "$u $p" ;; *) echo "* $p" ;; esac
            done
        done
        for f in /etc/ssh/.ssh/authorized_keys*; do [ -f "$f" ] && echo "* $f"; done
    } | sort -u
}
# parse one line: options|type|blob|comment  (options may be empty)
parse() {
    echo "$1" | awk '{
        for (i = 1; i <= NF; i++) if ($i ~ /^(ssh-|ecdsa-|sk-)/ && $(i+1) ~ /^AAAA/) break
        if (i > NF) { print "BAD"; exit }
        o = ""; for (j = 1; j < i; j++) o = o (j > 1 ? " " : "") $j
        c = ""; for (j = i + 2; j <= NF; j++) c = c (j > i + 2 ? " " : "") $j
        print o "|" $i "|" $(i+1) "|" c }'
}

if [ "$MODE" = list ]; then
    keyfiles | while read -r u f; do
        grep -vE '^[[:space:]]*(#|$)' "$f" | while IFS= read -r l; do
            p=$(parse "$l"); [ "$p" = BAD ] && { echo "K|$h|$u|$f|bad|?|?|unparseable line|"; continue; }
            echo "K|$h|$u|$f|$p" | awk -F'|' -v OFS='|' '{ kind = ($5 ~ /cert-authority/) ? "ca" : "key"; print $1,$2,$3,$4,kind,$6,$7,$8,$5 }'
        done
    done
    echo "S|$h|permitrootlogin|$(sshd -T 2>/dev/null | awk '/^permitrootlogin /{print $2}')"
    exit 0
fi

[ "$MODE" = apply ] || { say "usage: --list | --keep-b64 B64 [--root-keys-only] [--check] [--force]"; exit 1; }
KEEP=/tmp/.ccdc-keep.$$
echo "$KEEP_B64" | base64 -d 2>/dev/null | grep '^AAAA' > "$KEEP"
[ -s "$KEEP" ] || { say "FAILED: empty keep list; nothing changed"; rm -f "$KEEP"; exit 1; }

# safety: root must keep at least one entry
rootleft=0
if [ -f /root/.ssh/authorized_keys ]; then
    while IFS= read -r l; do
        p=$(parse "$l"); [ "$p" = BAD ] && continue
        b=$(echo "$p" | cut -d'|' -f3); grep -qxF "$b" "$KEEP" && rootleft=$((rootleft + 1))
    done <<EOF
$(grep -vE '^[[:space:]]*(#|$)' /root/.ssh/authorized_keys)
EOF
fi
if [ "$rootleft" -eq 0 ] && [ "$FORCE" = 0 ]; then
    say "ABORTED: root would be left with no keys or CA lines (lockout risk). Nothing changed. Use --force to override."
    rm -f "$KEEP"; exit 1
fi

TS=$(date +%Y%m%d-%H%M%S); BK=/root/.ccdc-keys/$TS
[ "$CHECK" = 1 ] && say "CHECK MODE: nothing will be changed"
keyfiles | awk '!seen[$2]++' | while read -r u f; do
    kept=0; removed=0; out="$f.ccdc-new"
    [ "$CHECK" = 0 ] && : > "$out"
    while IFS= read -r l; do
        case "$l" in ''|'#'*) [ "$CHECK" = 0 ] && printf '%s\n' "$l" >> "$out"; continue;; esac
        p=$(parse "$l")
        b=$(echo "$p" | cut -d'|' -f3)
        if [ "$p" != BAD ] && grep -qxF "$b" "$KEEP"; then
            kept=$((kept + 1)); [ "$CHECK" = 0 ] && printf '%s\n' "$l" >> "$out"
        else
            removed=$((removed + 1))
            say "$( [ "$CHECK" = 1 ] && echo WOULD\ REMOVE || echo REMOVED ) $u: $(echo "$p" | cut -d'|' -f2) ...$(echo "$b" | tail -c 11) $(echo "$p" | cut -d'|' -f4) $(echo "$p" | cut -d'|' -f1 | cut -c1-40)"
        fi
    done < "$f"
    if [ "$CHECK" = 0 ]; then
        if [ "$removed" -gt 0 ]; then
            mkdir -p "$BK$(dirname "$f")"; cp -p "$f" "$BK$f"
            chmod --reference="$f" "$out" 2>/dev/null || chmod 600 "$out"
            chown --reference="$f" "$out" 2>/dev/null || { [ "$u" != "*" ] && chown "$u" "$out" 2>/dev/null; }
            mv "$out" "$f"
        else rm -f "$out"; fi
    fi
    say "$f: kept $kept, removed $removed"
done
rm -f "$KEEP"
[ "$CHECK" = 0 ] && [ -d "$BK" ] && say "backup of changed files: $BK  (undo: cp -a $BK/. /)"

if [ "$ROOTKEYS" = 1 ]; then
    SSHD=$(command -v sshd || echo /usr/sbin/sshd); CFG=/etc/ssh/sshd_config
    if [ ! -x "$SSHD" ]; then say "no OpenSSH server; --root-keys-only skipped"
    elif [ "$CHECK" = 1 ]; then say "WOULD set PermitRootLogin prohibit-password (passwords stop working for root; keys and certs still work)"
    else
        line="PermitRootLogin prohibit-password"
        cp -p "$CFG" "/tmp/.sshd_config.$$"
        if grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$CFG" && [ -d /etc/ssh/sshd_config.d ]; then
            T=/etc/ssh/sshd_config.d/00-ccdc-rootkeys.conf; echo "$line" > "$T"; chmod 600 "$T"
        else
            T=$CFG; grep -v '^PermitRootLogin prohibit-password # ccdc-rootkeys' "$CFG" > "$CFG.tmp"
            { echo "$line # ccdc-rootkeys"; cat "$CFG.tmp"; } > "$CFG" && rm -f "$CFG.tmp"
        fi
        if "$SSHD" -t 2>/dev/null; then
            { systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || rc-service sshd reload 2>/dev/null \
              || /etc/init.d/sshd reload 2>/dev/null; } && say "root is now keys/certs only (sshd reloaded; open sessions stay up)" \
              || say "WARN: config written but sshd reload failed; reload by hand"
        else
            say "FAILED: sshd -t rejected the change; rolled back"
            cp -p "/tmp/.sshd_config.$$" "$CFG"; [ "$T" != "$CFG" ] && rm -f "$T"
        fi
        rm -f "/tmp/.sshd_config.$$"
    fi
    say "sshd now: $("$SSHD" -T 2>/dev/null | grep -i '^permitrootlogin ')"
fi

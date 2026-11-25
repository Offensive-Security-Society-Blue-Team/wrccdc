#!/bin/sh
# pii_find.sh - READ-ONLY. Finds what the red team steals and what injects ask about: SSNs, credit card numbers
# (Luhn-checked), bulk email/phone lists, private keys, database dumps and backup files. Flags anything a web
# server, FTP server or SMB share hands out. Prints counts and MASKED samples only, never full values.
#   ansible linux -m script -a "scripts/pii_find.sh"            default places
#   ansible linux -m script -a "scripts/pii_find.sh /data"      plus extra directories
#   ansible linux -m script -a "scripts/pii_find.sh --deep"     also /opt, /tmp and /var/lib (slower)
# Ideas: UCI LOCS pii.sh, DSU ace misc/pii.sh. Our own code.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C; export LC_ALL          # byte-wise grep: many times faster than a UTF-8 locale
case "${1:-}" in
    -h|--help) cat >&2 <<'USAGE'
usage: pii_find.sh [--deep] [DIR ...]     (READ-ONLY; run as root)
  ansible linux -m script -a "scripts/pii_find.sh"
  ansible linux -m script -a "scripts/pii_find.sh /data"
  ansible linux -m script -a "scripts/pii_find.sh --deep"
USAGE
        exit 0 ;;
esac
DEEP=""; [ "${1:-}" = --deep ] && { DEEP="/opt /tmp /var/lib"; shift; }
h=$(hostname -s 2>/dev/null || hostname)
has() { command -v "$1" >/dev/null 2>&1; }
TMP=$(mktemp -d 2>/dev/null || echo /tmp/pii.$$); mkdir -p "$TMP"; trap 'rm -rf "$TMP"' EXIT

# ---- where to look, and what each place exposes ----
: > "$TMP/exposed"   # "TAG path" lines
for d in /var/www /srv/www /usr/share/nginx/html; do echo "WEB $d" >> "$TMP/exposed"; done
grep -rhoE '^[[:space:]]*(DocumentRoot|root)[[:space:]]+"?/[^";[:space:]]+' /etc/apache2 /etc/httpd /etc/nginx /etc/lighttpd 2>/dev/null | awk '{gsub(/"/, "", $2); print "WEB " $2}' >> "$TMP/exposed"
grep -hE '^(anon_root|local_root)=' /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null | cut -d= -f2 | sed 's/^/FTP /' >> "$TMP/exposed"
for d in /var/ftp /srv/ftp; do [ -d "$d" ] && echo "FTP $d" >> "$TMP/exposed"; done
grep -hiE '^[[:space:]]*path[[:space:]]*=' /etc/samba/smb.conf 2>/dev/null | sed 's/.*=[[:space:]]*/SMB /' >> "$TMP/exposed"
sort -u "$TMP/exposed" -o "$TMP/exposed"
DIRS=""
for d in /home /root /var/www /srv /var/ftp /var/backups $DEEP $(awk '{print $2}' "$TMP/exposed") "$@"; do
    [ -d "$d" ] && case " $DIRS " in *" $d "*) ;; *) DIRS="$DIRS $d";; esac
done
tag_for() { awk -v f="$1" '{ if (index(f, $2 "/") == 1 || f == $2) t = t (t ? "+" : "") $1 } END { print (t ? t "-EXPOSED" : "") }' "$TMP/exposed"; }

SSN='(^|[^0-9])[0-9]{3}-[0-9]{2}-[0-9]{4}([^0-9]|$)'
CARD='(^|[^0-9])([0-9]{4}[ -]?){3}[0-9]{4}([^0-9]|$)|(^|[^0-9])3[47][0-9]{2}[ -]?[0-9]{6}[ -]?[0-9]{5}([^0-9]|$)'
EMAIL='[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z][A-Za-z]+'
PHONE='(^|[^0-9])\(?[0-9]{3}\)?[-. ][0-9]{3}[-. ][0-9]{4}([^0-9]|$)'
SKIP='/(node_modules|vendor|\.git|site-packages|dist-packages|\.cache|\.ccdc-[a-z]+|proc|sys)/|^/var/backups/(dpkg|apt|alternatives)[.]'   # package lists: maintainer emails, not PII

# ---- fast passes: a few greps pick candidate files; only those get the detailed (slower) checks ----
# shellcheck disable=SC2086
{
    grep -rIlE -- "$SSN|$CARD|-----BEGIN [A-Z ]*PRIVATE KEY-----" $DIRS 2>/dev/null
    grep -rIcE -- "$EMAIL" $DIRS 2>/dev/null | awk -F: '$NF >= 20 {sub(/:[0-9]+$/, ""); print}'
    grep -rIcE -- "$PHONE" $DIRS 2>/dev/null | awk -F: '$NF >= 20 {sub(/:[0-9]+$/, ""); print}'
    find $DIRS -xdev -type f \( -name id_rsa -o -name id_dsa -o -name id_ecdsa -o -name id_ed25519 -o -name '*.kdbx' -o -name '*.key' \
        -o -name '*.p12' -o -name '*.pfx' -o -name 'shadow*' -o -name '*.sql' -o -name '*.sql.gz' -o -name '*.dump' -o -name '*.bak' \
        -o -name '*.backup' -o -name '.env' -o -name '*.env' -o -name 'wp-config.php.*' \) 2>/dev/null
    { has pdftotext || has unzip; } && find $DIRS -xdev -type f -size -20M \( -iname '*.pdf' -o -name '*.docx' -o -name '*.xlsx' -o -name '*.pptx' -o -name '*.odt' -o -name '*.ods' \) 2>/dev/null
} | grep -vE "$SKIP" | grep -v "^$TMP/" | sort -u > "$TMP/files"

textof() {
    case "$1" in
        *.pdf|*.PDF) has pdftotext && pdftotext -q "$1" - 2>/dev/null ;;
        *.docx|*.xlsx|*.pptx|*.odt|*.ods) has unzip && unzip -p "$1" 2>/dev/null | sed 's/<[^>]*>/ /g' ;;
        *) grep -Iq . "$1" 2>/dev/null && cat "$1" 2>/dev/null ;;
    esac
}
# Luhn check + masking for card candidates, SSN sanity check (portable awk: no regex repetition counts)
luhn() { awk '{ s = $0; gsub(/[^0-9]/, "", s); n = length(s); if (n < 13 || n > 19) next; t = 0; alt = 0
    for (i = n; i >= 1; i--) { d = substr(s, i, 1) + 0; if (alt) { d *= 2; if (d > 9) d -= 9 }; t += d; alt = !alt }
    if (t % 10 == 0) print "****-" substr(s, n - 3, 4) }'; }
ssnok() { awk '{ s = $0; gsub(/[^0-9-]/, "", s); split(s, p, "-"); a = p[1] + 0
    if (a == 0 || a == 666 || a >= 900 || p[2] + 0 == 0 || p[3] + 0 == 0) next; print "***-**-" p[3] }'; }

total=0; exposed=0
while read -r f; do
    [ -f "$f" ] || continue
    note=""
    case "$(basename "$f")" in id_rsa|id_dsa|id_ecdsa|id_ed25519|*.kdbx|*.key|*.p12|*.pfx|shadow*|*.sql|*.sql.gz|*.dump|*.bak|*.backup|.env|*.env|wp-config.php.*) note="sensitive file type" ;; esac
    textof "$f" > "$TMP/t" 2>/dev/null
    ssn=""; card=""; ne=0; np=0
    if [ -s "$TMP/t" ]; then
        grep -q -- '-----BEGIN [A-Z ]*PRIVATE KEY-----' "$TMP/t" && note="PRIVATE KEY inside"
        ssn=$(grep -oE -- "$SSN" "$TMP/t" | ssnok | sort -u)
        card=$(grep -oE -- "$CARD" "$TMP/t" | luhn | sort -u)
        ne=$(grep -oE -- "$EMAIL" "$TMP/t" | sort -u | wc -l | tr -d ' ')
        np=$(grep -cE -- "$PHONE" "$TMP/t")
    fi
    found=""
    [ -n "$ssn" ] && found="$found SSN x$(echo "$ssn" | grep -c .) (e.g. $(echo "$ssn" | head -1))"
    [ -n "$card" ] && found="$found CARD x$(echo "$card" | grep -c .) (e.g. $(echo "$card" | head -1))"
    [ "$ne" -ge 20 ] && found="$found EMAILS x$ne"
    [ "$np" -ge 20 ] && found="$found PHONES x$np"
    [ -n "$note" ] && found="$found [$note]"
    [ -z "$found" ] && continue
    tag=$(tag_for "$f")
    # a private key in someone's ~/.ssh is normal; one in a shared or odd place is a finding
    if [ "$found" = " [PRIVATE KEY inside]" ] && [ -z "$tag" ]; then case "$f" in */.ssh/*|/opt/*|/var/lib/*) continue;; esac; fi
    total=$((total + 1)); [ -n "$tag" ] && exposed=$((exposed + 1))
    printf '[%s] %-16s %s :%s\n' "$h" "${tag:-local}" "$f" "$found" >> "$TMP/out"
done < "$TMP/files"
[ -f "$TMP/out" ] && { grep -- '-EXPOSED ' "$TMP/out"; grep -v -- '-EXPOSED ' "$TMP/out"; }
echo "[$h] $total file(s) with PII or secrets, $exposed of them downloadable through web/FTP/SMB.$( has pdftotext || echo ' (no pdftotext: PDF contents not read)')"
[ "$exposed" -gt 0 ] && echo "[$h] Move *-EXPOSED files out of the shared path (keep a copy for evidence) and write it up as an incident."
exit 0

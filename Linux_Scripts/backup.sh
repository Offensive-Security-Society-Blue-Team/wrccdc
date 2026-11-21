#!/bin/sh
# backup.sh - back up ONE box by hand (use 02_backup.yml when Ansible works).
# Copies /etc, /root, web roots and app folders, plus MySQL/PostgreSQL dumps
# when root can reach them, into one archive.
#
# Usage:   sudo sh backup.sh               # archive goes to /var/tmp
#          sudo sh backup.sh /some/dir
# Then copy it OFF the box and delete it from the box:
#          scp root@<box>:/var/tmp/bk-<host>-<time>.tgz .
# It holds /etc/shadow and database dumps: treat it like a password file.
#
# Restore ONE file (never untar over /):
#          mkdir -p /tmp/r && tar xzf bk-....tgz -C /tmp/r etc/nginx/nginx.conf
#          cp /tmp/r/etc/nginx/nginx.conf /etc/nginx/nginx.conf

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 077
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo sh backup.sh)"; exit 1; }

dest=${1:-/var/tmp}
ts=$(date +%Y%m%d-%H%M%S)
host=$(hostname)
out="$dest/bk-$host-$ts.tgz"
db=$(mktemp -d /tmp/.bkdb.XXXXXX)

paths=""
for p in /etc /root /var/www /srv /opt /var/lib/gitea /usr/local/etc; do
    [ -e "$p" ] && paths="$paths $p"
done

if command -v mysqldump >/dev/null 2>&1; then
    if mysqldump --all-databases --single-transaction > "$db/mysql_all.sql" 2>"$db/mysql.err"; then
        echo "mysql: dumped"
    else
        echo "mysql: FAILED (needs a password? try: mysqldump -u root -p --all-databases > db.sql)"
    fi
fi
if command -v pg_dumpall >/dev/null 2>&1; then
    if su -s /bin/sh postgres -c pg_dumpall > "$db/postgres_all.sql" 2>"$db/pg.err"; then
        echo "postgres: dumped"
    else
        echo "postgres: FAILED (see pg.err inside the archive)"
    fi
fi

echo "archiving:$paths + database dumps"
# shellcheck disable=SC2086
tar czf "$out" --exclude='*/.cache' --exclude='*/node_modules' --exclude='*.iso' \
    $paths "$db" 2>"$out.err"
rc=$?
rm -rf "$db"
if [ "$rc" -gt 1 ] || [ ! -s "$out" ]; then
    echo "FAILED (tar exit $rc) - see $out.err"
    exit 1
fi
rm -f "$out.err"

echo "saved: $out  ($(du -h "$out" | cut -f1))"
if command -v sha256sum >/dev/null 2>&1; then sha256sum "$out"; fi
echo "next: copy it off the box (scp), then: rm $out"

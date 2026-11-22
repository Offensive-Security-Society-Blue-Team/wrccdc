#!/bin/sh
# backup.sh - back up ONE box by hand (use 02_backup.yml when Ansible works).
# Copies /etc, /root, web roots and app folders, plus MySQL/PostgreSQL dumps
# when root can reach them, into one archive.
#
# Usage:   sudo sh backup.sh               # archive goes to /var/tmp
#          sudo sh backup.sh /some/dir     # dir must already exist
#          sh backup.sh -h                 # prints these examples
# Then copy it OFF the box and delete it from the box:
#          scp root@<box>:/var/tmp/bk-<host>-<time>.tgz .
# It holds /etc/shadow and database dumps: treat it like a password file.
#
# Restore ONE file (never untar over /):
#          mkdir -p /tmp/r && tar xzf bk-....tgz -C /tmp/r etc/nginx/nginx.conf
#          cp /tmp/r/etc/nginx/nginx.conf /etc/nginx/nginx.conf

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 077
usage() {
    [ -n "${1:-}" ] && echo "error: $1" >&2
    cat >&2 <<'USAGE'
usage: backup.sh [DIR]     (run as root; archive goes to DIR, default /var/tmp)
  sudo sh backup.sh
  sudo sh backup.sh /root/bk
  then: scp root@<box>:/var/tmp/bk-<host>-<time>.tgz .
USAGE
    [ -n "${1:-}" ] && exit 1
    exit 0
}
case "${1:-}" in -h|--help) usage ;; esac
[ $# -le 1 ] || usage "only one argument: the folder to write the archive to"
case "${1:-}" in -*) usage "unknown option: $1" ;; esac
[ -z "${1:-}" ] || [ -d "$1" ] || usage "$1 is not a folder"
[ "$(id -u)" -eq 0 ] || usage "must run as root"

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

#!/bin/sh
# php_find.sh - READ-ONLY. Shows PHP versions, how PHP is served, and web files changed today.
# Usage (from ansible/linux):  ansible linux -m script -a scripts/php_find.sh
# On a box:  sudo sh php_find.sh      Help: sh php_find.sh -h
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
usage() {
    [ -n "${1:-}" ] && echo "error: $1" >&2
    cat >&2 <<'USAGE'
usage: php_find.sh     (no arguments; READ-ONLY)
  ansible linux -m script -a scripts/php_find.sh
  sudo sh php_find.sh
USAGE
    [ -n "${1:-}" ] && exit 1
    exit 0
}
case "${1:-}" in -h|--help) usage ;; esac
[ $# -eq 0 ] || usage "this script takes no arguments (got: $*)"
[ "$(id -u)" -eq 0 ] || echo "[warn] not root: docker and some web roots will be hidden (run: sudo sh php_find.sh)" >&2
echo "===== $(hostname) ====="
found=0
for b in /usr/bin/php* /usr/sbin/php-fpm* /usr/local/bin/php* /usr/local/sbin/php-fpm*; do
    [ -x "$b" ] || continue
    case "$b" in *config*|*phpize*|*phar*|*dbg*) continue ;; esac
    v=$("$b" -v 2>/dev/null | head -1)
    [ -n "$v" ] && { found=1; echo "[php] $b -> $v"; }
done
[ "$found" -eq 1 ] || echo "(no php binary on host)"
echo "-- php packages"
{ dpkg -l 2>/dev/null | awk '/^ii/ && $2 ~ /php/ {print $2, $3}'
  rpm -qa 2>/dev/null | grep -i '^php'
  apk info -v 2>/dev/null | grep -i '^php'; } | head -15
echo "-- PHP2Shell fix in distro changelog? (backports keep the old version number)"
{ for c in /usr/share/doc/php*-common/changelog.Debian.gz; do [ -f "$c" ] && zcat "$c" | grep -m1 -o 'CVE-2026-1096..' | sed "s|^|$c: |"; done
  rpm -q --changelog php-common 2>/dev/null | grep -m1 -o 'CVE-2026-1096..'; } | grep . || echo "(no CVE-2026-109618/9 mention found - treat as UNPATCHED unless version >= 8.2.35/8.3.36/8.4.27/8.5.12)"
echo "-- php / web server processes"
{ ps -eo user,pid,args 2>/dev/null || ps; } | grep -E '[p]hp|[a]pache2|[h]ttpd|[n]ginx|[f]rankenphp' | cut -c1-110 | head -8
echo "-- php in docker"
docker ps --format '{{.Names}}  {{.Image}}' 2>/dev/null | grep -iE 'php|wordpress|nextcloud|drupal|joomla|laravel' || echo "(none)"
echo "-- listening web ports"
{ ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null; } | grep -E ':(80|443|8080|8443|9000) ' | awk '{print $4, $NF}' | head -8
echo "-- .php files changed today (possible webshells)"
find /var/www /srv /usr/share/nginx /usr/share/webapps /opt -name '*.php' -newermt "$(date +%Y-%m-%d)" -type f 2>/dev/null | head -20
true

#!/bin/sh
# php2shell_mitigate.sh - STOPGAP for PHP2Shell (CVE-2026-109618/109619) until PHP is patched.
# Drops 99-php2shell.ini into every PHP conf.d dir, then restarts PHP/web services. Undo: delete the file + restart.
# Usage (from ansible/linux):
#   ansible linux -m script -a scripts/php_find.sh                 # first: which boxes run PHP
#   ansible skerja -m script -a scripts/php2shell_mitigate.sh      # then only those boxes
# On a box:  sudo sh php2shell_mitigate.sh      Help: sh php2shell_mitigate.sh -h
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
usage() {
    [ -n "${1:-}" ] && echo "error: $1" >&2
    cat >&2 <<'USAGE'
usage: php2shell_mitigate.sh     (no arguments; CHANGES PHP config + restarts web; run as root)
  ansible linux -m script -a scripts/php_find.sh             # find the PHP boxes first
  ansible skerja -m script -a scripts/php2shell_mitigate.sh
  sudo sh php2shell_mitigate.sh
USAGE
    [ -n "${1:-}" ] && exit 1
    exit 0
}
case "${1:-}" in -h|--help) usage ;; esac
[ $# -eq 0 ] || usage "this script takes no arguments (got: $*)"
[ "$(id -u)" -eq 0 ] || usage "must run as root"
echo "===== $(hostname) ====="
n=0
for d in /etc/php/*/*/conf.d /etc/php.d /etc/php[0-9]*/conf.d /usr/local/etc/php/conf.d; do
    [ -d "$d" ] || continue
    printf '%s\n' '; PHP2Shell stopgap (CVE-2026-109618/109619) - blue team INV3. Remove after patching.' \
        'session.upload_progress.enabled = 0' 'fatal_error_backtraces = 0' 'memory_limit = -1' > "$d/99-php2shell.ini"
    echo "wrote $d/99-php2shell.ini"; n=$((n + 1))
done
[ "$n" -gt 0 ] || { echo "no PHP conf.d dirs - nothing to do"; exit 0; }
for f in /usr/sbin/php-fpm*; do [ -x "$f" ] && { "$f" -t 2>&1 | tail -1; }; done
if command -v systemctl >/dev/null 2>&1; then
    for s in $(systemctl list-units --type=service --state=running --no-legend 2>/dev/null | awk '{print $1}' | grep -E '^(php.*fpm|apache2|httpd)\.service$'); do
        systemctl restart "$s" && echo "restarted $s" || echo "FAILED to restart $s - check: systemctl status $s"
    done
else
    for s in /etc/init.d/php-fpm* /etc/init.d/apache2; do
        [ -x "$s" ] || continue
        rc-service "${s##*/}" status >/dev/null 2>&1 && rc-service "${s##*/}" restart && echo "restarted ${s##*/}"
    done
fi
php -r 'echo "cli check: upload_progress=", var_export((bool)ini_get("session.upload_progress.enabled"), true), " memory_limit=", ini_get("memory_limit"), "\n";' 2>/dev/null
true

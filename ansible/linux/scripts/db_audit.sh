#!/bin/sh
# db_audit.sh - runs on each box. Finds the database holes the red team uses: empty passwords, anonymous users,
# root reachable from the network, FILE privilege + no secure_file_priv (= write a web shell through SQL),
# databases listening on every interface, PostgreSQL 'trust' logins, Redis without a password.
# Default is READ-ONLY. Options:
#   --fix                  drop anonymous MySQL users and root accounts reachable from other hosts
#   --log-queries          turn on the MySQL general query log (/var/log/mysql/ccdc-queries.log) for IR evidence
#   --rotate USER@HOST     new random password for one MySQL user; prints it as PW|... and lists the app config
#                          files that mention the user, which must be updated or the app breaks
#   --mysql-defaults FILE  credentials file if root can't log in through the socket (e.g. /etc/mysql/debian.cnf)
# Ideas: UCI LOCS mysql_audit.sh / psql_audit.sh. Our own code.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
FIX=0; LOGQ=0; ROTATE=""; DEFS=""
usage() {
    [ -n "${1:-}" ] && echo "error: $1" >&2
    cat >&2 <<'USAGE'
usage: db_audit.sh [--fix] [--log-queries] [--rotate USER@HOST] [--mysql-defaults FILE]   (run as root; READ-ONLY without options)
  ansible linux -m script -a "scripts/db_audit.sh"
  ansible haf -m script -a "scripts/db_audit.sh --mysql-defaults /etc/mysql/debian.cnf"
  ansible haf -m script -a "scripts/db_audit.sh --fix --log-queries"
  ANSIBLE_LOG_PATH=/dev/null ansible haf -m script -a "scripts/db_audit.sh --rotate wordpress@localhost" | grep '^PW|'
USAGE
    [ -n "${1:-}" ] && exit 1
    exit 0
}
needval() { [ $# -ge 2 ] && [ -n "$2" ] || usage "$1 needs a value"; }
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage ;;
        --fix) FIX=1 ;;
        --log-queries) LOGQ=1 ;;
        --rotate) needval "$@"; ROTATE=$2; shift ;;
        --mysql-defaults) needval "$@"; DEFS=$2; shift ;;
        *) usage "unknown option: $1" ;;
    esac
    shift
done
h=$(hostname -s 2>/dev/null || hostname)
r() { printf '[%s] %-7s %-22s %s\n' "$h" "$1" "$2" "$3"; }
has() { command -v "$1" >/dev/null 2>&1; }
[ "$(id -u)" = 0 ] || { r FAILED - "run as root"; exit 1; }
listen_all() { { ss -tln 2>/dev/null || netstat -tln 2>/dev/null; } | awk -v p=":$1" '$4 ~ p"$" && $4 ~ /^(0\.0\.0\.0|\*|\[::\]|::):/ {f = 1} END {exit !f}'; }

# ================= MySQL / MariaDB =================
MY=$(command -v mariadb || command -v mysql)
if [ -n "$MY" ] && { pgrep -x mysqld >/dev/null 2>&1 || pgrep -x mariadbd >/dev/null 2>&1; }; then
    AUTH=""
    for d in "$DEFS" /etc/mysql/debian.cnf /root/.my.cnf; do
        [ -n "$d" ] && [ -f "$d" ] && "$MY" --defaults-file="$d" -N -e 'SELECT 1' >/dev/null 2>&1 && { AUTH="--defaults-file=$d"; break; }
    done
    [ -z "$AUTH" ] && "$MY" -N -e 'SELECT 1' >/dev/null 2>&1 && AUTH="socket"
    q() { if [ "$AUTH" = socket ]; then "$MY" -N -B -e "$1" 2>/dev/null; else "$MY" "$AUTH" -N -B -e "$1" 2>/dev/null; fi; }
    if [ -z "$AUTH" ]; then
        r MANUAL "MySQL/MariaDB" "running, but root can't log in without a password: re-run with --mysql-defaults FILE"
    else
        r INFO "MySQL/MariaDB" "$(q 'SELECT VERSION()') (logged in via ${AUTH#--defaults-file=})"
        listen_all 3306 && r REVIEW "MySQL network" "listening on ALL interfaces: anyone can try passwords (bind it or firewall.sh mgmt port 3306)"
        # one row per account: user, host, plugin, password state
        SYS="'mariadb.sys','mysql.sys','mysql.session','mysql.infoschema','mysql'"
        users=$(q "SELECT CONCAT_WS('|', user, host, IFNULL(plugin,''), IF(IFNULL(authentication_string,'')='' AND IFNULL(password,'')='', 'EMPTY', 'set')) FROM mysql.user WHERE user NOT IN ($SYS)" ||
                q "SELECT CONCAT_WS('|', user, host, IFNULL(plugin,''), IF(IFNULL(authentication_string,'')='', 'EMPTY', 'set')) FROM mysql.user WHERE user NOT IN ($SYS)")
        echo "$users" | while IFS='|' read -r u hst plug pw; do
            [ -z "$u$hst" ] && continue
            flags=""
            [ -z "$u" ] && flags="$flags ANONYMOUS"
            [ "$pw" = EMPTY ] && case "$plug" in *socket*|*gssapi*) ;; *) flags="$flags EMPTY-PASSWORD";; esac
            [ "$u" = root ] && case "$hst" in localhost|127.0.0.1|::1) ;; *) flags="$flags ROOT-FROM-NETWORK";; esac
            if [ -n "$flags" ]; then r VULN "MySQL account" "'$u'@'$hst' ${plug:+($plug)}:$flags"
            elif [ "$hst" = % ]; then r REVIEW "MySQL account" "'$u'@'$hst' can log in from any host (fine if the app is on another box)"
            else r OK "MySQL account" "'$u'@'$hst' ${plug:+($plug)}"; fi
        done
        q "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE File_priv='Y' AND user<>'root' AND user NOT IN ($SYS)" | while read -r a; do r VULN "MySQL FILE privilege" "$a can read/write server files (web shell via INTO OUTFILE)"; done
        sfp=$(q "SELECT @@secure_file_priv")
        [ -z "$sfp" ] || [ "$sfp" = NULL ] && r VULN "secure_file_priv" "empty: SQL can write files anywhere mysqld can (set secure_file_priv in my.cnf, restart)"
        r INFO "databases" "$(q "SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN ('mysql','information_schema','performance_schema','sys')" | tr '\n' ' ')"
        if [ "$FIX" = 1 ]; then
            echo "$users" | while IFS='|' read -r u hst plug pw; do
                if [ -z "$u" ] && [ -n "$hst" ]; then q "DROP USER ''@'$hst'" ; r FIXED "MySQL account" "dropped anonymous ''@'$hst'"; fi
                if [ "$u" = root ]; then case "$hst" in localhost|127.0.0.1|::1) ;; *) q "DROP USER 'root'@'$hst'"; r FIXED "MySQL account" "dropped 'root'@'$hst' (root now local-only)";; esac; fi
            done
            q "FLUSH PRIVILEGES" >/dev/null
        fi
        if [ "$LOGQ" = 1 ]; then
            mkdir -p /var/log/mysql; touch /var/log/mysql/ccdc-queries.log; chown mysql: /var/log/mysql/ccdc-queries.log 2>/dev/null
            q "SET GLOBAL general_log_file='/var/log/mysql/ccdc-queries.log'"; q "SET GLOBAL general_log=ON"
            r FIXED "query log" "every query now logged to /var/log/mysql/ccdc-queries.log (turn off: SET GLOBAL general_log=OFF)"
        fi
        if [ -n "$ROTATE" ]; then
            ru=${ROTATE%@*}; rh=${ROTATE#*@}; [ "$rh" = "$ROTATE" ] && rh=localhost
            pw=$(tr -dc 'A-Za-z0-9' < /dev/urandom 2>/dev/null | head -c 20)
            if q "ALTER USER '$ru'@'$rh' IDENTIFIED BY '$pw'" || q "SET PASSWORD FOR '$ru'@'$rh' = PASSWORD('$pw')"; then
                echo "PW|$h|mysql:$ru@$rh|$pw"
                r FIXED "MySQL password" "'$ru'@'$rh' changed. UPDATE THESE APP CONFIGS or the app breaks:"
                grep -rlI -- "$ru" /var/www /srv /opt /etc 2>/dev/null | grep -vE '/(mysql|mariadb)/|\.log$' | head -15 | while read -r f; do r REVIEW "uses $ru" "$f"; done
            else r FAILED "MySQL password" "could not change '$ru'@'$rh' (does the account exist?)"; fi
        fi
    fi
fi

# ================= PostgreSQL =================
if has psql && id postgres >/dev/null 2>&1 && { pgrep -x postgres >/dev/null 2>&1 || pgrep -f 'postgres: ' >/dev/null 2>&1; }; then
    pq() { su -s /bin/sh postgres -c "psql -At -c \"$1\"" 2>/dev/null; }
    r INFO "PostgreSQL" "$(pq 'SHOW server_version')"
    pq "SELECT rolname, rolsuper, rolcanlogin, (rolpassword IS NULL) FROM pg_authid WHERE rolcanlogin" | while IFS="|" read -r role su _login nopw; do
        flags=""; [ "$su" = t ] && [ "$role" != postgres ] && flags="$flags SUPERUSER"; [ "$nopw" = t ] && flags="$flags NO-PASSWORD"
        if [ -n "$flags" ]; then r REVIEW "Postgres role" "$role:$flags"; else r OK "Postgres role" "$role"; fi
    done
    hba=$(pq 'SHOW hba_file')
    [ -f "$hba" ] && grep -vE '^[[:space:]]*(#|$)' "$hba" | while read -r l; do
        case "$l" in *trust*) r VULN "pg_hba.conf" "'$l' = no password needed";; esac
        echo "$l" | grep -qE '(0\.0\.0\.0/0|::/0|[[:space:]]all[[:space:]]*$)' && r REVIEW "pg_hba.conf" "'$l' allows any address"
    done
    la=$(pq 'SHOW listen_addresses'); [ "$la" = '*' ] && r REVIEW "Postgres network" "listen_addresses='*' (every interface)"
fi

# ================= Redis =================
if has redis-cli && pgrep -x redis-server >/dev/null 2>&1; then
    if redis-cli ping 2>/dev/null | grep -q PONG; then
        r VULN "Redis" "no password: anyone who reaches it can write files/cron/SSH keys (set requirepass, bind 127.0.0.1)"
        redis-cli config get protected-mode 2>/dev/null | tail -1 | grep -q no && r VULN "Redis" "protected-mode no"
    else r OK "Redis" "requires a password"; fi
fi
[ -z "$MY" ] && ! has psql && ! has redis-cli && r INFO "databases" "no MySQL/MariaDB, PostgreSQL or Redis client found"
exit 0

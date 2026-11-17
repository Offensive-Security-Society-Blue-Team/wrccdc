#!/usr/bin/env bash
# defaultcreds.sh — rotate stock service passwords (portable fallback for Go
# `defaultcreds`, Linux behavior). Locks out attackers relying on default/known
# credentials for MySQL/MariaDB, WordPress and Gitea/Forgejo. Each service is
# best-effort: a missing tool/config is reported, not fatal.
#
#   sudo ./defaultcreds.sh --dry-run
#   sudo ./defaultcreds.sh --gitea-admin giteaadmin
#   sudo ./defaultcreds.sh --services mysql --mysql-all --mysql-pass 'oldRootPw'
#
# Flags mirror the Go tool: --services --out --length --dry-run
#   --mysql-bin --mysql-user --mysql-pass --mysql-host --mysql-all
#   --wp-path --wp-admin
#   --gitea-bin --gitea-config --gitea-admin --gitea-runas
set -u

SERVICES="mysql,wordpress,gitea"
OUT=""
LENGTH=24
DRY_RUN=0
MYSQL_BIN=""; MYSQL_USER="root"; MYSQL_PASS=""; MYSQL_HOST="127.0.0.1"; MYSQL_ALL=0
WP_PATH=""; WP_ADMIN="admin"
GITEA_BIN=""; GITEA_CONF=""; GITEA_ADMIN=""; GITEA_RUNAS="git"

while [ $# -gt 0 ]; do
  case "$1" in
    --services) SERVICES="$2"; shift 2;;      --services=*) SERVICES="${1#*=}"; shift;;
    --out) OUT="$2"; shift 2;;                --out=*) OUT="${1#*=}"; shift;;
    --length) LENGTH="$2"; shift 2;;          --length=*) LENGTH="${1#*=}"; shift;;
    --dry-run) DRY_RUN=1; shift;;
    --mysql-bin) MYSQL_BIN="$2"; shift 2;;    --mysql-bin=*) MYSQL_BIN="${1#*=}"; shift;;
    --mysql-user) MYSQL_USER="$2"; shift 2;;  --mysql-user=*) MYSQL_USER="${1#*=}"; shift;;
    --mysql-pass) MYSQL_PASS="$2"; shift 2;;  --mysql-pass=*) MYSQL_PASS="${1#*=}"; shift;;
    --mysql-host) MYSQL_HOST="$2"; shift 2;;  --mysql-host=*) MYSQL_HOST="${1#*=}"; shift;;
    --mysql-all) MYSQL_ALL=1; shift;;
    --wp-path) WP_PATH="$2"; shift 2;;        --wp-path=*) WP_PATH="${1#*=}"; shift;;
    --wp-admin) WP_ADMIN="$2"; shift 2;;      --wp-admin=*) WP_ADMIN="${1#*=}"; shift;;
    --gitea-bin) GITEA_BIN="$2"; shift 2;;    --gitea-bin=*) GITEA_BIN="${1#*=}"; shift;;
    --gitea-config) GITEA_CONF="$2"; shift 2;; --gitea-config=*) GITEA_CONF="${1#*=}"; shift;;
    --gitea-admin) GITEA_ADMIN="$2"; shift 2;; --gitea-admin=*) GITEA_ADMIN="${1#*=}"; shift;;
    --gitea-runas) GITEA_RUNAS="$2"; shift 2;; --gitea-runas=*) GITEA_RUNAS="${1#*=}"; shift;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown flag: $1" >&2; exit 2;;
  esac
done

ts() { date +%H:%M:%S; }
info() { printf '[%s] [*] %s\n' "$(ts)" "$*" >&2; }
good() { printf '[%s] [+] %s\n' "$(ts)" "$*" >&2; }
err()  { printf '[%s] [-] %s\n' "$(ts)" "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

HOST="$(hostname 2>/dev/null || echo unknown)"
if [ "$(id -u)" = "0" ]; then SECRETDIR="/root/wrccdc"
elif [ -n "${HOME:-}" ]; then SECRETDIR="$HOME/wrccdc"
else SECRETDIR="${TMPDIR:-/tmp}/wrccdc"; fi
[ -z "$OUT" ] && OUT="$SECRETDIR/${HOST}-default_creds.txt"

# Alphanumeric password generation (symbols off: these flow through SQL/config).
LOWER='abcdefghijkmnopqrstuvwxyz'; UPPER='ABCDEFGHJKLMNPQRSTUVWXYZ'; DIGITS='23456789'
rand_int() {
  local max="$1" b limit; limit=$(( 256 - (256 % max) ))
  while :; do
    b=$(od -An -N1 -tu1 /dev/urandom 2>/dev/null | tr -d ' ')
    [ -z "$b" ] && b=$(( RANDOM % 256 ))
    if [ "$b" -lt "$limit" ]; then printf '%s' $(( b % max )); return; fi
  done
}
pick() { local set="$1" i; i=$(rand_int ${#set}); printf '%s' "${set:i:1}"; }
generate() {
  local len="$LENGTH"; [ "$len" -lt 8 ] && len=8
  local pool="$LOWER$UPPER$DIGITS"; local -a req=("$LOWER" "$UPPER" "$DIGITS")
  local -a out=(); local c
  for c in "${req[@]}"; do out+=("$(pick "$c")"); done
  while [ "${#out[@]}" -lt "$len" ]; do out+=("$(pick "$pool")"); done
  local i j tmp
  for (( i=${#out[@]}-1; i>0; i-- )); do
    j=$(rand_int $(( i+1 ))); tmp="${out[i]}"; out[i]="${out[j]}"; out[j]="$tmp"
  done
  printf '%s' "$(IFS=; echo "${out[*]}")"
}

CRED_ROWS=""
record() { CRED_ROWS="${CRED_ROWS}$1,$2,$3,$4\n"; }
firstline() { head -n1 2>/dev/null | sed 's/^ *//;s/ *$//'; }
escq() { printf '%s' "$1" | sed "s/'/''/g"; }

want() { case ",$(printf '%s' "$SERVICES" | tr '[:upper:]' '[:lower:]')," in *",$1,"*) return 0;; *) return 1;; esac; }

info "host=$HOST os=linux — rotating default service credentials (dry-run=$DRY_RUN)"

# --------------------------------------------------------------- MySQL -----
resolve_mysql() {
  [ -n "$MYSQL_BIN" ] && { printf '%s' "$MYSQL_BIN"; return; }
  if have mysql; then printf 'mysql'; return; fi
  for c in /usr/bin/mysql /usr/local/bin/mysql /usr/bin/mariadb; do
    [ -x "$c" ] && { printf '%s' "$c"; return; }
  done
  have mariadb && printf 'mariadb'
}
mysql_q() { # sql -> runs with MYSQL_PWD if set
  local sql="$1"
  if [ -n "$MYSQL_PASS" ]; then
    MYSQL_PWD="$MYSQL_PASS" "$MBIN" -u "$MYSQL_USER" -h "$MYSQL_HOST" --protocol=TCP -N -B -e "$sql" 2>&1
  else
    "$MBIN" -u "$MYSQL_USER" -h "$MYSQL_HOST" --protocol=TCP -N -B -e "$sql" 2>&1
  fi
}
do_mysql() {
  MBIN="$(resolve_mysql)"
  if [ -z "$MBIN" ]; then
    record mysql - "" "skipped: mysql client not found (install or pass --mysql-bin)"
    err "mysql - skipped: client not found"; return
  fi
  if ! mysql_q "SELECT 1" >/dev/null 2>&1; then
    record mysql "$MYSQL_USER" "" "skipped: cannot authenticate"
    err "mysql $MYSQL_USER skipped: cannot authenticate"; return
  fi
  local -a targets=()
  if [ "$MYSQL_ALL" = "1" ]; then
    while IFS=$'\t' read -r u h; do
      [ -z "$u" ] && continue
      case "$(printf '%s' "$u" | tr '[:upper:]' '[:lower:]')" in
        mysql.sys|mysql.session|mysql.infoschema|debian-sys-maint|mariadb.sys) continue;;
      esac
      targets+=("'$(escq "$u")'@'$(escq "$h")'")
    done < <(mysql_q "SELECT CONCAT(user,'\t',host) FROM mysql.user" 2>/dev/null)
  else
    for h in localhost 127.0.0.1 '%'; do
      if [ -n "$(mysql_q "SELECT 1 FROM mysql.user WHERE user='$(escq "$MYSQL_USER")' AND host='$(escq "$h")'" 2>/dev/null)" ]; then
        targets+=("'$(escq "$MYSQL_USER")'@'$(escq "$h")'")
      fi
    done
    [ "${#targets[@]}" -eq 0 ] && targets+=("'$(escq "$MYSQL_USER")'@'localhost'")
  fi
  for t in "${targets[@]}"; do
    pw="$(generate)"
    if [ "$DRY_RUN" = "1" ]; then record mysql "$t" "$pw" "dry-run"; good "mysql $t dry-run"; continue; fi
    if mysql_q "ALTER USER $t IDENTIFIED BY '$pw'" >/dev/null 2>&1 \
       || mysql_q "SET PASSWORD FOR $t = PASSWORD('$pw')" >/dev/null 2>&1; then
      mysql_q "FLUSH PRIVILEGES" >/dev/null 2>&1
      record mysql "$t" "$pw" "changed"; good "mysql $t changed"
    else
      record mysql "$t" "" "error: alter/set password failed"; err "mysql $t error"
    fi
  done
}

# ------------------------------------------------------------ WordPress ----
find_wp() {
  local r sub
  for r in /var/www/html /var/www /usr/share/nginx/html /srv/www /srv/http /srv; do
    [ -f "$r/wp-config.php" ] && { printf '%s' "$r"; return; }
    [ -d "$r" ] || continue
    for sub in "$r"/*/; do
      [ -f "${sub}wp-config.php" ] && { printf '%s' "${sub%/}"; return; }
    done
  done
}
wp_define() { # file key
  sed -n -E "s/.*define\(\s*['\"]$2['\"]\s*,\s*['\"]([^'\"]*)['\"].*/\1/ip" "$1" 2>/dev/null | head -n1
}
do_wordpress() {
  local dir="$WP_PATH"
  [ -z "$dir" ] && dir="$(find_wp)"
  if [ -z "$dir" ]; then
    record wordpress - "" "skipped: no wp-config.php found (pass --wp-path)"
    err "wordpress - skipped: no wp-config.php"; return
  fi
  pw="$(generate)"
  local user="$WP_ADMIN @ $dir"
  if [ "$DRY_RUN" = "1" ]; then record wordpress "$user" "$pw" "dry-run"; good "wordpress $user dry-run"; return; fi
  if have wp; then
    if wp user update "$WP_ADMIN" --user_pass="$pw" --path="$dir" --allow-root >/dev/null 2>&1; then
      record wordpress "$user" "$pw" "changed (wp-cli)"; good "wordpress $user changed (wp-cli)"; return
    fi
  fi
  # DB fallback: WordPress accepts a legacy 32-char MD5 and upgrades on login.
  local cfg="$dir/wp-config.php"
  local name dbuser dbpass dbhost prefix
  name="$(wp_define "$cfg" DB_NAME)"; dbuser="$(wp_define "$cfg" DB_USER)"
  dbpass="$(wp_define "$cfg" DB_PASSWORD)"; dbhost="$(wp_define "$cfg" DB_HOST)"
  prefix="$(sed -n -E "s/^[[:space:]]*\\\$table_prefix[[:space:]]*=[[:space:]]*['\"]([^'\"]+)['\"].*/\1/p" "$cfg" 2>/dev/null | head -n1)"
  [ -z "$prefix" ] && prefix="wp_"
  if [ -z "$name" ] || [ -z "$dbuser" ]; then
    record wordpress "$user" "" "error: could not parse DB credentials from wp-config.php"
    err "wordpress $user error: parse wp-config.php"; return
  fi
  [ -z "$dbhost" ] && dbhost="localhost"
  MBIN="$(resolve_mysql)"
  if [ -z "$MBIN" ]; then
    record wordpress "$user" "" "error: wp-cli absent and mysql client not found"
    err "wordpress $user error: no mysql client"; return
  fi
  local hash; hash="$(printf '%s' "$pw" | md5sum 2>/dev/null | awk '{print $1}')"
  local sql="UPDATE ${prefix}users SET user_pass='$hash' WHERE user_login='$(escq "$WP_ADMIN")'"
  local -a a=(-u "$dbuser")
  if [ "$dbhost" != "localhost" ]; then
    local hp_host="${dbhost%%:*}" hp_port=""
    case "$dbhost" in *:*) hp_port="${dbhost##*:}";; esac
    a+=(-h "$hp_host" --protocol=TCP)
    [ -n "$hp_port" ] && a+=(-P "$hp_port")
  fi
  a+=("$name" -e "$sql")
  if [ -n "$dbpass" ]; then MYSQL_PWD="$dbpass" "$MBIN" "${a[@]}" >/dev/null 2>&1
  else "$MBIN" "${a[@]}" >/dev/null 2>&1; fi
  if [ $? -eq 0 ]; then record wordpress "$user" "$pw" "changed (db md5)"; good "wordpress $user changed (db md5)"
  else record wordpress "$user" "" "error: db update failed"; err "wordpress $user error: db update"; fi
}

# --------------------------------------------------------------- Gitea -----
resolve_gitea() {
  [ -n "$GITEA_BIN" ] && { printf '%s' "$GITEA_BIN"; return; }
  if have gitea; then printf 'gitea'; return; fi
  for c in /usr/local/bin/gitea /usr/bin/gitea /usr/local/bin/forgejo /usr/bin/forgejo; do
    [ -x "$c" ] && { printf '%s' "$c"; return; }
  done
}
resolve_gitea_conf() {
  [ -n "$GITEA_CONF" ] && { printf '%s' "$GITEA_CONF"; return; }
  for c in /etc/gitea/app.ini /var/lib/gitea/custom/conf/app.ini \
           /etc/forgejo/app.ini /var/lib/forgejo/custom/conf/app.ini; do
    [ -f "$c" ] && { printf '%s' "$c"; return; }
  done
}
gitea_workdir() {
  for d in /var/lib/gitea /var/lib/forgejo; do [ -d "$d" ] && { printf '%s' "$d"; return; }; done
}
do_gitea() {
  local gbin; gbin="$(resolve_gitea)"
  if [ -z "$gbin" ]; then
    record gitea - "" "skipped: gitea binary not found (pass --gitea-bin)"
    err "gitea - skipped: binary not found"; return
  fi
  if [ -z "$GITEA_ADMIN" ]; then
    record gitea - "" "skipped: no admin username given (pass --gitea-admin <user>)"
    err "gitea - skipped: no admin username"; return
  fi
  pw="$(generate)"
  if [ "$DRY_RUN" = "1" ]; then record gitea "$GITEA_ADMIN" "$pw" "dry-run"; good "gitea $GITEA_ADMIN dry-run"; return; fi
  local conf; conf="$(resolve_gitea_conf)"
  local wd; wd="$(gitea_workdir)"
  run_gitea() { # args...
    if [ -n "$GITEA_RUNAS" ] && have sudo; then
      ( [ -n "$wd" ] && cd "$wd"; GITEA_WORK_DIR="$wd" sudo -u "$GITEA_RUNAS" -H "$gbin" "$@" 2>&1 )
    else
      ( [ -n "$wd" ] && cd "$wd"; GITEA_WORK_DIR="$wd" "$gbin" "$@" 2>&1 )
    fi
  }
  local out
  for variant in "new" "old"; do
    if [ "$variant" = "new" ]; then set -- admin user change-password --username "$GITEA_ADMIN" --password "$pw"
    else set -- admin change-password --username "$GITEA_ADMIN" --password "$pw"; fi
    [ -n "$conf" ] && set -- "$@" --config "$conf"
    out="$(run_gitea "$@")"
    if [ $? -eq 0 ]; then record gitea "$GITEA_ADMIN" "$pw" "changed"; good "gitea $GITEA_ADMIN changed"; return; fi
    case "$(printf '%s' "$out" | tr '[:upper:]' '[:lower:]')" in
      *"unknown command"*|*"flag provided but not defined"*|*"command not found"*|*"no help topic"*) : ;;
      *) break;;
    esac
  done
  record gitea "$GITEA_ADMIN" "" "error: $(printf '%s' "$out" | firstline)"
  err "gitea $GITEA_ADMIN error"
}

# ------------------------------------------------------------- dispatch ----
want mysql && do_mysql; want mariadb && do_mysql
want wordpress && do_wordpress; want wp && do_wordpress
want gitea && do_gitea; want forgejo && do_gitea

# ------------------------------------------------------- write cred file ---
if [ "$DRY_RUN" != "1" ]; then
  mkdir -p "$(dirname "$OUT")" 2>/dev/null
  umask 077
  {
    echo "# WRCCDC password rotation record"
    echo "# host=$HOST os=linux time=$(date -Is 2>/dev/null || date)"
    echo "# KEEP THIS FILE SECRET. Record it off-box, then delete."
    echo "scope,username,password,status"
    printf '%b' "$CRED_ROWS"
  } > "$OUT"
  chmod 600 "$OUT" 2>/dev/null
  good "credentials written to $OUT (0600) — record off-box then delete"
fi
printf '\nDone. Review statuses above; services not installed are reported, not errors.\n' >&2

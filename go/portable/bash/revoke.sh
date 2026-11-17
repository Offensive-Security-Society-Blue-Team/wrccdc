#!/usr/bin/env bash
# revoke.sh — Linux intruder eviction (portable fallback for the Go `revoke`).
#
# Three-stage sequence to remove an active red-team foothold:
#   1. Revoke all login sessions except your own (loginctl, or per-tty on
#      OpenRC/Alpine), then pkill stray processes owned by human users.
#   2. Rotate local passwords for human accounts (service/system accounts and
#      your own account are left alone).
#   3. Revoke sessions again, dropping anything re-established during rotation.
#
# Standalone paste-able rewrite of cmd/revoke (Linux behavior). Run as root.
#
#   sudo ./revoke.sh                 # full sequence, preserves your shell
#   sudo ./revoke.sh --no-rotate     # only revoke sessions
#
# Flags: --out --include-self --include-root --length --no-symbols --deny
#        --no-rotate
set -u

# ---------------------------------------------------------------- defaults ---
OUT=""
INCLUDE_SELF=0
INCLUDE_ROOT=1
LENGTH=20
SYMBOLS=1
DENY_EXTRA=""
NO_ROTATE=0
MIN_UID=1000
MAX_UID=60000

while [ $# -gt 0 ]; do
  case "$1" in
    --out)            OUT="$2"; shift 2;;
    --out=*)          OUT="${1#*=}"; shift;;
    --include-self)   INCLUDE_SELF=1; shift;;
    --include-root)   INCLUDE_ROOT=1; shift;;
    --include-root=false|--no-include-root) INCLUDE_ROOT=0; shift;;
    --length)         LENGTH="$2"; shift 2;;
    --length=*)       LENGTH="${1#*=}"; shift;;
    --no-symbols)     SYMBOLS=0; shift;;
    --deny)           DENY_EXTRA="$2"; shift 2;;
    --deny=*)         DENY_EXTRA="${1#*=}"; shift;;
    --no-rotate)      NO_ROTATE=1; shift;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown flag: $1" >&2; exit 2;;
  esac
done

ts() { date +%H:%M:%S; }
info()  { printf '[%s] [*] %s\n' "$(ts)" "$*" >&2; }
good()  { printf '[%s] [+] %s\n' "$(ts)" "$*" >&2; }
warn()  { printf '[%s] [!] %s\n' "$(ts)" "$*" >&2; }
err()   { printf '[%s] [-] %s\n' "$(ts)" "$*" >&2; }

HOST="$(hostname 2>/dev/null || echo unknown)"
SELF="$(id -un 2>/dev/null || echo "")"

if [ "$(id -u)" != "0" ]; then err "must run as root/Administrator"; exit 1; fi

if [ -z "$OUT" ]; then
  if [ "$(id -u)" = "0" ]; then SECRETDIR="/root/wrccdc"
  elif [ -n "${HOME:-}" ]; then SECRETDIR="$HOME/wrccdc"
  else SECRETDIR="${TMPDIR:-/tmp}/wrccdc"; fi
  OUT="$SECRETDIR/${HOST}-revoke_passwords.txt"
fi

DENY_LIST="root daemon bin sys sync games man lp mail news uucp proxy backup \
list irc gnats nobody systemd-network systemd-resolve systemd-timesync \
messagebus syslog _apt tss uuidd tcpdump landscape pollinate sshd \
systemd-coredump lxd dnsmasq ntp chrony mysql postgres redis mongodb mongod \
nginx www-data apache httpd named bind git gitea forgejo nobody4 ftp vmail \
dovecot dovenull postfix clamav amavis haproxy memcache rabbitmq elasticsearch \
grafana prometheus docker containerd nixbld snapd krbtgt guest defaultaccount \
wdagutilityaccount sshd_server healthmailbox"
NOLOGIN_SHELLS="/usr/sbin/nologin /sbin/nologin /usr/bin/nologin /bin/false /usr/bin/false"

is_service_account() {
  local ln; ln="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  local d
  for d in $DENY_LIST; do [ "$ln" = "$d" ] && return 0; done
  if [ -n "$DENY_EXTRA" ]; then
    local IFS=','; for d in $DENY_EXTRA; do
      d="$(printf '%s' "$d" | tr '[:upper:]' '[:lower:]' | sed 's/^ *//;s/ *$//')"
      [ -n "$d" ] && [ "$ln" = "$d" ] && return 0
    done
  fi
  case "$ln" in nixbld*|svc-*|svc_*|_*) return 0;; esac
  return 1
}
is_login_shell() {
  local s="$1" n; [ -z "$s" ] && return 1
  for n in $NOLOGIN_SHELLS; do [ "$s" = "$n" ] && return 1; done
  return 0
}

# --------------------------------------------------- password generation ---
LOWER='abcdefghijkmnopqrstuvwxyz'; UPPER='ABCDEFGHJKLMNPQRSTUVWXYZ'
DIGITS='23456789'; SYMS='!@#$%^*()-_=+[]{}'
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
  local len="$1" use_sym="$2"; [ "$len" -lt 8 ] && len=8
  local pool="$LOWER$UPPER$DIGITS"; local -a req=("$LOWER" "$UPPER" "$DIGITS")
  if [ "$use_sym" = "1" ]; then pool="$pool$SYMS"; req+=("$SYMS"); fi
  local -a out=(); local c
  for c in "${req[@]}"; do out+=("$(pick "$c")"); done
  while [ "${#out[@]}" -lt "$len" ]; do out+=("$(pick "$pool")"); done
  local i j tmp
  for (( i=${#out[@]}-1; i>0; i-- )); do
    j=$(rand_int $(( i+1 ))); tmp="${out[i]}"; out[i]="${out[j]}"; out[j]="$tmp"
  done
  printf '%s' "$(IFS=; echo "${out[*]}")"
}

# ------------------------------------------------- stage 1/3: revoke ---------
# currentSessionID: prefer XDG_SESSION_ID, else derive from our cgroup.
my_session_id() {
  if [ -n "${XDG_SESSION_ID:-}" ]; then printf '%s' "$XDG_SESSION_ID"; return; fi
  if [ -r /proc/self/cgroup ]; then
    sed -n 's/.*session-\([A-Za-z0-9]\+\)\.scope.*/\1/p' /proc/self/cgroup | head -n1
  fi
}

revoke_sessions() {
  local stage="$1"
  info "stage $stage: revoking sessions"
  local mysess; mysess="$(my_session_id)"

  if command -v loginctl >/dev/null 2>&1; then
    # Terminate individual login sessions precisely.
    loginctl list-sessions --no-legend 2>/dev/null | while read -r sess _ uname _; do
      [ -z "$sess" ] && continue
      if [ "$sess" = "$mysess" ]; then good "kept own login session $sess ($uname)"; continue; fi
      if [ "$INCLUDE_SELF" != "1" ] && [ "$uname" = "$SELF" ] && [ -z "$mysess" ]; then
        good "kept session $sess for current user $uname (own id unknown)"; continue; fi
      if is_service_account "$uname"; then continue; fi
      if loginctl terminate-session "$sess" 2>/dev/null; then
        good "terminated login session $sess ($uname)"
      else warn "terminate-session $sess failed"; fi
    done
  else
    # OpenRC / non-systemd fallback: kill per-tty from `who`.
    local mytty=""; mytty="$(tty 2>/dev/null | sed 's#^/dev/##')"
    [ "$mytty" = "not a tty" ] && mytty=""
    who 2>/dev/null | while read -r uname tty _; do
      [ -z "$tty" ] && continue
      if [ "$tty" = "$mytty" ]; then good "kept own tty $tty ($uname)"; continue; fi
      if [ "$INCLUDE_SELF" != "1" ] && [ "$uname" = "$SELF" ] && [ -z "$mytty" ]; then
        good "kept $tty session for current user (own tty unknown)"; continue; fi
      if is_service_account "$uname"; then continue; fi
      pkill -KILL -t "$tty" 2>/dev/null
      good "terminated tty $tty ($uname)"
    done
  fi

  # Backstop: kill stray processes owned by human users.
  awk -F: -v min="$MIN_UID" '($3>=min)&&($3<=60000){print $1":"$3}' /etc/passwd 2>/dev/null \
  | sort -u | while IFS=: read -r uname uid; do
      [ -z "$uname" ] && continue
      if [ "$INCLUDE_SELF" != "1" ] && [ "$uname" = "$SELF" ]; then
        good "kept current user \"$uname\" processes"; continue; fi
      if is_service_account "$uname"; then continue; fi
      pkill -KILL -u "$uname" 2>/dev/null
      rc=$?
      if [ "$rc" = "0" ]; then good "killed processes for user \"$uname\""
      elif [ "$rc" = "1" ]; then good "no live processes for user \"$uname\""
      else warn "pkill -u $uname failed"; fi
    done
}

# ------------------------------------------------- stage 2: rotate ----------
rotate_passwords() {
  info "stage 2: rotating passwords (local)"
  local changed=0 errors=0 cred_rows="" skip_rows=""
  while IFS=: read -r name _ uid _ _ home shell; do
    [ -z "$name" ] && continue
    case "$name" in \#*) continue;; esac
    [ -z "$uid" ] && continue
    reason=""
    if [ "$uid" = "0" ]; then
      if [ "$INCLUDE_ROOT" = "1" ] && { [ "$INCLUDE_SELF" = "1" ] || [ "$name" != "$SELF" ]; }; then
        reason=""
      elif [ "$name" = "$SELF" ] && [ "$INCLUDE_SELF" != "1" ]; then reason="current user"
      else reason="root (use --include-root)"; fi
    elif [ "$INCLUDE_SELF" != "1" ] && [ "$name" = "$SELF" ]; then reason="current user"
    elif is_service_account "$name"; then reason="service/system account"
    elif ! is_login_shell "$shell"; then reason="non-login shell ($shell)"
    elif [ "$uid" -lt "$MIN_UID" ] || [ "$uid" -gt "$MAX_UID" ]; then
      reason="uid $uid outside human range $MIN_UID-$MAX_UID"
    fi
    if [ -n "$reason" ]; then skip_rows="$skip_rows$name ($reason)\n"; continue; fi
    pw="$(generate "$LENGTH" "$SYMBOLS")"
    if printf '%s:%s\n' "$name" "$pw" | chpasswd 2>/tmp/.rv_err; then
      good "local $name changed"
      cred_rows="${cred_rows}local,${name},${pw},changed\n"; changed=$((changed+1))
    else
      msg="$(head -n1 /tmp/.rv_err 2>/dev/null)"
      err "local $name error: chpasswd: $msg"
      cred_rows="${cred_rows}local,${name},,error: chpasswd: ${msg}\n"; errors=$((errors+1))
    fi
  done < /etc/passwd
  rm -f /tmp/.rv_err 2>/dev/null

  mkdir -p "$(dirname "$OUT")" 2>/dev/null
  umask 077
  {
    echo "# WRCCDC password rotation record"
    echo "# host=$HOST os=linux time=$(date -Is 2>/dev/null || date)"
    echo "# KEEP THIS FILE SECRET. Record it off-box, then delete."
    echo "scope,username,password,status"
    printf '%b' "$cred_rows" | sort -t, -k1,1 -k2,2
    if [ -n "$skip_rows" ]; then
      echo ""; echo "# skipped (left intentionally alone):"
      printf '%b' "$skip_rows" | sed '/^$/d;s/^/# - /'
    fi
  } > "$OUT"
  chmod 600 "$OUT" 2>/dev/null
  good "credentials written to $OUT (0600)"
}

# ------------------------------------------------------------- main run -----
info "host=$HOST os=linux — stage 1: revoking sessions"
revoke_sessions 1

if [ "$NO_ROTATE" != "1" ]; then
  rotate_passwords
else
  info "stage 2 skipped (--no-rotate)"
fi

revoke_sessions 3
printf '\nDone. Verify no unexpected sessions remain and that the credential record is stored off-box.\n' >&2

#!/usr/bin/env bash
# rotatepw.sh — Linux password rotation (portable fallback for the Go `rotatepw`).
#
# Rotates passwords for every human/local account while deliberately leaving
# service and system accounts untouched, and records the new credentials to a
# 0600 file. This is a standalone paste-able rewrite of cmd/rotatepw (Linux
# behavior) for when the Go binary cannot be delivered to the host.
#
# Run as root. Use --dry-run to preview without elevation.
#
#   sudo ./rotatepw.sh                      # rotate humans + root
#   sudo ./rotatepw.sh --dry-run            # preview only
#   sudo ./rotatepw.sh --deny appsvc,bak --no-symbols
#
# Flags mirror the Go tool: --out --length --no-symbols --include-root
# --include-self --min-uid --max-uid --deny --dry-run.
set -u

# ---------------------------------------------------------------- defaults ---
OUT=""
LENGTH=20
SYMBOLS=1
INCLUDE_ROOT=1
INCLUDE_SELF=0
MIN_UID=1000
MAX_UID=60000
DENY_EXTRA=""
DRY_RUN=0

# -------------------------------------------------------------- arg parse ---
while [ $# -gt 0 ]; do
  case "$1" in
    --out)            OUT="$2"; shift 2;;
    --out=*)          OUT="${1#*=}"; shift;;
    --length)         LENGTH="$2"; shift 2;;
    --length=*)       LENGTH="${1#*=}"; shift;;
    --no-symbols)     SYMBOLS=0; shift;;
    --include-root)   INCLUDE_ROOT=1; shift;;
    --include-root=false) INCLUDE_ROOT=0; shift;;
    --no-include-root)    INCLUDE_ROOT=0; shift;;
    --include-self)   INCLUDE_SELF=1; shift;;
    --min-uid)        MIN_UID="$2"; shift 2;;
    --min-uid=*)      MIN_UID="${1#*=}"; shift;;
    --max-uid)        MAX_UID="$2"; shift 2;;
    --max-uid=*)      MAX_UID="${1#*=}"; shift;;
    --deny)           DENY_EXTRA="$2"; shift 2;;
    --deny=*)         DENY_EXTRA="${1#*=}"; shift;;
    --dry-run)        DRY_RUN=1; shift;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown flag: $1" >&2; exit 2;;
  esac
done

# ------------------------------------------------------------------ logging ---
ts() { date +%H:%M:%S; }
info()  { printf '[%s] [*] %s\n' "$(ts)" "$*" >&2; }
good()  { printf '[%s] [+] %s\n' "$(ts)" "$*" >&2; }
warn()  { printf '[%s] [!] %s\n' "$(ts)" "$*" >&2; }
err()   { printf '[%s] [-] %s\n' "$(ts)" "$*" >&2; }

HOST="$(hostname 2>/dev/null || echo unknown)"
SELF="$(id -un 2>/dev/null || echo "")"

# Default output path: /root/wrccdc when root, else ~/wrccdc, else /tmp/wrccdc.
if [ -z "$OUT" ]; then
  if [ "$(id -u)" = "0" ]; then SECRETDIR="/root/wrccdc"
  elif [ -n "${HOME:-}" ]; then SECRETDIR="$HOME/wrccdc"
  else SECRETDIR="${TMPDIR:-/tmp}/wrccdc"; fi
  OUT="$SECRETDIR/${HOST}-new_passwords.txt"
fi

# ------------------------------------------------- service/system deny list ---
# Baseline accounts that are never rotated even if they carry a login shell.
# Mirrors serviceAccountDeny in internal/common/rotate.go. krbtgt included so a
# careless run never touches the Kerberos service account.
DENY_LIST="root daemon bin sys sync games man lp mail news uucp proxy backup \
list irc gnats nobody systemd-network systemd-resolve systemd-timesync \
messagebus syslog _apt tss uuidd tcpdump landscape pollinate sshd \
systemd-coredump lxd dnsmasq ntp chrony mysql postgres redis mongodb mongod \
nginx www-data apache httpd named bind git gitea forgejo nobody4 ftp vmail \
dovecot dovenull postfix clamav amavis haproxy memcache rabbitmq elasticsearch \
grafana prometheus docker containerd nixbld snapd krbtgt guest defaultaccount \
wdagutilityaccount sshd_server healthmailbox"

# Non-login shells mark an account as non-interactive; never rotated.
NOLOGIN_SHELLS="/usr/sbin/nologin /sbin/nologin /usr/bin/nologin /bin/false /usr/bin/false"

is_service_account() { # name -> 0 if service/system (skip)
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

is_login_shell() { # shell -> 0 if interactive login allowed
  local s="$1" n
  [ -z "$s" ] && return 1
  for n in $NOLOGIN_SHELLS; do [ "$s" = "$n" ] && return 1; done
  return 0
}

# --------------------------------------------------- password generation ---
LOWER='abcdefghijkmnopqrstuvwxyz'   # no l
UPPER='ABCDEFGHJKLMNPQRSTUVWXYZ'    # no I, O
DIGITS='23456789'                   # no 0, 1
SYMS='!@#$%^*()-_=+[]{}'

rand_int() { # max -> random 0..max-1 via /dev/urandom, rejection-sampled
  local max="$1" b limit
  limit=$(( 256 - (256 % max) ))
  while :; do
    b=$(od -An -N1 -tu1 /dev/urandom 2>/dev/null | tr -d ' ')
    [ -z "$b" ] && b=$(( RANDOM % 256 ))
    if [ "$b" -lt "$limit" ]; then printf '%s' $(( b % max )); return; fi
  done
}

pick() { # set -> one random char
  local set="$1" i
  i=$(rand_int ${#set})
  printf '%s' "${set:i:1}"
}

generate() { # length symbols(0/1) -> password
  local len="$1" use_sym="$2"
  [ "$len" -lt 8 ] && len=8
  local pool="$LOWER$UPPER$DIGITS"
  local -a req=("$LOWER" "$UPPER" "$DIGITS")
  if [ "$use_sym" = "1" ]; then pool="$pool$SYMS"; req+=("$SYMS"); fi
  local -a out=()
  local c
  for c in "${req[@]}"; do out+=("$(pick "$c")"); done
  while [ "${#out[@]}" -lt "$len" ]; do out+=("$(pick "$pool")"); done
  # Fisher-Yates shuffle
  local i j tmp
  for (( i=${#out[@]}-1; i>0; i-- )); do
    j=$(rand_int $(( i+1 )))
    tmp="${out[i]}"; out[i]="${out[j]}"; out[j]="$tmp"
  done
  printf '%s' "$(IFS=; echo "${out[*]}")"
}

# -------------------------------------------------------------- main run ---
info "host=$HOST os=linux (dry-run=$DRY_RUN)"

if [ "$(id -u)" != "0" ] && [ "$DRY_RUN" != "1" ]; then
  err "must run as root to change passwords (use --dry-run to preview)"
  exit 1
fi

CHANGED=0; SKIPPED=0; ERRORS=0
CRED_ROWS=""     # scope,user,password,status
SKIP_ROWS=""     # name (reason)

add_skip() { SKIP_ROWS="$SKIP_ROWS$1\n"; SKIPPED=$((SKIPPED+1)); info "skip: $1"; }

# Iterate /etc/passwd.
while IFS=: read -r name _ uid _ _ home shell; do
  [ -z "$name" ] && continue
  case "$name" in \#*) continue;; esac
  [ -z "$uid" ] && continue

  reason=""
  if [ "$uid" = "0" ]; then
    if [ "$INCLUDE_ROOT" = "1" ] && { [ "$INCLUDE_SELF" = "1" ] || [ "$name" != "$SELF" ]; }; then
      reason=""
    elif [ "$name" = "$SELF" ] && [ "$INCLUDE_SELF" != "1" ]; then
      reason="current user (use --include-self to override)"
    else
      reason="root (use --include-root to rotate)"
    fi
  elif [ "$INCLUDE_SELF" != "1" ] && [ "$name" = "$SELF" ]; then
    reason="current user (use --include-self to override)"
  elif is_service_account "$name"; then
    reason="service/system account"
  elif ! is_login_shell "$shell"; then
    reason="non-login shell ($shell)"
  elif [ "$uid" -lt "$MIN_UID" ] || [ "$uid" -gt "$MAX_UID" ]; then
    reason="uid $uid outside human range $MIN_UID-$MAX_UID"
  fi

  if [ -n "$reason" ]; then add_skip "$name ($reason)"; continue; fi

  pw="$(generate "$LENGTH" "$SYMBOLS")"
  if [ "$DRY_RUN" = "1" ]; then
    info "local $name would change"
    CRED_ROWS="${CRED_ROWS}local,${name},${pw},dry-run\n"
    CHANGED=$((CHANGED+1))
    continue
  fi
  # Feed user:password on stdin so the secret never appears in argv.
  if printf '%s:%s\n' "$name" "$pw" | chpasswd 2>/tmp/.rp_err; then
    good "local $name changed"
    CRED_ROWS="${CRED_ROWS}local,${name},${pw},changed\n"
    CHANGED=$((CHANGED+1))
  else
    msg="$(head -n1 /tmp/.rp_err 2>/dev/null)"
    err "local $name error: chpasswd: $msg"
    CRED_ROWS="${CRED_ROWS}local,${name},,error: chpasswd: ${msg}\n"
    ERRORS=$((ERRORS+1))
  fi
done < /etc/passwd
rm -f /tmp/.rp_err 2>/dev/null

# ------------------------------------------------------- write cred file ---
if [ "$DRY_RUN" != "1" ]; then
  mkdir -p "$(dirname "$OUT")" 2>/dev/null
  umask 077
  {
    echo "# WRCCDC password rotation record"
    echo "# host=$HOST os=linux time=$(date -Is 2>/dev/null || date)"
    echo "# KEEP THIS FILE SECRET. Record it off-box, then delete."
    echo "scope,username,password,status"
    printf '%b' "$CRED_ROWS" | sort -t, -k1,1 -k2,2
    if [ -n "$SKIP_ROWS" ]; then
      echo ""
      echo "# skipped (left intentionally alone):"
      printf '%b' "$SKIP_ROWS" | sed '/^$/d;s/^/# - /'
    fi
  } > "$OUT"
  chmod 600 "$OUT" 2>/dev/null
  good "credentials written to $OUT (0600) — record off-box then delete"
fi

printf '\nSummary: %d accounts changed, %d skipped, %d errors\n' "$CHANGED" "$SKIPPED" "$ERRORS" >&2
[ "$ERRORS" -gt 0 ] && exit 1 || exit 0

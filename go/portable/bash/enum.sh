#!/usr/bin/env bash
# enum.sh — Linux host enumeration (portable fallback for the Go `enum`).
#
# Collects services, listening ports and owning processes, connections,
# processes, logins, cron, interfaces/routes, mounts/disk, installed packages,
# SSH/sudoers config and world-writable files into one report. Standalone
# paste-able rewrite of cmd/enum (Linux behavior).
#
#   sudo ./enum.sh -out /root/enum.txt
#
# Flag: -out / --out  (default: $TMPDIR/<host>-enum.txt)
set -u

HOST="$(hostname 2>/dev/null || echo unknown)"
OUT="${TMPDIR:-/tmp}/${HOST}-enum.txt"

while [ $# -gt 0 ]; do
  case "$1" in
    -out|--out) OUT="$2"; shift 2;;
    -out=*|--out=*) OUT="${1#*=}"; shift;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown flag: $1" >&2; exit 2;;
  esac
done

ts() { date +%H:%M:%S; }
info() { printf '[%s] [*] %s\n' "$(ts)" "$*" >&2; }
good() { printf '[%s] [+] %s\n' "$(ts)" "$*" >&2; }
warn() { printf '[%s] [!] %s\n' "$(ts)" "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

# Distro / package manager detection (mirrors osdetect.go).
DISTRO="linux"; VERSION=""
if [ -r /etc/os-release ]; then
  DISTRO="$(. /etc/os-release 2>/dev/null; printf '%s' "${ID:-linux}" | tr '[:upper:]' '[:lower:]')"
  VERSION="$(. /etc/os-release 2>/dev/null; printf '%s' "${VERSION_ID:-}")"
elif [ -f /etc/alpine-release ]; then DISTRO="alpine"
elif [ -f /etc/debian_version ]; then DISTRO="debian"
elif [ -f /etc/redhat-release ]; then DISTRO="rhel"
elif [ -d /etc/nixos ]; then DISTRO="nixos"
fi

info "host=$HOST os=linux distro=$DISTRO version=$VERSION"
[ "$(id -u)" != "0" ] && warn "not running as root: some sections will be incomplete"

TMP="$(mktemp 2>/dev/null || echo "${TMPDIR:-/tmp}/enum.$$")"
: > "$TMP"

sec() { # title ; body comes from stdin
  printf '==================================================\n' >> "$TMP"
  printf '%s\n' "$1" >> "$TMP"
  printf -- '--------------------------------------------------\n' >> "$TMP"
  cat >> "$TMP"
  printf '\n\n' >> "$TMP"
}

run_sec() { # title prog args... — run prog if present
  local title="$1" prog="$2"; shift 2
  if ! have "$prog"; then printf '(%s not installed)' "$prog" | sec "$title"; return; fi
  local body; body="$("$prog" "$@" 2>&1)"
  [ -z "$body" ] && body="(no output)"
  printf '%s' "$body" | sec "$title"
}

file_sec() { # title path
  if [ -r "$2" ]; then cat "$2" | sec "$1"; else printf '(%s: not readable)' "$2" | sec "$1"; fi
}

glob_sec() { # title dir
  local title="$1" dir="$2" any=0
  { if [ -d "$dir" ]; then
      for f in "$dir"/*; do
        [ -f "$f" ] || continue
        any=1; printf '### %s\n' "$f"; cat "$f" 2>/dev/null; printf '\n'
      done
      [ "$any" = "0" ] && printf '(empty)'
    else printf '(%s: not present)' "$dir"; fi
  } | sec "$title"
}

# --- Host summary ---
printf 'hostname: %s\nos: linux\ndistro: %s\nversion: %s\ncollected: %s' \
  "$HOST" "$DISTRO" "$VERSION" "$(date -Is 2>/dev/null || date)" | sec "Host"

# --- Kernel ---
run_sec "Kernel" uname -a

# --- Services (systemd -> OpenRC -> SysV) ---
if have systemctl; then
  run_sec "Running services (systemd)" systemctl list-units --type=service --state=running --no-pager --no-legend
elif have rc-status; then
  run_sec "Running services (OpenRC)" rc-status -a
elif have service; then
  run_sec "Services (SysV)" service --status-all
fi

# --- Listening ports + connections ---
if have ss; then
  run_sec "Listening ports (ss)" ss -tulpn
  run_sec "Established connections (ss)" ss -tunp state established
elif have netstat; then
  run_sec "Listening ports (netstat)" netstat -tulnp
  run_sec "Connections (netstat)" netstat -antup
fi

run_sec "All processes" ps aux
run_sec "Logged-in users (w)" w
run_sec "Recent logins (last)" last -n 40
run_sec "Open network files (lsof -i)" lsof -i -n -P
run_sec "Interfaces (ip addr)" ip addr
run_sec "Routes (ip route)" ip route
run_sec "Mounts" mount
run_sec "Disk usage" df -h

# --- Package inventory per distro ---
case "$DISTRO" in
  alpine) run_sec "Installed packages (apk)" apk info -v;;
  debian|ubuntu|kali|raspbian) run_sec "Installed packages (dpkg)" dpkg -l;;
  rhel|centos|fedora|rocky|almalinux) run_sec "Installed packages (rpm)" rpm -qa;;
  nixos) run_sec "Nix store (live paths)" nix-store --gc --print-live;;
  *)
    if have dpkg; then run_sec "Installed packages (dpkg)" dpkg -l
    elif have rpm; then run_sec "Installed packages (rpm)" rpm -qa
    elif have apk; then run_sec "Installed packages (apk)" apk info -v; fi;;
esac

# --- File-based sections ---
file_sec "Crontab (system)" /etc/crontab
glob_sec "Cron jobs (/etc/cron.d)" /etc/cron.d
file_sec "Sudoers" /etc/sudoers
file_sec "Network interfaces (debian)" /etc/network/interfaces
glob_sec "Netplan" /etc/netplan
file_sec "SSH server config" /etc/ssh/sshd_config
file_sec "fstab" /etc/fstab

# --- World-writable files (bounded search) ---
{
  body="$(find /etc /var/www /srv /home -xdev -type f -perm -0002 -ls 2>/dev/null)"
  [ -z "$body" ] && body="(none found in /etc /var/www /srv /home)"
  printf '%s' "$body"
} | sec "World-writable files (common paths)"

umask 077
mv "$TMP" "$OUT" 2>/dev/null || cp "$TMP" "$OUT"
chmod 600 "$OUT" 2>/dev/null
good "enumeration written to $OUT"

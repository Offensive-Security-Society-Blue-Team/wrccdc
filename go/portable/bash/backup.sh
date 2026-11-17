#!/usr/bin/env bash
# backup.sh — Linux pseudo-snapshot & restore (portable fallback for Go `backup`).
#
# Archives the folders red teams wipe or deface (/etc, DNS zones, web roots, ...)
# and the state of running Docker containers, with a sha256-checksummed manifest
# so restoration is verifiable. Standalone paste-able rewrite of cmd/backup
# (Linux behavior).
#
#   sudo ./backup.sh --mirror /mnt/backup2
#   sudo ./backup.sh --no-docker --paths /etc,/var/www,/etc/bind
#   sudo ./backup.sh --restore /root/wrccdc/snapshots/HOST-20261111_120000
#   sudo ./backup.sh --restore <snapdir> --in-place --force
#
# Flags: --out --paths --add --no-docker --mirror --restore --in-place --force
#
# Note: alongside the Go-compatible MANIFEST.json this writes sidecar files.tsv
# and docker.tsv that this script's own restore reads (pure-bash, no JSON parser).
set -u

OUTBASE=""
PATHS=""
ADD=""
NO_DOCKER=0
MIRROR=""
RESTORE=""
IN_PLACE=0
FORCE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --out)      OUTBASE="$2"; shift 2;;
    --out=*)    OUTBASE="${1#*=}"; shift;;
    --paths)    PATHS="$2"; shift 2;;
    --paths=*)  PATHS="${1#*=}"; shift;;
    --add)      ADD="$2"; shift 2;;
    --add=*)    ADD="${1#*=}"; shift;;
    --no-docker) NO_DOCKER=1; shift;;
    --mirror)   MIRROR="$2"; shift 2;;
    --mirror=*) MIRROR="${1#*=}"; shift;;
    --restore)  RESTORE="$2"; shift 2;;
    --restore=*) RESTORE="${1#*=}"; shift;;
    --in-place) IN_PLACE=1; shift;;
    --force)    FORCE=1; shift;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown flag: $1" >&2; exit 2;;
  esac
done

ts() { date +%H:%M:%S; }
info() { printf '[%s] [*] %s\n' "$(ts)" "$*" >&2; }
good() { printf '[%s] [+] %s\n' "$(ts)" "$*" >&2; }
warn() { printf '[%s] [!] %s\n' "$(ts)" "$*" >&2; }
err()  { printf '[%s] [-] %s\n' "$(ts)" "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }
fatal(){ err "$*"; exit 1; }

HOST="$(hostname 2>/dev/null || echo unknown)"
if [ "$(id -u)" = "0" ]; then SECRETDIR="/root/wrccdc"
elif [ -n "${HOME:-}" ]; then SECRETDIR="$HOME/wrccdc"
else SECRETDIR="${TMPDIR:-/tmp}/wrccdc"; fi
[ -z "$OUTBASE" ] && OUTBASE="$SECRETDIR/snapshots"

sha256() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }

# Turn a path into a safe archive basename (mirrors sanitize() in backup).
sanitize() {
  local s; s="$(printf '%s' "$1" | tr '/\\: ' '____' | sed 's/^_*//;s/_*$//')"
  [ -z "$s" ] && s="root"; printf '%s' "$s"
}

# Default Linux paths (mirrors paths_linux.go).
default_paths() {
  cat <<'EOF'
/etc
/etc/bind
/var/named
/var/lib/bind
/etc/nginx
/etc/apache2
/etc/httpd
/var/www
/usr/share/nginx/html
/srv
/etc/ssh
/etc/pki
/etc/ssl
/opt
/root
EOF
}

# ============================================================== RESTORE =====
if [ -n "$RESTORE" ]; then
  snap="$RESTORE"
  [ -f "$snap/files.tsv" ] || fatal "no files.tsv in $snap (was this snapshot made by backup.sh?)"
  if [ "$IN_PLACE" = "1" ] && [ "$FORCE" != "1" ]; then
    fatal "in-place restore overwrites live files; re-run with --in-place --force"
  fi
  info "restoring snapshot from $snap"
  while IFS=$'\t' read -r source archive sha; do
    [ -z "$source" ] && continue
    arc="$snap/$archive"
    [ -f "$arc" ] || { warn "missing archive $archive; skipping"; continue; }
    if [ -n "$sha" ]; then
      cur="$(sha256 "$arc")"
      if [ -n "$cur" ] && [ "$cur" != "$sha" ]; then
        warn "checksum MISMATCH for $archive (archive may be corrupt); skipping"; continue; fi
    fi
    if [ "$IN_PLACE" = "1" ]; then dest="$(dirname "$source")"
    else dest="$snap/restored/$(sanitize "$source")"; mkdir -p "$dest"; fi
    if tar -xzf "$arc" -C "$dest" 2>/dev/null; then good "restored $source -> $dest"
    else warn "restore $source failed"; fi
  done < "$snap/files.tsv"

  if have docker && [ -f "$snap/docker.tsv" ]; then
    while IFS=$'\t' read -r name image_archive; do
      [ -z "$image_archive" ] && continue
      arc="$snap/$image_archive"
      [ -f "$arc" ] || continue
      if docker load -i "$arc" >/dev/null 2>&1; then good "loaded image for container $name"
      else warn "docker load $name failed"; fi
    done < "$snap/docker.tsv"
  fi
  good "restore finished"
  [ "$IN_PLACE" != "1" ] && info "files extracted into $snap/restored for review; re-run with --in-place --force to overwrite live paths"
  exit 0
fi

# ============================================================== SNAPSHOT ====
STAMP="$(date +%Y%m%d_%H%M%S)"
SNAP="$OUTBASE/${HOST}-${STAMP}"
FILESDIR="$SNAP/files"
DOCKERDIR="$SNAP/docker"
mkdir -p "$FILESDIR" || fatal "create snapshot dir"
umask 077

NOTES=""
if [ "$(id -u)" != "0" ]; then
  warn "not elevated: some protected files will be skipped"
  NOTES="not run as root; some protected files were unreadable and skipped"
fi

# Build target list.
if [ -n "$PATHS" ]; then
  TARGETS="$(printf '%s' "$PATHS" | tr ',' '\n')"
else
  TARGETS="$(default_paths)"
fi
[ -n "$ADD" ] && TARGETS="$TARGETS
$(printf '%s' "$ADD" | tr ',' '\n')"

: > "$SNAP/files.tsv"
FILES_JSON=""
info "snapshotting candidate folders into $SNAP"
while IFS= read -r t; do
  t="$(printf '%s' "$t" | sed 's/^ *//;s/ *$//')"
  [ -z "$t" ] && continue
  if [ ! -e "$t" ]; then info "skip $t (not present)"; continue; fi
  arcname="$(sanitize "$t").tar.gz"
  arcpath="$FILESDIR/$arcname"
  # Store paths relative to the parent dir (e.g. tar of /etc -> etc/...), so an
  # in-place restore into dirname(src) lands the folder back in place.
  if tar -C "$(dirname "$t")" -czf "$arcpath" "$(basename "$t")" 2>/dev/null; then
    sha="$(sha256 "$arcpath")"
    good "archived $t"
  else
    sha=""; warn "archive $t had errors (partial archive kept)"
  fi
  printf '%s\t%s\t%s\n' "$t" "files/$arcname" "$sha" >> "$SNAP/files.tsv"
  FILES_JSON="${FILES_JSON}    {\"source\":\"$t\",\"archive\":\"files/$arcname\",\"sha256\":\"$sha\"},\n"
done <<EOF
$TARGETS
EOF

# --- Docker ---
: > "$SNAP/docker.tsv"
DOCKER_JSON=""
if [ "$NO_DOCKER" != "1" ] && have docker; then
  mkdir -p "$DOCKERDIR"
  docker ps --format '{{.ID}}\t{{.Names}}\t{{.Image}}' 2>/dev/null | while IFS=$'\t' read -r id name image; do
    [ -z "$id" ] && continue
    info "backing up container $name ($id)"
    docker inspect "$id" > "$DOCKERDIR/$name.inspect.json" 2>/dev/null
    tag="wrccdc-snap/$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9_.-' '_'):$STAMP"
    if docker commit "$id" "$tag" >/dev/null 2>&1; then
      if docker save "$tag" -o "$DOCKERDIR/$name.image.tar" 2>/dev/null; then
        gzip -f "$DOCKERDIR/$name.image.tar" 2>/dev/null
        imgarc="docker/$name.image.tar.gz"
        printf '%s\t%s\n' "$name" "$imgarc" >> "$SNAP/docker.tsv"
      fi
      docker image rm "$tag" >/dev/null 2>&1
    else
      warn "docker commit $name failed"
    fi
    # Named volumes.
    docker inspect --format '{{range .Mounts}}{{.Type}}|{{.Name}}|{{.Source}}{{"\n"}}{{end}}' "$id" 2>/dev/null \
    | while IFS='|' read -r mtype vname vsource; do
        [ "$mtype" = "volume" ] || continue; [ -z "$vname" ] && continue
        varc="$DOCKERDIR/$name.vol.$(sanitize "$vname").tar.gz"
        if [ -n "$vsource" ] && [ -d "$vsource" ]; then
          tar -C "$vsource" -czf "$varc" . 2>/dev/null && good "archived volume $vname (mountpoint)"
        else
          docker run --rm -v "$vname:/v:ro" -v "$DOCKERDIR:/backup" alpine \
            sh -c "tar czf /backup/$name.vol.$(sanitize "$vname").tar.gz -C /v ." 2>/dev/null \
            && good "archived volume $vname (container-tar)" \
            || warn "could not back up volume $vname"
        fi
      done
  done
elif [ "$NO_DOCKER" != "1" ]; then
  NOTES="${NOTES:+$NOTES; }docker not installed; container backup skipped"
fi

# --- MANIFEST.json (Go-compatible shape; sidecars drive this script's restore) ---
{
  printf '{\n'
  printf '  "host": "%s",\n' "$HOST"
  printf '  "os": "linux",\n'
  printf '  "created": "%s",\n' "$(date -Is 2>/dev/null || date)"
  printf '  "files": [\n'
  printf '%b' "$FILES_JSON" | sed '$ s/,$//'
  printf '  ],\n'
  printf '  "notes": ["%s"]\n' "$NOTES"
  printf '}\n'
} > "$SNAP/MANIFEST.json"
chmod -R go-rwx "$SNAP" 2>/dev/null

good "snapshot complete: $SNAP"

# --- Mirror ---
if [ -n "$MIRROR" ]; then
  dst="$MIRROR/$(basename "$SNAP")"
  info "mirroring snapshot to $dst"
  mkdir -p "$dst"
  if cp -a "$SNAP/." "$dst/" 2>/dev/null; then good "mirror complete: $dst"
  else warn "mirror failed"; fi
fi

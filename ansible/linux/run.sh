#!/usr/bin/env bash
# run.sh - runs ON YOUR LAPTOP. Runs one scripts/*.sh on the boxes and ALWAYS saves the output to
# out/<script>_<hosts>_<YYYYmmdd-HHMMSS>.txt: one block per host, with rc and errors, ready to send to someone.
# The screen shows the same thing, or only the lines matching -g. The file always has everything.
#
# Usage (from ansible/linux):
#   ./run.sh linux verify_clean.sh                    # team keys from files/team_key.pub + ~/.ssh/inv3.pub are added for you
#   ./run.sh linux hunt.sh -g '=====|\[!\]'           # screen: only flags; file: everything
#   ./run.sh haf,djupi lockdown_ssh.sh
#   ./run.sh linux revoke_certs.sh forged-root-cert <new-id>
#   ./run.sh linux harden.sh --rotate '' --check      # PW| lines go to loot/passwords/, never into out/ or logs/
#   ./run.sh -h
# Options (before the hosts): -g REGEX   only show matching lines on screen
#                             -o FILE    save to FILE instead of out/<auto name>.txt
set -uo pipefail
cd "$(dirname "$0")" || exit 1

usage() {
    [ -n "${1:-}" ] && echo "error: $1" >&2
    cat >&2 <<'USAGE'
usage: ./run.sh [-g REGEX] [-o FILE] <hosts> <script.sh> [script args...]     (from ansible/linux)
  ./run.sh linux verify_clean.sh
  ./run.sh linux hunt.sh -g '=====|\[!\]'
  ./run.sh haf,djupi lockdown_ssh.sh
  ./run.sh linux harden.sh --rotate '' --check
  <hosts> = a host, a group, or a list: haf | linux | haf,djupi | 'linux:!gufu'
  Scripts: ls scripts/      Help for one script: sh scripts/<name>.sh -h
USAGE
    [ -n "${1:-}" ] && exit 1
    exit 0
}

GREP=""; OUT=""
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage ;;
        -g) [ $# -ge 2 ] || usage "-g needs a pattern"; GREP=$2; shift 2 ;;
        -o) [ $# -ge 2 ] || usage "-o needs a file name"; OUT=$2; shift 2 ;;
        -*) usage "unknown option: $1 (run.sh options go BEFORE the hosts)" ;;
        *) break ;;
    esac
done
[ $# -ge 2 ] || usage "need <hosts> and <script.sh>"
HOSTS=$1; SCRIPT=${2#scripts/}; shift 2
case "$SCRIPT" in *.sh) ;; *) SCRIPT="$SCRIPT.sh" ;; esac
[ -f "scripts/$SCRIPT" ] || usage "no scripts/$SCRIPT (have: $(cd scripts && ls *.sh | tr '\n' ' '))"
[ "$SCRIPT" != keys_apply.sh ] || usage "keys_apply.sh is run by keys_pick.sh: use ./keys_pick.sh -l $HOSTS --check"
command -v ansible >/dev/null || usage "ansible not found (pip install ansible)"

ARGS=("$@")
# verify_clean.sh with no keys: fill in the team keys so UNKNOWN-KEYS works
if [ "$SCRIPT" = verify_clean.sh ] && [ $# -eq 0 ]; then
    mapfile -t ARGS < <(cat files/team_key.pub ~/.ssh/inv3.pub 2>/dev/null | awk '$2 ~ /^AAAA/ {print $2}' | sort -u)
    [ ${#ARGS[@]} -gt 0 ] || echo "note: no team keys found in files/team_key.pub or ~/.ssh/inv3.pub; checking known red keys only" >&2
fi

TS=$(date +%Y%m%d-%H%M%S)
SAFEHOSTS=$(printf '%s' "$HOSTS" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-40)
mkdir -p out && chmod 700 out
OUT=${OUT:-out/${SCRIPT%.sh}_${SAFEHOSTS}_$TS.txt}
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# quote each argument so spaces and '' survive the trip to the box
CMD="scripts/$SCRIPT"; for a in ${ARGS[@]+"${ARGS[@]}"}; do CMD="$CMD $(printf '%q' "$a")"; done

# scripts that print new passwords (PW| lines, e.g. harden.sh): keep them out of logs/ansible.log
LOGP=""; grep -q '"PW|' "scripts/$SCRIPT" && LOGP=/dev/null
echo "running $CMD on $HOSTS ..." >&2
ANSIBLE_LOG_PATH=${LOGP:-${ANSIBLE_LOG_PATH:-./logs/ansible.log}} \
    ansible "$HOSTS" -m script -a "$CMD" --tree "$TMP/tree" > "$TMP/raw.txt" 2>&1
ARC=$?

PWFILE=loot/passwords/${SCRIPT%.sh}_$TS.csv
python3 - "$TMP" "$OUT" "$PWFILE" "$HOSTS" "$CMD" "$ARC" <<'PY'
import json, os, sys
tmp, out, pwfile, hosts, cmd, arc = sys.argv[1:]
tree = os.path.join(tmp, "tree")
lines = [f"# {cmd}", f"# hosts: {hosts}   ran: {os.popen('date').read().strip()}   ansible rc={arc}", ""]
pw = []
names = sorted(os.listdir(tree)) if os.path.isdir(tree) else []
for h in names:
    try:
        r = json.load(open(os.path.join(tree, h)))
    except Exception as e:
        lines += [f"##### {h}  (could not read result: {e})", ""]; continue
    if r.get("unreachable"):
        state = "UNREACHABLE"
    elif r.get("failed") or r.get("rc", 0) != 0:
        state = "FAILED"
    else:
        state = "ok"
    lines.append(f"##### {h}  rc={r.get('rc', '-')}  {state}")
    for l in (r.get("stdout") or "").replace("\r", "").splitlines():
        if l.startswith("PW|"):
            pw.append(l); f = l.split("|")
            lines.append(f"PW|{f[1] if len(f) > 1 else h}|{f[2] if len(f) > 2 else '?'}|<saved to {pwfile}>")
        else:
            lines.append(l)
    err = (r.get("stderr") or "").replace("\r", "").strip()
    # ansible adds "Shared connection to X closed." to stderr on every run; drop that noise
    err = "\n".join(l for l in err.splitlines() if not l.startswith("Shared connection to"))
    if err: lines += ["--- stderr:", err]
    if state != "ok" and r.get("msg") and not r.get("stdout"): lines += ["--- ansible: " + str(r["msg"])[:400]]
    lines.append("")
if not names:
    lines += ["(no host results: ansible said)", open(os.path.join(tmp, "raw.txt")).read()]
fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f: f.write("\n".join(lines).rstrip() + "\n")
if pw:
    os.makedirs(os.path.dirname(pwfile), exist_ok=True)
    fd = os.open(pwfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("host,user,password\n")
        for l in pw:
            p = l.split("|", 3)
            if len(p) == 4: f.write(f"{p[1]},{p[2]},{p[3]}\n")
PY

if [ -n "$GREP" ]; then grep -E -- "$GREP|^##### " "$OUT"; else cat "$OUT"; fi
echo >&2
echo "saved: $OUT" >&2
[ -f "$PWFILE" ] && echo "NEW PASSWORDS: $PWFILE  (copy into the tracker; never send this file)" >&2
exit 0

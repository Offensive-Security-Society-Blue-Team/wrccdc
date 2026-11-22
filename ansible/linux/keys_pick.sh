#!/usr/bin/env bash
# keys_pick.sh - runs ON YOUR LAPTOP (WSL). Lists every SSH key on every box in one table, lets you pick
# which to KEEP, then removes all others everywhere (backed up on each box). Optional: root keys-only.
#
#   ./keys_pick.sh -l linux --check        show the table and what WOULD be removed; change nothing
#   ./keys_pick.sh -l linux                pick, confirm, apply
#   ./keys_pick.sh -l linux -y             no questions: keep TEAM keys + CA lines only (scriptable)
#   ./keys_pick.sh -l linux -r             also set PermitRootLogin prohibit-password after the keys
# Team keys are read from ~/.ssh/inv3.pub and files/team_key.pub (add more with -K file.pub).
set -euo pipefail
cd "$(dirname "$0")"
LIMIT=""; CHECK=""; YES=0; ROOTKEYS=""; TEAMFILES=()
for k in ~/.ssh/inv3.pub files/team_key.pub; do [ -f "$k" ] && TEAMFILES+=("$k"); done
while [ $# -gt 0 ]; do
    case "$1" in
        -l) LIMIT=$2; shift ;;
        --check) CHECK="--check" ;;
        -y) YES=1 ;;
        -r) ROOTKEYS="--root-keys-only" ;;
        -K) TEAMFILES+=("$2"); shift ;;
        *) echo "unknown option: $1"; exit 1 ;;
    esac
    shift
done
[ -n "$LIMIT" ] || { echo "need -l <host or group>"; exit 1; }
[ -f scripts/keys_apply.sh ] || { echo "scripts/keys_apply.sh not found (run from ~/wrccdc/ansible/linux)"; exit 1; }
# everything printed below (table, your answers' results, per-box output) is also saved to out/, mode 0600
mkdir -p out && chmod 700 out; umask 077
SAVED="out/keys_pick_$(printf '%s' "$LIMIT" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-40)_$(date +%Y%m%d-%H%M%S)${CHECK:+_check}.txt"
exec > >(tee "$SAVED") 2>&1
echo "# ./keys_pick.sh -l $LIMIT ${CHECK} $([ "$YES" = 1 ] && echo -y) ${ROOTKEYS}   ran: $(date)"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"; echo; echo "saved: $SAVED"' EXIT
cat "${TEAMFILES[@]}" 2>/dev/null | awk '$2 ~ /^AAAA/ {print $2}' | sort -u > "$TMP/team.txt" || true

echo "Collecting keys from $LIMIT ..."
ANSIBLE_LOG_PATH=/dev/null ansible "$LIMIT" -m script -a "scripts/keys_apply.sh --list" --tree "$TMP/list" > "$TMP/raw.txt" 2>&1 || true

# build the table; writes $TMP/table.json for the apply step
python3 - "$TMP" <<'PY'
import json, os, subprocess, sys
tmp = sys.argv[1]; tree = os.path.join(tmp, "list")
team = set(open(os.path.join(tmp, "team.txt")).read().split())
keys, sshd, bad = {}, {}, []
for host in sorted(os.listdir(tree)) if os.path.isdir(tree) else []:
    r = json.load(open(os.path.join(tree, host)))
    if r.get("unreachable") or not r.get("stdout"):
        bad.append(f"{host}: {r.get('msg', 'no output')[:120]}"); continue
    for line in r["stdout"].replace("\r", "").splitlines():
        f = line.split("|")
        if f[0] == "S": sshd[host] = f[3] or "?"
        if f[0] != "K" or len(f) < 9 or f[6] == "?": continue
        _, h, user, path, kind, ktype, blob, comment, opts = f[:9]
        k = keys.setdefault(blob, {"type": ktype, "kind": kind, "comment": comment, "opts": opts, "where": []})
        k["where"].append(f"{host}:{user}")
def fp(t, b):
    try:
        o = subprocess.run(["ssh-keygen", "-lf", "-"], input=f"{t} {b}\n", capture_output=True, text=True, timeout=5).stdout.split()
        return o[1] if len(o) > 1 else "?"
    except Exception:
        return "?"
rows = sorted(keys.items(), key=lambda kv: (kv[0] not in team, kv[1]["kind"] != "ca", kv[1]["comment"]))
table = []
print(f"\n{'#':>3}  {'tag':6} {'type':12} {'fingerprint':22} {'comment':24} where")
for i, (blob, k) in enumerate(rows, 1):
    tag = "TEAM" if blob in team else ("CA" if k["kind"] == "ca" else "")
    note = f"  opts: {k['opts'][:50]}" if k["opts"] and k["kind"] != "ca" else ""
    where = ", ".join(sorted(set(k["where"])))
    print(f"{i:>3}  {tag:6} {k['type'][:12]:12} {fp(k['type'], blob)[:22]:22} {k['comment'][:24]:24} {where}{note}")
    table.append({"n": i, "blob": blob, "tag": tag, "comment": k["comment"], "where": where})
print("\nroot password login (PermitRootLogin): " + ", ".join(f"{h}={v}" for h, v in sorted(sshd.items())))
for b in bad: print("UNREACHABLE " + b)
json.dump(table, open(os.path.join(tmp, "table.json"), "w"))
PY

DEFAULT=$(python3 -c "import json,sys; print(' '.join(str(r['n']) for r in json.load(open('$TMP/table.json')) if r['tag'] in ('TEAM','CA')))")
[ -n "$(python3 -c "import json; print(json.load(open('$TMP/table.json')) or '')")" ] || { echo "no keys found"; exit 1; }
echo
echo "Default keep = TEAM keys + CA lines: [${DEFAULT:-none}]"
echo "CA lines are usually scoring or black team. Drop one only if you know it's the attack path."
if [ "$YES" = 1 ]; then PICK=$DEFAULT
else
    read -rp "Numbers to KEEP (space separated, Enter = default, q = quit): " PICK
    [ "$PICK" = q ] && exit 0
    PICK=${PICK:-$DEFAULT}
fi
python3 - "$TMP" "$PICK" <<'PY'
import base64, json, sys
tmp, pick = sys.argv[1], sys.argv[2].replace(",", " ").split()
table = json.load(open(f"{tmp}/table.json"))
nums = {int(p) for p in pick if p.isdigit()}
keep = [r for r in table if r["n"] in nums]
drop = [r for r in table if r["n"] not in nums]
if not keep: sys.exit("nothing picked to keep; aborting")
if not any(r["tag"] == "TEAM" for r in keep): print("WARNING: you are not keeping any TEAM key. Each box will refuse if root would be left with nothing.")
print("\nKEEP:");   [print(f"  {r['n']:>3} {r['tag']:5} {r['comment'][:30]:30} {r['where']}") for r in keep]
print("REMOVE:"); [print(f"  {r['n']:>3} {r['tag']:5} {r['comment'][:30]:30} {r['where']}") for r in drop] or print("  (nothing)")
open(f"{tmp}/keep.b64", "w").write(base64.b64encode("\n".join(r["blob"] for r in keep).encode()).decode())
PY
if [ "$YES" != 1 ] && [ -z "$CHECK" ]; then
    [ -z "$ROOTKEYS" ] && { read -rp "Also make root keys/certs-only (no root password over SSH)? [y/N] " a; [ "$a" = y ] && ROOTKEYS="--root-keys-only"; }
    read -rp "Apply to $LIMIT now? [y/N] " a; [ "$a" = y ] || { echo "cancelled; nothing changed"; exit 0; }
fi
ANSIBLE_LOG_PATH=/dev/null ansible "$LIMIT" -m script -a "scripts/keys_apply.sh --keep-b64 $(cat "$TMP/keep.b64") $ROOTKEYS $CHECK" --tree "$TMP/apply" > "$TMP/raw2.txt" 2>&1 || true
python3 - "$TMP/apply" <<'PY'
import json, os, sys
d = sys.argv[1]
for host in sorted(os.listdir(d)) if os.path.isdir(d) else []:
    r = json.load(open(os.path.join(d, host)))
    if r.get("unreachable"): print(f"[{host}] UNREACHABLE: {r.get('msg','')[:150]}"); continue
    print((r.get("stdout") or r.get("msg") or "").replace("\r", "").rstrip())
PY
echo "== Next: open a NEW ssh session to each box with your key before closing old ones."

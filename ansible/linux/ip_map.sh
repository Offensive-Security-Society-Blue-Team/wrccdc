#!/usr/bin/env bash
# ip_map.sh - runs ON YOUR LAPTOP (WSL). "Who is who" on the network: runs scripts/ip_collect.sh on every box,
# merges what each box saw, and labels every IP TEAM / SCORER / BLACK / RED / UNKNOWN with the evidence for it.
# Use it BEFORE you block anything (Inv3: we blocked a teammate, and someone blocked the scorer).
#
#   ./ip_map.sh                         all boxes in group 'linux'
#   ./ip_map.sh -l haf,djupi --top      plus Top-10 tables for injects (sources, failed logins, usernames)
#   ./ip_map.sh -u scoreduser1,scoreduser2   logins by these users count as scorer evidence
#   ./ip_map.sh --from-dir saved/       read saved collector outputs instead of running Ansible
# Labels you are sure of go in files/ipmap_labels.txt (created on first run):  LABEL  IP-or-CIDR  note
# Team keys (proof of TEAM): ~/.ssh/inv3.pub, files/team_key.pub, plus -K file.pub
# Writes loot/ipmap-<time>.md and .csv (and loot/top10-<time>.md with --top).
set -uo pipefail
cd "$(dirname "$0")" || exit 1
LIMIT=linux; TOP=0; USERS=""; FROMDIR=""; KEYS=(); LABELS=files/ipmap_labels.txt
for k in ~/.ssh/inv3.pub files/team_key.pub; do [ -f "$k" ] && KEYS+=("$k"); done
while [ $# -gt 0 ]; do
    case "$1" in
        -l) LIMIT=$2; shift ;;
        -u) USERS=$2; shift ;;
        -K) KEYS+=("$2"); shift ;;
        -L) LABELS=$2; shift ;;
        --top) TOP=1 ;;
        --from-dir) FROMDIR=$2; shift ;;
        -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "error: unknown option: $1 (try -h)" >&2; exit 1 ;;
    esac
    shift
done
mkdir -p loot files
if [ ! -f "$LABELS" ]; then
    cat > "$LABELS" <<'EOF'
# ipmap labels: LABEL  IP-or-CIDR  [note]       LABEL = team | scorer | black | red | ignore
# Add a line as soon as you KNOW who an IP is (ask in team chat first). Examples:
# team    192.168.220.0/24   our LAN + VPN
# team    10.0.0.25          teammate laptop (Inv3: we blocked this by mistake)
# scorer  10.234.234.234     scoring engine
# red     10.194.194.85      red team (forged root cert logins)
EOF
    echo "created $LABELS (fill it in as you confirm IPs)"
fi
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
: > "$TMP/teamfp.txt"
for k in "${KEYS[@]}"; do ssh-keygen -lf "$k" 2>/dev/null | awk '{print $2}' >> "$TMP/teamfp.txt"; done
if [ -z "$FROMDIR" ]; then
    [ -f scripts/ip_collect.sh ] || { echo "scripts/ip_collect.sh not found (run from ~/wrccdc/ansible/linux)"; exit 1; }
    echo "Collecting from $LIMIT ..."
    ANSIBLE_LOG_PATH=/dev/null ansible "$LIMIT" -m script -a "scripts/ip_collect.sh" --tree "$TMP/tree" > "$TMP/raw.txt" 2>&1 || true
    FROMDIR="$TMP/tree"
fi
STAMP=$(date +%Y%m%d-%H%M)
python3 - "$FROMDIR" "$LABELS" "$TMP/teamfp.txt" "$USERS" "$TOP" "loot/ipmap-$STAMP" "loot/top10-$STAMP.md" <<'PY'
import collections, csv, ipaddress, json, os, re, sys
src, labels_path, fp_path, users_arg, top, out_base, top_path = sys.argv[1:8]
TEAMFP = {l.strip() for l in open(fp_path) if l.strip()}
SCORED = {u for u in users_arg.split(",") if u}
SHELLS = {"bash", "sh", "dash", "ash", "zsh", "ksh", "python", "python2", "python3", "perl", "ruby", "php", "nc", "ncat", "netcat", "socat", "node", "lua", "busybox", "telnet"}

labels = []
for line in open(labels_path):
    p = line.split(None, 2)
    if len(p) >= 2 and not p[0].startswith("#"):
        try: labels.append((ipaddress.ip_network(p[1], strict=False), p[0].lower(), p[2].strip() if len(p) > 2 else ""))
        except ValueError: print(f"labels: skipped bad line: {line.strip()}")
def label_for(ip):
    a = ipaddress.ip_address(ip); best = None
    for net, lab, note in labels:
        if a in net and (best is None or net.prefixlen > best[0].prefixlen): best = (net, lab, note)
    return best

def blank(): return {"hosts": set(), "svcs": set(), "ok": [], "fail": 0, "fusers": 0, "web": 0, "w4": 0, "atk": 0, "scan": 0,
                     "wmin": 0, "smin": 0, "ua": set(), "tool": set(), "sample": "", "ftpok": 0, "ftpbad": 0, "smb": 0,
                     "conn": [], "drop": 0, "dropports": set(), "wtmp": 0, "btmp": 0, "first": "", "last": ""}
A = collections.defaultdict(blank)
selfips, selfnets, gws, dnss, hosts, users = set(), set(), set(), set(), [], collections.Counter()
for fn in sorted(os.listdir(src)):
    raw = open(os.path.join(src, fn), errors="replace").read()
    try:
        j = json.loads(raw)
        if j.get("unreachable") or not j.get("stdout"):
            print(f"[{fn}] no data: {str(j.get('msg', ''))[:100]}"); continue
        raw = j["stdout"]
    except ValueError:
        pass
    host = fn.rsplit(".", 1)[0]
    for line in raw.replace("\r", "").splitlines():
        f = line.split("|")
        t = f[0]
        try:
            if t == "HOST": host = f[1]; hosts.append(host); continue
            if t == "SELF": selfips.add(f[1]); selfnets.add(str(ipaddress.ip_network(f[2], strict=False))); continue
            if t == "GW": gws.add(f[1]); continue
            if t == "DNS": dnss.add(f[1]); continue
            if t == "SSHUSER": users[f[1]] += int(f[2]); continue
            ip = f[1]; ipaddress.ip_address(ip)
        except (IndexError, ValueError):
            continue
        a = A[ip]; a["hosts"].add(host)
        if t == "SSHOK":
            a["svcs"].add("ssh"); a["ok"].append({"host": host, "user": f[2], "meth": f[3], "kt": f[4], "fp": f[5], "cid": f[6], "n": int(f[7])})
        elif t == "SSHFAIL":
            a["svcs"].add("ssh"); a["fail"] += int(f[2]); a["fusers"] = max(a["fusers"], int(f[3]))
        elif t == "SSHMIN":
            a["smin"] = max(a["smin"], int(f[2]))
        elif t == "WEB":
            a["svcs"].add("web"); a["web"] += int(f[2]); a["w4"] += int(f[3]); a["atk"] += int(f[4]); a["scan"] += int(f[5])
            a["wmin"] = max(a["wmin"], int(f[6])); a["ua"].add(f[9])
            if f[10]: a["tool"].add(f[10])
            if f[11] and not a["sample"]: a["sample"] = f[11]
        elif t == "FTP":
            a["svcs"].add("ftp"); a["ftpok"] += int(f[2]); a["ftpbad"] += int(f[3])
        elif t == "SMB":
            a["svcs"].add("smb"); a["smb"] += int(f[2])
        elif t == "CONN":
            a["svcs"].add("conn-" + f[2]); a["conn"].append({"host": host, "dir": f[2], "lp": f[3], "rp": f[4], "proc": f[5]})
        elif t == "DROP":
            a["drop"] += int(f[3]); a["dropports"].update(f[4].split())
        elif t == "WTMP":
            a["wtmp"] += int(f[3])
        elif t == "BTMP":
            a["btmp"] += int(f[2])
H = max(len(set(hosts)), 1)

def classify(ip, a):
    ev, red, scr, blk, team = [], 0, 0, 0, 0
    lab = label_for(ip)
    teamkey = sorted({o["host"] for o in a["ok"] if o["fp"] in TEAMFP})
    if teamkey: team += 5; ev.append("team key login on " + ",".join(teamkey))
    for o in a["ok"]:
        if o["cid"] != "-":
            if re.search(r"competition|infra|black|vault|scor", o["cid"], re.I): blk += 4; ev.append(f"cert ID '{o['cid']}' as {o['user']}")
            elif o["user"] == "root": red += 3; ev.append(f"root via certificate ID '{o['cid']}'")
            else: red += 1; ev.append(f"certificate ID '{o['cid']}' as {o['user']}")
        elif o["meth"] == "publickey" and o["fp"] not in TEAMFP and o["user"] == "root":
            red += 2; ev.append(f"root via UNKNOWN key {o['fp'][:22]}")
    if a["fail"] >= 10 or a["fusers"] >= 3: red += 3; ev.append(f"{a['fail']} failed SSH logins, {a['fusers']} usernames")
    elif a["fail"] >= 3: red += 1; ev.append(f"{a['fail']} failed SSH logins")
    if a["btmp"] >= 10: red += 1; ev.append(f"{a['btmp']} failed logins in btmp")
    if a["atk"]: red += 3; ev.append(f"{a['atk']} attack-looking web requests, e.g. {a['sample'][:45]}")
    if a["scan"]: red += 3; ev.append("scanner user-agent: " + ", ".join(sorted(a["tool"]))[:40])
    if a["ftpbad"] >= 3: red += 1; ev.append(f"{a['ftpbad']} failed FTP logins")
    if a["drop"]: red += 2; ev.append(f"dropped by our firewall {a['drop']}x (ports {' '.join(sorted(a['dropports'], key=lambda p: int(p) if p.isdigit() else 0)[:6])})")
    sh = [c for c in a["conn"] if c["proc"].split("/")[-1].rstrip("0123456789.") in SHELLS or c["proc"] in SHELLS]
    if sh: red += 4; ev.append("SHELL holding a connection: " + ", ".join(f"{c['proc']}@{c['host']}" for c in sh[:3]))
    cov = len(a["hosts"]) / H
    steady = max(a["wmin"], a["smin"])
    okusers = {o["user"] for o in a["ok"]}
    if H >= 2 and cov >= 0.6: scr += 2; ev.append(f"seen on {len(a['hosts'])}/{H} boxes")
    if len(a["svcs"] - {"conn-in", "conn-out"}) >= 2: scr += 1
    if steady >= 15: scr += 2; ev.append(f"steady: active in {steady} separate minutes")
    if SCORED & okusers: scr += 2; ev.append("logs in as scored user " + ",".join(sorted(SCORED & okusers)))
    if not a["atk"] and not a["scan"] and a["fail"] < 3: scr += 1
    rootlogin = any(o["user"] == "root" for o in a["ok"]) or a["wtmp"]
    if lab:
        return lab[1].upper(), "labeled", ([lab[2]] if lab[2] else []) + ev
    if ip in selfips: return "SELF", "certain", ["one of our boxes"]
    if ip in gws: return "GATEWAY", "certain", ["default gateway (router)"] + ev
    if team >= 5 and red < 4: return "TEAM", "certain", ev
    if blk >= 4 and red < 3: return "BLACK", "likely", ev
    if red >= 4 and red >= scr: return "RED", "likely", ev
    if scr >= 5 and steady >= 15 and red <= 1: return "SCORER", "likely", ev
    if red >= 2: return "RED", "possible", ev
    if scr >= 3 and steady >= 15 and red <= 1: return "SCORER", "possible", ev
    if ip in dnss: return "DNS/DC?", "possible", ["DNS server in resolv.conf (often the domain controller)"] + ev
    if rootlogin: return "UNKNOWN", "ASK TEAM", ["logged in as root"] + ev
    return "UNKNOWN", "", ev

rows = []
for ip, a in A.items():
    try:
        if ipaddress.ip_address(ip).is_loopback: continue
    except ValueError: continue
    cat, conf, ev = classify(ip, a)
    ev = list(dict.fromkeys(ev))
    okcount = sum(o["n"] for o in a["ok"]) + a["ftpok"] + a["wtmp"]
    alert = cat == "RED" and okcount > 0
    if alert: ev = [f"!! SUCCESSFUL LOGINS: {okcount}"] + ev
    rows.append({"ip": ip, "cat": cat, "conf": conf, "boxes": len(a["hosts"]), "svcs": ",".join(sorted(a["svcs"])),
                 "events": a["web"] + a["fail"] + okcount + a["smb"] + len(a["conn"]), "fails": a["fail"] + a["ftpbad"] + a["btmp"],
                 "evidence": "; ".join(ev), "alert": alert})
order = {"RED": 0, "UNKNOWN": 1, "SCORER": 2, "BLACK": 3, "TEAM": 4, "DNS/DC?": 5, "GATEWAY": 6, "SELF": 7, "IGNORE": 8}
rows.sort(key=lambda r: (not r["alert"], order.get(r["cat"], 1), -r["events"]))

print(f"\n{'IP':16} {'WHO':8} {'HOW SURE':9} {'BOXES':>5} {'SERVICES':22} EVIDENCE")
for r in rows:
    print(f"{r['ip']:16} {r['cat']:8} {r['conf']:9} {r['boxes']:>3}/{H:<1} {r['svcs'][:22]:22} {r['evidence'][:150]}")
unk_fp = sorted({(o["fp"], ip) for ip, a in A.items() for o in a["ok"] if o["meth"] == "publickey" and o["fp"] not in TEAMFP and o["cid"] == "-"})
if unk_fp:
    print("\nSSH keys that are NOT team keys (fingerprint  <- IP):")
    for fp, ip in unk_fp: print(f"  {fp}  <- {ip}")

with open(out_base + ".csv", "w", newline="") as fh:
    w = csv.writer(fh); w.writerow(["ip", "who", "how_sure", "boxes", "services", "events", "failed_logins", "evidence"])
    for r in rows: w.writerow([r["ip"], r["cat"], r["conf"], r["boxes"], r["svcs"], r["events"], r["fails"], r["evidence"]])
with open(out_base + ".md", "w") as fh:
    fh.write(f"# Who is who ({H} boxes)\n\n| IP | Who | How sure | Boxes | Services | Evidence |\n|---|---|---|---|---|---|\n")
    for r in rows: fh.write(f"| {r['ip']} | {r['cat']} | {r['conf']} | {r['boxes']}/{H} | {r['svcs']} | {r['evidence'].replace('|', '/')} |\n")

lab_nets = lambda kinds: [n for n, l, _ in labels if l in kinds]
covered = lambda ip, kinds: any(ipaddress.ip_address(ip) in n for n in lab_nets(kinds))
trusted = list(dict.fromkeys(sorted(selfnets) + [str(n) for n in lab_nets(("team", "black"))] +
               [r["ip"] for r in rows if r["cat"] == "TEAM" and r["conf"] == "certain" and not covered(r["ip"], ("team", "black"))]))
maybe_trusted = [r["ip"] for r in rows if r["cat"] == "BLACK" and r["conf"] == "likely"]
scorer = [str(n) for n in lab_nets(("scorer",))]
maybe_scorer = [r["ip"] for r in rows if r["cat"] == "SCORER" and r["conf"] in ("likely", "possible")]
asks = [r["ip"] for r in rows if r["cat"] == "UNKNOWN" and r["conf"] == "ASK TEAM"]
print(f"\nFirewall flags (confirm anything marked * with your team, then put it in {labels_path}):")
print("  --trusted " + ",".join(trusted + [x + "*" for x in maybe_trusted]) + "   --scorer " + (",".join(scorer + [x + "*" for x in maybe_scorer]) or "<UNKNOWN: find it before using the firewall>"))
if asks: print("  ASK TEAM before blocking (they logged in as root and aren't labeled): " + ", ".join(asks))
print("  never block TEAM / SCORER / BLACK / GATEWAY rows; RED 'possible' needs a second look")
print(f"\nSaved: {out_base}.md and {out_base}.csv")

if top == "1":
    t1 = sorted(rows, key=lambda r: -r["events"])[:10]
    t2 = sorted([r for r in rows if r["fails"]], key=lambda r: -r["fails"])[:10]
    t3 = users.most_common(10)
    with open(top_path, "w") as fh:
        fh.write("# Top 10 report\n\nSource: SSH, web, FTP and SMB logs plus live connections on every box, collected with ip_collect.sh.\n\n")
        fh.write("## Top 10 source IPs by activity\n\n| # | IP | Who | Events | Services |\n|---|---|---|---|---|\n")
        for i, r in enumerate(t1, 1): fh.write(f"| {i} | {r['ip']} | {r['cat']} | {r['events']} | {r['svcs']} |\n")
        fh.write("\n## Top 10 failed-login sources\n\n| # | IP | Who | Failed logins |\n|---|---|---|---|\n")
        for i, r in enumerate(t2, 1): fh.write(f"| {i} | {r['ip']} | {r['cat']} | {r['fails']} |\n")
        fh.write("\n## Top 10 usernames attacked over SSH\n\n| # | Username | Failed attempts |\n|---|---|---|\n")
        for i, (u, n) in enumerate(t3, 1): fh.write(f"| {i} | {u} | {n} |\n")
    print(f"Top-10 tables for injects: {top_path}")
PY

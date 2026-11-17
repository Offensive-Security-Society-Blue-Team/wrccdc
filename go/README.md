# WRCCDC Go toolkit

Robust, single-binary rewrites of the blue-team scripts in this repo, for the
WRCCDC defensive competition. Every tool **detects the OS at runtime** and
switches behavior accordingly: on Linux it uses the native shells/commands
(`chpasswd`, `loginctl`, `ss`, `apk`/`dpkg`/`rpm`/`nix`), on Windows it uses
PowerShell/`net`/`query session`/`logoff` and Active Directory where present.

The code is **pure Go with no third-party dependencies**, so it builds and runs
offline and ships as one static binary per tool. Nothing here reads from the
network.

> These replace the Linux `*-enum.sh` / `*_pass.sh` and the Windows
> `passwords.ps1` / `localusers.ps1` / `changePasswords.bat` scripts. The
> original scripts under `Linux_Scripts/` and `Windows_Scripts/` are left
> untouched. The Ansible and Wazuh material is intentionally out of scope.

## Tools

| Binary | Purpose |
|--------|---------|
| `enum` | OS-aware host enumeration to one consolidated report |
| `rotatepw` | Rotate every human/local + domain password, skip service/system accounts |
| `revoke` | Kick intruders out: revoke sessions → rotate passwords → revoke again |
| `backup` | Pseudo-snapshot of important folders + Docker containers, with restore |
| `defaultcreds` | Rotate default creds for MySQL/MariaDB, WordPress, Gitea |

Binaries are prebuilt in `bin/linux-amd64/` and `bin/windows-amd64/`.

## Build

Requires a Go toolchain (built with Go 1.25). From this `go/` directory:

```bash
bash build.sh        # Linux/macOS or Git Bash
```
```powershell
.\build.ps1          # Windows PowerShell
```

Both cross-compile all five tools for `linux/amd64` and `windows/amd64` into
`bin/`. To target another architecture, e.g. a Linux ARM box:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o rotatepw-arm64 ./cmd/rotatepw
```

Run every tool **as root (Linux)** or **elevated / Administrator (Windows)**.
Most of them refuse to make changes otherwise; `--dry-run` previews without
elevation.

---

## rotatepw — password rotation

Rotates passwords for real accounts and records them to a `0600` file.

**What it rotates vs. skips**
- **Linux:** accounts with a real login shell whose UID is in the human range
  (default 1000–60000), plus `root` (unless `--include-root=false`). Accounts
  with a `nologin`/`false` shell, out-of-range UIDs, and a built-in deny list of
  service/system accounts (`www-data`, `mysql`, `postgres`, `git`, `gitea`,
  `named`, `sshd`, `nixbld*`, …) are **never** touched.
- **Windows local:** enabled local users, skipping the built-in `Guest`,
  `DefaultAccount`, `WDAGUtilityAccount`, disabled accounts, and (unless
  `--include-root`) the built-in `Administrator`.
- **Windows domain (on a DC):** AD users, **skipping any account with a
  `servicePrincipalName`** (classic service accounts), `krbtgt`, gMSA/disabled
  accounts. Rotating an SPN account breaks its service — exactly what we avoid.

By default the account **running the tool** is skipped so you can't lock
yourself out (`--include-self` to override).

```bash
# Linux: rotate humans + root, write record to default 0600 file
sudo ./rotatepw

# Preview only, no changes
sudo ./rotatepw --dry-run

# Leave extra accounts alone, alphanumeric-only passwords
sudo ./rotatepw --deny appsvc,backupjob --no-symbols
```
```powershell
# Windows DC: local + domain users (SPN/service accounts auto-skipped)
.\rotatepw.exe
# Local accounts only
.\rotatepw.exe -domain=false
```

Key flags: `-out`, `-length` (default 20), `-no-symbols`, `-include-root`
(default true), `-include-self`, `-domain` (default true), `-min-uid`,
`-max-uid`, `-deny`, `-dry-run`.

The credential file is written `0600` (and locked down with `icacls` on
Windows). **Record it off-box and delete it** when done.

---

## revoke — kick intruders out

A three-stage sequence to remove an active red-team foothold:

1. **Revoke all sessions.**
   - Linux: terminate each logind login session except your own
     (`loginctl terminate-session`), falling back to per-tty kills on OpenRC
     (Alpine). Then `pkill -KILL -u` any stray processes owned by human users.
     Root and your own session are never swept wholesale.
   - Windows: `logoff` every interactive/RDP session except your own, and
     `Close-SmbSession` to drop inbound file-share footholds.
2. **Rotate passwords** (same engine and exclusions as `rotatepw`).
3. **Revoke sessions again**, so any session re-established during the rotation
   with now-stale credentials is dropped.

```bash
sudo ./revoke                 # full sequence, preserves your shell
sudo ./revoke --no-rotate     # only revoke sessions
```
```powershell
.\revoke.exe
```

Your own session is preserved unless you pass `--include-self` (which can kill
the tool itself). Other flags mirror `rotatepw` (`-include-root`, `-domain`,
`-length`, `-deny`, …).

> Note: resetting a password does not by itself end an attacker's *existing*
> logon token or Kerberos ticket — that's why this logs sessions off twice
> around the rotation. It deliberately does **not** touch `krbtgt`; a `krbtgt`
> double-rotation is a separate, higher-risk action.

---

## backup — pseudo-snapshot & restore

We can't snapshot the VM, so this captures the parts that matter for recovery:
the folders red teams wipe or deface, and the state of running containers.

**What it captures**
- **Folders → `files/<name>.tar.gz`** with a per-archive sha256. Defaults:
  - Linux: `/etc`, DNS (`/etc/bind`, `/var/named`), web roots (`/var/www`,
    `/srv`, nginx/apache config), `/etc/ssh`, TLS material, `/opt`, `/root`.
  - Windows: `C:\inetpub\wwwroot`, DNS (`C:\Windows\System32\dns`),
    `C:\ProgramData\ssh`, XAMPP/WAMP/Apache web roots.
  - Override with `-paths`, or add more with `-add`.
- **Docker (if installed):** for each running container it saves
  `docker inspect`, commits the live container to an image and `docker save`s it
  gzipped, and archives each named **volume** (directly from the host mountpoint
  on Linux, or via a throwaway `alpine` tar container otherwise).
- **`MANIFEST.json`** tying it together with checksums.

```bash
# Snapshot to the default secret dir, and mirror to a second disk
sudo ./backup --mirror /mnt/backup2

# Snapshot specific paths, skip docker
sudo ./backup --no-docker --paths /etc,/var/www,/etc/bind

# Restore into a staging folder for review (safe, default)
sudo ./backup --restore /root/wrccdc/snapshots/HOST-20261111_120000

# Overwrite the live files in place (checksum-verified)
sudo ./backup --restore <snapdir> --in-place --force
```

Restore verifies each archive's sha256 before extracting and guards against
path-traversal entries. In-place restore requires `--force`. Loaded Docker
images are non-destructive (`docker load`); volume/data restore happens only
with `--in-place --force`.

Run snapshots on a schedule (cron / Task Scheduler) and **mirror off the box**,
since a single wiped path shouldn't destroy the only copy.

---

## defaultcreds — rotate stock service passwords

Locks out attackers relying on default/known service credentials. Each service
is best-effort: if the tool or config isn't found it's reported, not fatal.

- **MySQL / MariaDB:** connects with the mysql client (current password passed
  via `MYSQL_PWD`, never argv), rotates `root` across `localhost`/`127.0.0.1`/`%`
  (or every non-system account with `--mysql-all`). Tries `ALTER USER` then
  falls back to `SET PASSWORD`. System accounts like `mysql.sys` and
  `debian-sys-maint` are skipped.
- **WordPress:** finds `wp-config.php` (common web roots or `--wp-path`). Uses
  `wp-cli` when available; otherwise parses the DB credentials and updates the
  admin hash directly (WordPress accepts the legacy MD5 and upgrades it on next
  login).
- **Gitea / Forgejo:** runs `gitea admin user change-password` (new and old
  subcommand forms) as the service user via `sudo -u` on Linux, with the
  detected `app.ini`. Requires `--gitea-admin <username>`.

```bash
# Rotate everything it can find (dry-run first to see what's detected)
sudo ./defaultcreds --dry-run
sudo ./defaultcreds --gitea-admin giteaadmin

# Just MySQL, every account, with a known current root password
sudo ./defaultcreds --services mysql --mysql-all --mysql-pass 'oldRootPw'
```

Binary/config locations auto-detect on both OSes and can be overridden
(`--mysql-bin`, `--gitea-bin`, `--gitea-config`, `--wp-path`). Rotated
credentials go to the same kind of `0600` record file.

---

## enum — host enumeration

Collects services, listening ports and owning processes, connections, processes,
logins, cron/scheduled tasks, interfaces/routes, mounts/disk, installed
packages/apps, firewall posture, sudoers/SSH config, world-writable files, and
local admins — whatever applies to the detected OS — into one report
(`-out`, default under the temp dir).

```bash
sudo ./enum -out /root/enum.txt
```
```powershell
.\enum.exe -out C:\enum.txt
```

On Windows the report includes `systeminfo` and several PowerShell queries, so a
full run can take ~30–60 seconds.

---

## Safety model

- Service and system accounts are **never** rotated (shell/UID rules on Linux;
  SPN/well-known-SID/deny-list rules on Windows/AD). `krbtgt` is always
  excluded.
- The operator's own account and session are preserved by default.
- Secrets are fed to tools via stdin or environment, not command-line arguments,
  and credential files are written `0600`.
- Destructive restore is opt-in (`--in-place --force`) and checksum-verified.
- All tools support `--dry-run` or a safe default (staging restore) so you can
  preview before committing.

# WRCCDC portable scripts (paste-able fallbacks)

These are standalone **PowerShell**, **batch**, and **bash** rewrites of the Go
toolkit in `../` (`enum`, `rotatepw`, `revoke`, `backup`, `defaultcreds`). They
exist for one reason: **if you can't get the Go binary onto a box**, you can copy
and paste one of these scripts in over SSH / a console instead.

Every script is **fully self-contained** — no shared library, no other file to
source. Paste one script, run it, done. Behavior, flags, skip-rules, the
ambiguity-free password character set, and the credential-record format all
mirror the Go tools.

The Go binaries remain the preferred option when you can deliver them: they use a
cryptographic RNG everywhere and are a single static file. Reach for these
scripts only as a fallback.

## Which file for which box

The Go binary is one OS-aware program. The scripts split along the shell you'll
actually have on the target:

| Target | Use | Covers |
|--------|-----|--------|
| Linux / Unix | `bash/*.sh` | the Linux behavior of each tool |
| Windows (normal) | `powershell/*.ps1` | the Windows behavior of each tool |
| Windows (no PowerShell, or `.ps1` blocked) | `batch/*.bat` | the Windows behavior, cmd.exe-only |

```
portable/
  bash/        enum.sh  rotatepw.sh  revoke.sh  backup.sh  defaultcreds.sh
  powershell/  enum.ps1 rotatepw.ps1 revoke.ps1 backup.ps1 defaultcreds.ps1
  batch/       enum.bat rotatepw.bat revoke.bat backup.bat defaultcreds.bat
```

## The five tools

- **enum** — OS-aware host enumeration to one consolidated report.
- **rotatepw** — rotate every human/local (and, on a Windows DC, domain)
  password; skip service/system/SPN accounts.
- **revoke** — kick intruders out: revoke sessions, rotate passwords, revoke
  again.
- **backup** — pseudo-snapshot of important folders + Docker containers, with
  verifiable restore.
- **defaultcreds** — rotate default creds for MySQL/MariaDB, WordPress, Gitea.

See `../README.md` for the full description of each tool's logic; the scripts
follow it.

## Running

Run elevated: **root** on Linux, **Administrator** on Windows. Most refuse to
make changes otherwise; use the dry-run option to preview.

```bash
# Linux
sudo bash rotatepw.sh --dry-run
sudo bash enum.sh -out /root/enum.txt
sudo bash revoke.sh
sudo bash backup.sh --mirror /mnt/backup2
sudo bash defaultcreds.sh --gitea-admin giteaadmin
```

```powershell
# Windows (PowerShell) — you may need: Set-ExecutionPolicy -Scope Process Bypass
.\rotatepw.ps1 -DryRun
.\enum.ps1 -Out C:\enum.txt
.\revoke.ps1
.\backup.ps1 -Mirror E:\backups
.\defaultcreds.ps1 -GiteaAdmin giteaadmin
```

```bat
rem Windows (cmd.exe), from an elevated prompt
rotatepw.bat /dryrun
enum.bat C:\enum.txt
revoke.bat
backup.bat /mirror E:\backups
defaultcreds.bat /giteaadmin giteaadmin
```

Flag names match the Go tools. PowerShell uses `-Flag` style, batch uses
`/flag` style, bash uses `--flag` style.

## Credential records

`rotatepw`, `revoke`, and `defaultcreds` write new passwords to a record file
under the secret directory (`/root/wrccdc` on Linux, `%ProgramData%\wrccdc` on
Windows), locked to the owner (`chmod 600` / `icacls` Administrators+SYSTEM).
**Record it off-box and delete it when done.**

## Safety model (same as the Go tools)

- Service/system accounts are never rotated — shell/UID rules on Linux, well-known
  SID / deny-list rules on Windows. On a DC, accounts with a
  `servicePrincipalName` and `krbtgt` are always skipped.
- The operator's own account and session are preserved by default.
- Secrets are fed via stdin/environment, not command-line arguments, wherever the
  shell allows it.
- Destructive restore is opt-in and checksum-verified.

## Known limitations of the fallbacks

**Batch (`.bat`) versions — read before relying on them:**

- **Passwords are alphanumeric only** and use `%RANDOM%`, which is *not*
  cryptographically secure. cmd.exe cannot safely carry the symbol set
  (`! ^ % & | < >`) through variables or `net user`, so symbols are dropped and
  the default length is raised to 24 to compensate. Use the Go / PowerShell /
  bash version whenever you can for crypto-strength, symbol-bearing passwords.
- **No Active Directory rotation.** `rotatepw.bat` / `revoke.bat` rotate local
  accounts only. On a domain controller use `rotatepw.ps1` or the Go binary.
- `rotatepw.bat` / `revoke.bat` enumerate accounts with **`wmic`** and set
  passwords with **`net user`**. `wmic` is present on Server 2016–2022 and
  Win10/11 before 24H2; on newer builds that removed it, use the PowerShell
  version.
- `backup.bat` needs **`tar.exe`** (Win10 1803+ / Server 2019+) and stores Docker
  image archives **uncompressed** (`.tar`). `defaultcreds.bat`'s WordPress DB
  fallback parses **single-quoted** `wp-config.php` defines only.

**All versions:** `backup`'s Docker volume backup needs the `alpine` image
locally to tar a volume it can't reach by host mountpoint; `defaultcreds` is
best-effort per service and reports (does not fail on) missing tools/configs.

## Relationship to the Go source

These are ports, kept in sync with `../cmd/*` and `../internal/common/*`. If you
change the Go logic (skip-rules, deny list, character set, file format), update
the corresponding scripts here too.

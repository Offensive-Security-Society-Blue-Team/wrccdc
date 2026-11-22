# ccdc-audit

Read-only scripts that look for signs someone has been in a Linux box:
odd accounts, extra privileges, planted SSH keys, and scheduled-job persistence.
**They change nothing.** Lines starting with `[!]` are leads, not verdicts.

```
ccdc-audit/
├── 01_audit.yml            # runs both scripts on every host via Ansible
└── scripts/
    ├── user_audit.sh      # accounts, passwords, groups, sudo, SSH keys, sshd, logins
    └── cron_audit.sh      # cron, at, systemd timers/units, rc.local, shell hooks, ld.so.preload
```

POSIX `sh`. Tested on Ubuntu 24.04 with dash and busybox ash. Written to also run on
RHEL-family and Alpine (paths for each are handled).

## Run by hand on one box

```bash
sudo sh user_audit.sh | tee user_$(hostname)_$(date +%H%M).txt
sudo sh cron_audit.sh | tee cron_$(hostname)_$(date +%H%M).txt
grep '^\[!\]' user_*.txt cron_*.txt          # flags only
sudo RECENT_DAYS=1 sh cron_audit.sh          # tighten the "recently modified" window
```

## Run on every host with Ansible

```bash
ansible-playbook 01_audit.yml               # hosts in [linux]
ansible-playbook 01_audit.yml -l web01        # one host
```

Results: `out/<timestamp>/<host>-user_audit.txt` and `-cron_audit.txt` (mode 0600).
`script` doesn't need Python on the target, so this works on minimal or old boxes.

**After the first pass, use `verify_clean.sh` and `hunt.sh` instead of re-running 01.** At INV3, 01 was run at the start and once after the first fixes. After that, checks were one line per box:

```bash
ansible linux -m script -a "scripts/verify_clean.sh" | grep -E "certauth=|UNREACHABLE|FAILED"   # every 10-15 min
ansible linux -m script -a "scripts/hunt.sh" | tee out/hunt_$(date +%H%M).txt | grep -E "=====|\[!\]"
```

To compare two 01 runs anyway:

```bash
diff out/<earlier>/web01-cron_audit.txt out/<later>/web01-cron_audit.txt
grep -h '^\[!\]' out/<run>/*.txt           # every flag from every host
```

See `README.md` (sections *Clean-up pass* and *Watching*) for the scripts that fix what these find.

## Expected noise

- Every password shows "changed TODAY" right after *you* rotate them.
- `www-data`/`postgres` with a real shell can be legit on some images. Check what the service needs.
- `curl`/`wget` in a cron job can be legit (update checks, certbot).
- If the image was built in the last day or two, "recently modified" fires on stock files. Lower `RECENT_DAYS` or ignore.
- `last`/`lastb` are empty if the logs were never set up or were wiped. Wiped logs are a finding too.

## When something is flagged

Confirm it, **write it down** (time, host, what, where: incident reports earn points),
then fix it. Tell the box owner before you touch a scored service.

| Flag | Usual fix |
|---|---|
| Extra UID 0 account | `usermod -L name; usermod -s /usr/sbin/nologin name; chage -E 0 name` (lock, don't delete) |
| Empty password | `passwd name`, or lock it as above if nobody should use it |
| Service account with a shell | `usermod -s /usr/sbin/nologin name` (check the service still works) |
| Unknown sudo / NOPASSWD rule | Comment it out with `visudo` / `visudo -f /etc/sudoers.d/FILE` (never edit sudoers directly) |
| Unknown user in sudo/wheel/docker | `gpasswd -d name sudo` |
| Unknown SSH key | Delete that line from the file. Remember `chage -E 0` also blocks key logins |
| Stray `authorized_keys` / odd `AuthorizedKeysFile` | Remove the file / fix sshd config → `sshd -t` → reload, keeping a second session open |
| `PermitEmptyPasswords yes` | Set `no` (check `sshd_config.d/` drop-ins too) → `sshd -t` → reload |
| Immutable `/etc/passwd` etc. | `chattr -i FILE` first, or your password changes silently fail |
| Malicious cron line | Copy it into your notes, then delete the line or file. User crontab: `crontab -u name -r` |
| Pending `at` job | `at -c N` to read it, `atrm N` to remove |
| Unknown systemd unit | `systemctl disable --now NAME`, then move the unit file to a quarantine folder |
| Startup-file alias/hook | Remove the line from the `.bashrc`/profile |
| `/etc/ld.so.preload` | Move it aside, then check what the library is. Treat the box as rootkitted. |

After fixing, **kill what's already running**. Removing the cron job doesn't stop a
reverse shell that's already connected. Check `ss -tupn` and `ps -ef` and `kill` the process.

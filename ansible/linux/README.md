# inv3-ansible: Team 12 Linux kit (WCComps INV3)

Lock down, back up, and watch the 7 Linux boxes from one control node.
Run every command from inside this folder (`cd ansible/linux`): `ansible.cfg` only loads from here.

```
ansible/linux/
├── ansible.cfg
├── inventory/
│   ├── hosts.ini              # the 7 Linux boxes + router/Windows (kept out of [linux])
│   └── group_vars/all.yml     # FILL IN: scored users, Wazuh settings
├── 00_bootstrap.yml           # Python on Alpine + RAM/CPU per box
├── 01_audit.yml               # first-pass user + cron audit -> out/<time>/ (run once at the start)
├── 02_backup.yml              # /etc, web roots, DB dumps -> loot/backups/
├── 03_keys.yml                # team SSH key on the login account + proves it works
├── 04_passwords.yml           # new random passwords -> loot/passwords/*.csv
├── 05_sshd.yml                # safe sshd hardening (validated, keeps password login)
├── 06_wazuh.yml               # Wazuh manager on one box + agents everywhere else
├── files/agent.conf           # what Wazuh watches (pushed to every agent)
└── scripts/                   # run with: ansible <hosts> -m script -a "scripts/<name>.sh [args]"
    ├── verify_clean.sh        # READ-ONLY  one line per box: CLEAN or what came back  <- the main check
    ├── hunt.sh                # READ-ONLY  live triage: reverse shells, /tmp procs, SUID, web shells
    ├── account_use.sh <user>  # READ-ONLY  is this account in use (logins, sudo, processes, history)
    ├── implant_triage.sh [n]  # READ-ONLY  memfd/fileless programs + planted binary (default dbus_session)
    ├── php_find.sh            # READ-ONLY  PHP versions, PHP2Shell patch status, PHP files changed today
    ├── lockdown_ssh.sh        # CHANGES    /etc/ssh/.ssh, red keys on root, AuthorizedKeysFile, root certs
    ├── revoke_certs.sh [ID..] # CHANGES    revoke forged SSH certs by key ID (default forged-root-cert)
    ├── cleanup_persist.sh     # CHANGES    health-check timer, cron.d syshealth/sysintegrity, svc_health, red keys
    ├── php2shell_mitigate.sh  # CHANGES    PHP2Shell stopgap ini in every conf.d + restart PHP/web
    ├── reissue_cert.sh ENV    # CHANGES    re-issue an EXPIRED step-ca TLS cert from its renew .env file
    ├── reissue_hostcert.sh    # CHANGES    re-issue EXPIRED SSH host certs from step-ca
    ├── user_audit.sh          # (used by 01_audit.yml)
    └── cron_audit.sh          # (used by 01_audit.yml)
```

## Setup (the night before)

```bash
pip install ansible            # full package (includes the extra collections)
sudo apt install sshpass jq    # sshpass is needed for password logins (-k)
ssh-keygen -t ed25519 -f ~/.ssh/inv3 -C team12-blue
cp ~/.ssh/inv3.pub files/team_key.pub
ansible-inventory --graph      # should show debian / rhel / alpine under linux
```

## At 9:00

1. In `inventory/hosts.ini`, set `ansible_user=` under `[debian:vars]`. At INV3 every box (debian too) took `root`, so no `-K` was needed. If you log in as a sudo user instead, add `-K` to every command below. If the control node is outside 192.168.220.0/24, switch the IPs to 10.100.112.x.
2. In `inventory/group_vars/all.yml`, list the Quotient-scored accounts under `scored_users`.
3. Different password per box? Add `ansible_password=...` to that host's line for now. Delete it once 03 says KEY LOGIN OK.

## Run order

| # | Command | What you should see |
|---|---|---|
| 00 | `ansible-playbook 00_bootstrap.yml -k` | one line per box: OS, RAM, CPU. No `unreachable`. |
| 01 | `ansible-playbook 01_audit.yml` | flag counts per box. Then `grep -h '^\[!\]' out/<time>/*.txt` |
| 02 | `ansible-playbook 02_backup.yml` | `saved loot/backups/<host>-<time>.tgz` per box |
| 03 | `ansible-playbook 03_keys.yml -k` | `KEY LOGIN OK` per box. From here on `-k` is no longer needed. |
| 04 | `ansible-playbook 04_passwords.yml --check`, then without `--check` | the CHANGING / skipped lists, then `loot/passwords/<host>-<time>.csv` |
| 05 | `ansible-playbook 05_sshd.yml -l haf`, check scoring, then all | effective sshd settings printed; `permitemptypasswords no` |
| 06 | `ansible-playbook 06_wazuh.yml` | manager version, then an agent list with every box `Active` |

**`-k` and `-K`:** `-k` asks for the SSH password, which you only need until 03 has run. `-K` asks for the sudo password, only needed if `[debian:vars]` logs in as a sudo user instead of root.
**Test on one box first:** add `-l <host>` to any command. Preview playbook changes with `--check --diff`.

## Clean-up pass (after 03, once you know the red team's tricks)

These are the INV3 fixes as scripts. Run them in this order, on one or two boxes first (`-l haf,djupi`), then on `linux`:

```bash
for s in lockdown_ssh.sh "revoke_certs.sh forged-root-cert" cleanup_persist.sh; do
  ansible linux -m script -a "scripts/$s"
done | grep -E "=====|FIXED|REMOVED|LOCKED|CLEANED|FAILED|revoked IDs|cert-authority"
ansible linux -m script -a "scripts/verify_clean.sh" | grep -E "certauth=|UNREACHABLE|FAILED"
```

- **`lockdown_ssh.sh`** moves `/etc/ssh/.ssh` to `/root/quarantine/`, strips `kali@kali` / `deploy@management` from root's keys, forces `AuthorizedKeysFile .ssh/authorized_keys`, blocks cert logins as root, and restores the old sshd_config if `sshd -t` fails.
- **`revoke_certs.sh [ID ...]`** builds `/etc/ssh/revoked_keys` from the CA that signed `forged-root-cert` and adds `RevokedKeys`. Scoring certs have other IDs and keep working. Found another forged ID? Re-run with it added: `"scripts/revoke_certs.sh forged-root-cert <new-id>"`. Boxes that don't trust that CA print "nothing to do".
- **`cleanup_persist.sh`** removes the health-check timer/service, `cron.d/syshealth` + `sysintegrity`, the svc_health re-creation lines, the red keys in any `authorized_keys`, and locks `svc_health`. Everything removed is copied to `/root/quarantine/persist.<time>`. Leaves the scoring `cert-authority` lines alone and prints how many root has.
- All three are safe to re-run.

## Watching (every 10-15 minutes)

```bash
ansible linux -m script -a "scripts/verify_clean.sh" | grep -E "certauth=|UNREACHABLE|FAILED"
```

One line per box: `<host>: certauth=<n> CLEAN`, or the list of what came back (`RED-KEYS`, `NOPASSWD-SUDO`, `RED-SESSION`, `DEVNODE-RUNNING`, or a file path). Read it like this:
- **`certauth=`** must stay at the scoring CA count (it dropped to 0 when 03 ran with `wipe_other_keys`). If it falls, scoring SSH breaks.
- **`RED-SESSION`**: someone is connected from a red team IP right now. `ansible <host> -m raw -a "ss -tnp | grep -E '10\.194\.194\.85|10\.197\.207\.23'; who"`, then kill the PID, or on ss boxes `ss -K dst <ip>`.
- **Anything else:** re-run the clean-up pass on that host (`-l <host>`).

Deeper look, when verify_clean is clean but something still feels off:

```bash
ansible linux -m script -a "scripts/hunt.sh" | tee out/hunt_$(date +%H%M).txt | grep -E "=====|\[!\]"
ansible linux -m script -a "scripts/implant_triage.sh dbus_session"     # fileless / planted binary
ansible linux -m script -a "scripts/account_use.sh svc_health"          # is this account being used?
```

`01_audit.yml` is still useful for a first pass at 9:00. After that, verify_clean and hunt replace re-running it.
Re-run **02** after big fixes: `ansible-playbook 02_backup.yml -l 'linux:!gufu' | grep -E "saved|TOO BIG|failed="` (gufu's backup is too big; back it up by hand).

## PHP2Shell (CVE-2026-109618/109619)

```bash
ansible linux -m script -a "scripts/php_find.sh"            # which boxes run PHP, patched or not
ansible <hosts> -m script -a "scripts/php2shell_mitigate.sh" # stopgap until PHP is patched
```

The stopgap writes `99-php2shell.ini` into every PHP `conf.d` and restarts php-fpm/apache. To undo it, delete that file and restart the services.

## Expired step-ca certificates

`step ca renew` can't renew a cert that has already expired. These scripts re-issue it with the same key and names, using `/etc/step/provisioner-password`.

```bash
ansible linux -m script -a "scripts/reissue_hostcert.sh" | grep -E "=====|OK|FAILED|skipped|reloaded"   # SSH host certs
ansible haf   -m script -a "scripts/reissue_cert.sh /etc/step/renew/haf.env"      # TLS cert, one .env per cert
ansible djupi -m script -a "scripts/reissue_cert.sh /etc/step/renew/pos.env"
ansible skerja -m script -a "scripts/reissue_cert.sh /etc/step/skerja-https.env" | grep -E "=====|new cert|FAILED"
```

- **No .env on a box** (skerja had none): write one with `CA_URL`, `ROOT_FILE`, `CERT_FILE`, `KEY_FILE`, `KEY_PASSWORD_FILE` and `RELOAD_UNIT`. List the existing ones with `ls /etc/step/renew/`.
- **No `/etc/step/root_ca.crt`:** copy it over first: `ansible <host> -m copy -a "src=/tmp/root_ca.crt dest=/etc/step/root_ca.crt mode=0644"`.
- **Alpine:** `reissue_cert.sh` reloads with `systemctl`, which Alpine doesn't have. Reload by hand: `rc-service apache2 reload`.

## Things that will bite you

- **`UNREACHABLE`:** wrong IP or password, or a firewall is in the way. Run `ansible <host> -m ping -k -vvvv` to see the SSH error.
- **`Missing sudo password`:** add `-K` (only if a group logs in as a non-root user).
- **Alpine `NO_PYTHON`:** 00 installs it with `apk`, which needs the Alpine mirror. With no internet, use the bash kit on that box.
- **Scored users:** 04 never touches anything in `scored_users`. Change those through **Quotient** only.
- **Rotating the login account's own password:** run 04 with `-e rotate_login_user=true`, only after 03 said KEY LOGIN OK. If the debian group logs in as a sudo user, that's also the new sudo password for `-K`.
- **`03_keys.yml -e wipe_other_keys=true` also wipes the scoring `cert-authority` line** from root's keys, which breaks scored SSH. Put it back from the backup copy 03 leaves behind: `ansible <hosts> -m shell -a "grep -h '^cert-authority' /root/.ssh/authorized_keys.*~ | head -1 >> /root/.ssh/authorized_keys"`. Then check that verify_clean shows `certauth=1` or more.
- **Locked accounts** (Ubuntu's root, `!`/`*` in shadow) are skipped on purpose. Setting a password would unlock them.
- **Backups bigger than 400 MB** stay on the box at `/root/.bk-*.tgz`. Trim `backup_paths`, or raise the limit with `-e backup_max_mb=800`.
- **Wazuh needs internet** to reach packages.wazuh.com. Manager on Debian/RHEL only, never Alpine. Agents are pinned to the manager's exact version.
- **Newest Ansible (2.22+)** prints deprecation warnings for ad-hoc `-o`/`-t`. They still work. The playbooks don't use them.

## What was tested

Every playbook was run live against Ubuntu 24.04 with planted backdoors: a UID-0 user, an empty password, a red-team SSH key, an sshd drop-in with `PermitEmptyPasswords yes`, and cron reverse shells. Results:
- 03 wiped the planted key and proved key login over real SSH.
- 04 skipped the scored user and the locked accounts, and every saved password matched `/etc/shadow`.
- 05 overrode the planted drop-in, and refused a broken config.

The Rocky/Fedora/Alpine branches and the Wazuh install could not be run here (no access to those images or to packages.wazuh.com). They pass syntax checks and lint, but **dry-run 00 to 06 on practice VMs the night before.**

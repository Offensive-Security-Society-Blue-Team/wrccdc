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
├── 01_audit.yml               # user + cron audit on every box -> out/<time>/
├── 02_backup.yml              # /etc, web roots, DB dumps -> loot/backups/
├── 03_keys.yml                # team SSH key on the login account + proves it works
├── 04_passwords.yml           # new random passwords -> loot/passwords/*.csv
├── 05_sshd.yml                # safe sshd hardening (validated, keeps password login)
├── 06_wazuh.yml               # Wazuh manager on one box + agents everywhere else
├── files/agent.conf           # what Wazuh watches (pushed to every agent)
└── scripts/                   # audit scripts 01 runs + hunt.sh (ansible linux -K -b -m script -a scripts/hunt.sh)
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

1. In `inventory/hosts.ini`, set `ansible_user=` under `[debian:vars]` to the sudo user from the packet. If the control node is outside 192.168.220.0/24, switch the IPs to 10.100.112.x.
2. In `inventory/group_vars/all.yml`, list the Quotient-scored accounts under `scored_users`.
3. Different password per box? Add `ansible_password=...` to that host's line for now. Delete it once 03 says KEY LOGIN OK.

## Run order

| # | Command | What you should see |
|---|---|---|
| 00 | `ansible-playbook 00_bootstrap.yml -k -K` | one line per box: OS, RAM, CPU. No `unreachable`. |
| 01 | `ansible-playbook 01_audit.yml -K` | flag counts per box. Then `grep -h '^\[!\]' out/<time>/*.txt` |
| 02 | `ansible-playbook 02_backup.yml -K` | `saved loot/backups/<host>-<time>.tgz` per box |
| 03 | `ansible-playbook 03_keys.yml -k -K` | `KEY LOGIN OK` per box. From here on `-k` is no longer needed. |
| 04 | `ansible-playbook 04_passwords.yml -K --check`, then without `--check` | the CHANGING / skipped lists, then `loot/passwords/<host>-<time>.csv` |
| 05 | `ansible-playbook 05_sshd.yml -K -l haf`, check scoring, then all | effective sshd settings printed; `permitemptypasswords no` |
| 06 | `ansible-playbook 06_wazuh.yml -K` | manager version, then an agent list with every box `Active` |

Re-run **01** every 30-45 minutes and `diff` against the last run. Re-run **02** after big fixes.

**`-K` and `-k`:** `-K` asks for the sudo password (debian group). `-k` asks for the SSH password, which you only need until 03 has run.
**Test on one box first:** add `-l <host>` to any command. Preview changes with `--check --diff`.

## Things that will bite you

- **`UNREACHABLE`:** wrong IP or password, or a firewall is in the way. Run `ansible <host> -m ping -k -vvvv` to see the SSH error.
- **`Missing sudo password`:** add `-K`.
- **Alpine `NO_PYTHON`:** 00 installs it with `apk`, which needs the Alpine mirror. With no internet, use the bash kit on that box.
- **Scored users:** 04 never touches anything in `scored_users`. Change those through **Quotient** only.
- **Rotating the login account's own password:** run 04 with `-e rotate_login_user=true`, only after 03 said KEY LOGIN OK. On the debian group that's also the new sudo password for `-K`.
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

# INV3 command cheat sheet: Linux, team 12

Boxes: haf .67 (Lubuntu), kvigindis .44 (Ubuntu 24.04), djupi .222 (Mint), gufu .100 (Rocky, Gitea),
thorska .231 (Fedora 44), kolla .30 (Alpine), skerja .97 (Alpine), vigra .2 (OpenWRT router).
Internal 192.168.220.x, external 10.100.112.x.

**Before any change:** back up the file (`cp f f.bak`), change one thing, test the service, write it down.

---

## Where things live in this repo

| Folder | What | Run from |
|---|---|---|
| `Linux_Scripts/` | bash scripts, copied onto one box and run by hand (sections 1 and 1b) | the box |
| `Linux_Scripts/Wazzuh/` | manual / offline Wazuh install and rule notes (section 13b) | the Wazuh box |
| `ansible/linux/` | playbooks 00-06 + `scripts/` (verify_clean, lockdown, certs...) for every Linux box at once (sections 2-2c) | your laptop, `cd ansible/linux` first |
| `ansible/windows/` | Windows playbooks (Windows teammates) | - |

---

## 1. Audit scripts (all read-only except backup.sh)

```bash
sudo sh user_audit.sh | tee ua_$(hostname)_$(date +%H%M).txt   # accounts, sudo, SSH keys, sshd
sudo sh cron_audit.sh | tee ca_$(hostname)_$(date +%H%M).txt   # cron, at, systemd, rc.local, .bashrc hooks
sudo sh hunt.sh       | tee hu_$(hostname)_$(date +%H%M).txt   # reverse shells, /tmp processes, SUID, web shells
grep '^\[!\]' *.txt                                             # flagged lines only
diff ua_box_0915.txt ua_box_1000.txt                            # what changed between two runs
sudo sh backup.sh                                               # -> /var/tmp/bk-<host>-<time>.tgz, then scp it off
```
Get a script onto a box without Ansible: `scp hunt.sh root@192.168.220.67:/root/`, or paste it in with `cat > hunt.sh << 'EOF'` … `EOF`.

## 1b. Team enum / password / DNS scripts (Linux_Scripts/)

Pick the one for the distro. Enum + software are read-only; the rest CHANGE things.

```bash
# enumeration: services, ports, versions, processes, users, cron dirs
sudo bash debian-enum.sh      # any systemd box: Ubuntu, Lubuntu, Mint, Rocky, Fedora -> /tmp/enum.txt
sudo ash  alpine-enum.sh      # Alpine (OpenRC)                -> /tmp/enum.txt
#         linux-enum.sh       = same as alpine-enum.sh (OpenRC only), but writes /home/enum.txt
nix-shell nix-enum.sh         # NixOS only                     -> /tmp/<host>-enumeration.txt

# installed software
sudo bash debian-software.sh  # dpkg -l                        -> /tmp/installed-software.txt
sudo ash  alpine-software.sh  # apk info                       -> /tmp/installed-software.txt
nix-shell nix-software.sh     # NixOS only                     -> /tmp/<host>-installed-software.txt
rpm -qa | sort                # Rocky/Fedora: no script, use this

# copy results off, then delete them from the box (some are mode 0777)
scp root@<box>:/tmp/enum.txt enum_<box>.txt && ssh root@<box> rm /tmp/enum.txt

# DNS (BIND) hardening: recursion off, no zone transfers, hide version, security log
sudo bash dns.sh              # Debian paths; on Rocky/Fedora edit BIND_OPTIONS_FILE=/etc/named.conf and SERVICE_NAME=named first
```

**Password rotation by hand (no Ansible):**

```bash
sudo bash user-passwords.sh   # EVERY UID 1000-5999 user -> /home/<host>-new_passwords.txt
sudo bash root_pass.sh        # root only                -> /home/<host>-new_root_pass.txt
```
- `user-passwords.sh` **includes scored users.** On a box with Quotient-scored accounts, first edit the awk line,
  e.g. `awk -F: '$3>=1000 && $3<6000 && $1!="jsmith" {print $1}'`. Prefer `04_passwords.yml`, which skips them.
- Both leave the passwords on the box (user file is mode 0777). Copy them into the tracker, then `shred -u` the file.

## 2. Ansible (run from `ansible/linux/`)

Every box logs in as root (`hosts.ini`), so no `-K`/`-b` is needed. Add `-K` only if a group logs in as a sudo user.

```bash
cd ansible/linux                                    # ansible.cfg only loads from here
ansible-playbook 00_bootstrap.yml -k                # Python on Alpine + RAM/CPU per box
ansible-playbook 01_audit.yml                       # first-pass user + cron audit -> out/<time>/ (once at the start)
ansible-playbook 02_backup.yml -l 'linux:!gufu'     # -> loot/backups/<host>-<time>.tgz (section 16); gufu is too big
ansible-playbook 03_keys.yml -k                     # team key on login account; after this no more -k
ansible-playbook 04_passwords.yml --check           # preview, then run without --check -> loot/passwords/*.csv
ansible-playbook 04_passwords.yml -e rotate_login_user=true      # also root (the login account)
ANSIBLE_LOG_PATH=/dev/null ansible haf -m script -a "scripts/harden.sh --rotate '' --check"   # 05 step: harden.sh replaces 05_sshd.yml
ansible-playbook 06_wazuh.yml                       # manager + agents
grep -h '^\[!\]' out/<time>/*.txt                   # flagged lines from 01
```
Add `-l <host>` to test on one box, `--check --diff` to preview.

`03_keys.yml` only ADDS the team key now (`-e wipe_other_keys` was removed: it deleted the scoring `cert-authority` line).
Remove other keys with `keys_pick.sh` (section 2b), which keeps CA lines by default.
Every script prints its own examples with `-h`, and also when it's run with wrong arguments.

## 2b. INV3 scripts (`ansible/linux/scripts/`, details in `ansible/linux/README.md`)

**To keep or send the output, use `./run.sh <hosts> <script.sh> [args]` instead of `ansible ... -m script -a`.**
It saves `out/<script>_<hosts>_<time>.txt` (one block per box, with errors). Passwords go to `loot/passwords/` instead.
`./run.sh linux verify_clean.sh` · `./run.sh linux hunt.sh -g '=====|\[!\]'` · `./run.sh -h`

```bash
# --- the main check, every 10-15 min: one line per box, CLEAN or what came back
ansible linux -m script -a "scripts/verify_clean.sh $(awk '{print $2}' files/team_key.pub ~/.ssh/inv3.pub | sort -u | tr '\n' ' ')" | grep -E "certauth=|UNREACHABLE|FAILED"
#     UNKNOWN-KEYS=n -> ./keys_pick.sh -l <host>    (no key args = only checks the known INV3 red keys)

# --- clean-up pass (safe to re-run; try -l haf,djupi first)
./keys_pick.sh -l linux --check                     # every key on every box, what WOULD go
./keys_pick.sh -l linux                             # pick what to keep (Enter = team keys + CA lines)
for s in lockdown_ssh.sh "revoke_certs.sh forged-root-cert" cleanup_persist.sh; do
  ansible linux -m script -a "scripts/$s"
done | grep -E "=====|FIXED|REMOVED|LOCKED|CLEANED|FAILED|revoked IDs|cert-authority"
ANSIBLE_LOG_PATH=/dev/null ansible linux -m script -a "scripts/harden.sh --rotate ''"       # no --rotate = NEW ROOT PASSWORD
ANSIBLE_LOG_PATH=/dev/null ansible linux -m script -a "scripts/harden.sh --keys-b64 $(base64 -w0 files/team_key.pub) --exclude <scored,users>" | grep '^PW|'
ansible linux -m script -a "scripts/revoke_certs.sh forged-root-cert <new-id>"    # another forged cert ID found

# --- read-only digging
ansible linux -m script -a "scripts/hunt.sh" | tee out/hunt_$(date +%H%M).txt | grep -E "=====|\[!\]"
ansible linux -m script -a "scripts/implant_triage.sh dbus_session"   # fileless (memfd) + planted binary
ansible linux -m script -a "scripts/account_use.sh svc_health"        # logins, sudo, processes, history

# --- PHP2Shell (CVE-2026-109618/109619)
ansible linux   -m script -a "scripts/php_find.sh"                    # versions, patched?, PHP changed today
ansible <hosts> -m script -a "scripts/php2shell_mitigate.sh"          # stopgap ini + restart PHP/web

# --- expired step-ca certs (renew can't do expired ones)
ansible linux -m script -a "scripts/reissue_hostcert.sh" | grep -E "=====|OK|FAILED|skipped|reloaded"
ansible haf   -m script -a "scripts/reissue_cert.sh /etc/step/renew/haf.env"
ansible djupi -m script -a "scripts/reissue_cert.sh /etc/step/renew/pos.env"
ansible skerja -m script -a "scripts/reissue_cert.sh /etc/step/skerja-https.env"; ansible skerja -m raw -a 'rc-service apache2 reload'

# --- red team session still connected (verify_clean says RED-SESSION)
ansible <host> -m raw -a "ss -tnp | grep -E '10\.194\.194\.85|10\.197\.207\.23'; who"    # netstat -tnp on Alpine
ansible <host> -m raw -a "ss -K dst 10.194.194.85; ss -K dst 10.197.207.23"                  # or kill <PID>
```

## 2c. Ad-hoc

```bash
ansible linux -m ping                                   # who answers
ansible linux -m shell -a 'ss -tulpn'                   # any command on every box
ansible gufu -m shell -a 'tail -20 /var/log/secure'
ansible linux -m raw -a '...'                           # no Python needed (Alpine, broken boxes)
ansible 'linux:!alpine' -m shell -a 'who'               # everyone except Alpine
ansible linux -m shell -a 'systemctl is-active nginx apache2 httpd gitea 2>/dev/null'
```

## 3. Services: which tool on which distro

| Distro | Status / restart | Enable at boot | List running |
|---|---|---|---|
| Ubuntu, Lubuntu, Mint, Rocky, Fedora | `systemctl status X` / `systemctl restart X` | `systemctl enable X` | `systemctl list-units --type=service --state=running` |
| Alpine (OpenRC) | `rc-service X status` / `rc-service X restart` | `rc-update add X default` | `rc-status` |
| OpenWRT | `/etc/init.d/X restart` | `/etc/init.d/X enable` | `ls /etc/rc.d/` |

The SSH service is `ssh` on Ubuntu/Mint/Lubuntu, and `sshd` on Rocky/Fedora/Alpine. OpenWRT runs `dropbear`.

## 4. Accounts and passwords

```bash
awk -F: '$7 !~ /(nologin|false)$/ {print $1, $3, $7}' /etc/passwd   # who can log in
awk -F: '$3 == 0' /etc/passwd                                         # UID 0 = root-level
sudo awk -F: '$2 == ""' /etc/shadow                                   # no password at all
passwd <user>                                                         # change one (interactive)
# Suspicious account: LOCK, don't delete (keeps evidence, avoids breaking things)
usermod -L <user>; usermod -s /usr/sbin/nologin <user>; chage -E 0 <user>   # chage -E 0 also blocks SSH keys
# Alpine/busybox: passwd -l <user>; sed -i 's#^\(<user>:.*:\)[^:]*$#\1/sbin/nologin#' /etc/passwd
gpasswd -d <user> sudo         # remove from sudo (Debian family); wheel on Rocky/Fedora
visudo                         # edit sudoers SAFELY (syntax-checked); visudo -f /etc/sudoers.d/<file>
lsattr /etc/passwd /etc/shadow # 'i' flag = immutable, password changes fail -> chattr -i /etc/shadow
```
**Scored users change only through Quotient.**

## 5. SSH

```bash
find / -xdev -name 'authorized_keys*' 2>/dev/null       # every key file on the box
cat /home/<user>/.ssh/authorized_keys                    # delete lines you don't recognise
chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys       # sshd ignores keys with loose permissions
sshd -T | grep -iE 'permitroot|passwordauth|emptypass|authorizedkeys'   # settings sshd REALLY uses
ls /etc/ssh/sshd_config.d/                               # drop-in files override the main file
sshd -t && systemctl reload ssh                          # test THEN reload (sshd on Rocky/Fedora; rc-service sshd reload on Alpine)
```
Keep a second SSH session open until you've logged in again after any sshd change.

## 6. Persistence: find and remove

```bash
crontab -l -u <user>; crontab -u <user> -r      # show / remove a user's crontab
ls -la /etc/cron.d /etc/cron.hourly /var/spool/cron /var/spool/cron/crontabs /etc/crontabs 2>/dev/null
atq; at -c <job>; atrm <job>                    # one-time jobs
systemctl list-timers --all
systemctl disable --now <unit>; mkdir -p /root/quarantine; mv /etc/systemd/system/<unit> /root/quarantine/; systemctl daemon-reload
rc-update show; rc-update del <svc>             # Alpine boot services; also check /etc/local.d/*.start
cat /etc/ld.so.preload                          # should not exist; if it does, the box may be rootkitted
grep -nE 'alias (sudo|su)=|PROMPT_COMMAND|/dev/tcp' /root/.bashrc /home/*/.bashrc /etc/profile /etc/profile.d/* 2>/dev/null
```
Copy the bad line into your notes BEFORE you delete it, for the incident report.

## 7. Processes and connections

```bash
ss -tupn                        # live connections + owning process (netstat -tupn on busybox)
ss -tulpn                       # listening ports
ps -ef --forest                 # process tree (busybox: ps -o pid,user,args)
ls -l /proc/<pid>/exe /proc/<pid>/cwd   # what file it runs, where it lives
cat /proc/<pid>/cmdline | tr '\0' ' '
kill <pid>; kill -9 <pid>       # after noting it down; remove what restarts it first (cron/systemd)
lsof -i                          # if installed
```

## 8. Firewalls (allow scored ports + SSH BEFORE you turn anything on)

```bash
# Ubuntu / Mint / Lubuntu: ufw
ufw status numbered
ufw allow 22/tcp; ufw allow 80/tcp; ufw allow 443/tcp          # + every scored port on that box
ufw allow from 192.168.220.0/24 to any port 1514,1515 proto tcp # Wazuh manager box only
ufw enable                                                      # default = deny incoming
ufw disable                                                     # emergency undo

# Rocky / Fedora: firewalld
firewall-cmd --list-all
firewall-cmd --permanent --add-service=http --add-service=https
firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=192.168.220.0/24 port port=1514-1515 protocol=tcp accept'
firewall-cmd --reload

# Alpine / anything else: look only, change with the box owner
iptables -L -n -v
```
**Never block the scoring engine.** If a service goes red right after a firewall change, undo it first.

## 9. Web servers and web shells

```bash
nginx -t && systemctl reload nginx          # test config, then reload
apachectl configtest && systemctl reload apache2     # httpd on Rocky/Fedora
tail -f /var/log/nginx/access.log           # apache2/access.log, httpd/access_log
find /var/www -name '*.php' -mmin -60       # PHP files changed in the last hour
grep -rlE '(system|shell_exec|passthru|eval)\s*\(\s*\$_(GET|POST|REQUEST)' /var/www
```

## 10. Databases (change the app's config at the same time!)

```bash
mysql -u root -p -e "SELECT user,host FROM mysql.user;"
mysql -u root -p -e "ALTER USER 'wpuser'@'localhost' IDENTIFIED BY 'NewPass123';"
grep -E "DB_(USER|PASSWORD)" /var/www/*/wp-config.php       # update the app config to match, then test the site
sudo -u postgres psql -c '\du'
sudo -u postgres psql -c "ALTER USER appuser WITH PASSWORD 'NewPass123';"
```

## 11. Gitea (gufu)

```bash
ps -ef | grep [g]itea                                   # shows the user it runs as and its --config path
sudo -u git gitea --config /etc/gitea/app.ini admin user list
sudo -u git gitea --config /etc/gitea/app.ini admin user change-password --username <u> --password '<new>'
```
Swap `git` / `/etc/gitea/app.ini` for whatever `ps` showed. Admin accounts listed there that nobody knows are a finding.

## 12. Logs

```bash
tail -f /var/log/auth.log                     # Ubuntu/Mint/Lubuntu
journalctl -u sshd --since "30 min ago"       # Rocky/Fedora (or /var/log/secure)
tail -f /var/log/messages                     # Alpine
last -n 20; lastb -n 20                       # logins / failed logins
grep -E 'Accepted|Failed' /var/log/auth.log | tail -30
```

## 13. Wazuh

```bash
# on the manager
/var/ossec/bin/agent_control -l                     # every agent + Active/Disconnected
tail -f /var/ossec/logs/alerts/alerts.log
tail -f /var/ossec/logs/alerts/alerts.json | jq -c 'select(.rule.level >= 7) | {t: .timestamp, host: .agent.name, lvl: .rule.level, what: .rule.description, file: .syscheck.path}'
/var/ossec/bin/wazuh-control status
# on an agent
systemctl status wazuh-agent                         # Alpine: /var/ossec/bin/wazuh-control status
tail -50 /var/ossec/logs/ossec.log                   # why it won't connect
grep -A2 '<server>' /var/ossec/etc/ossec.conf        # which manager it points at
```

## 13b. Wazuh by hand (Linux_Scripts/Wazzuh/) - when 06_wazuh.yml can't be used

```bash
sudo bash wazuh_deploy.sh <this box's IP>    # all-in-one manager + indexer + dashboard (needs internet)
sudo bash wazuh_offline.sh                   # offline install; full steps in offline_install.md
# manager firewall (firewallrules.md): agents 1514/tcp, enrollment 1515/tcp, API 55000/tcp, dashboard 443
firewall-cmd --permanent --add-port={1514,1515,55000}/tcp && firewall-cmd --reload
ufw allow 1514,1515,55000/tcp
# Alpine agent by hand (wazuh_playlist.md)
apk add wazuh-agent && sed -i "s|MANAGER_IP|<manager IP>|g" /var/ossec/etc/ossec.conf && /var/ossec/bin/wazuh-control start
# log every command run as root via auditd (wazuh_notes.md); then add audit.log as a <localfile> in ossec.conf
echo '-a exit,always -F arch=b64 -F euid=0 -S execve -k audit-wazuh-c' >> /etc/audit/rules.d/audit.rules
auditctl -R /etc/audit/rules.d/audit.rules && auditctl -l
```
Custom rules (sudo, busybox-as-root): `linux_rules.md` -> `/var/ossec/etc/rules/local_rules.xml` on the manager.

## 14. OpenWRT router (vigra) - only with its owner

```bash
passwd                                       # root password = LuCI web login too
cat /etc/dropbear/authorized_keys            # SSH keys live HERE on OpenWRT
uci show dropbear; uci show firewall | head -50
logread -f                                   # live log
# send the router's logs to the Wazuh manager
uci set system.@system[0].log_ip='<manager IP>'
uci set system.@system[0].log_port='514'
uci set system.@system[0].log_proto='udp'
uci commit system && /etc/init.d/log restart
```

## 15. Find unlisted servers

```bash
nmap -sn 192.168.220.0/24                    # who's alive
nmap -sV -p- 192.168.220.<x>                 # what a new box is running (takes a while)
```

## 16. Restore one file from a backup

From `ansible/linux/`, using a `02_backup.yml` archive:

```bash
H=gufu                        # which box
F=etc/gitea/app.ini           # the file's path WITHOUT the leading /
V=20261121-094512             # which backup version (the time in the filename)

mkdir -p /tmp/r /tmp/now
tar xzf loot/backups/$H-$V.tgz -C /tmp/r "$F"
ansible $H -m fetch -a "src=/$F dest=/tmp/now/ flat=yes"
diff /tmp/now/$(basename "$F") "/tmp/r/$F"
ansible $H -m copy -a "src=/tmp/r/$F dest=/$F backup=yes"
ansible $H -m shell -a "<test> && <reload>"     # e.g. "nginx -t && systemctl reload nginx"
ansible $H -m shell -a "systemctl is-active <service>"
# then: check Quotient, and note time / host / file / diff output for the incident report
```

On the box itself, using a `backup.sh` archive (never untar over `/`):

```bash
mkdir -p /tmp/r && tar xzf /var/tmp/bk-<host>-<time>.tgz -C /tmp/r etc/nginx/nginx.conf
diff /etc/nginx/nginx.conf /tmp/r/etc/nginx/nginx.conf
cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bad && cp /tmp/r/etc/nginx/nginx.conf /etc/nginx/nginx.conf
# then test + reload with the table in section 17
```

## 17. After a restore: test, then reload/restart the service

The test part catches a broken config before the restart, so a bad file can't take the service down.
From `ansible/linux/`: `ansible $H -m shell -a "<command>"`. On the box itself, just run the command.

| You restored | Systemd boxes (Ubuntu, Mint, Lubuntu, Rocky, Fedora) | Alpine (OpenRC) |
|---|---|---|
| nginx config | `nginx -t && systemctl reload nginx` | `nginx -t && rc-service nginx reload` |
| Apache config | `apachectl configtest && systemctl reload apache2` (`httpd` on Rocky/Fedora) | `apachectl configtest && rc-service apache2 reload` |
| sshd config | `sshd -t && systemctl reload ssh` (`sshd` on Rocky/Fedora) | `sshd -t && rc-service sshd reload` |
| Gitea `app.ini` | `systemctl restart gitea && systemctl is-active gitea` | `rc-service gitea restart` |
| Samba (fileshare) | `testparm -s && systemctl restart smbd` (`smb` on Rocky/Fedora) | `testparm -s && rc-service samba restart` |
| NFS exports | `exportfs -ra` | `exportfs -ra` |
| FTP (vsftpd) | `systemctl restart vsftpd` | `rc-service vsftpd restart` |
| PHP-FPM | `php-fpm8.3 -t && systemctl reload php8.3-fpm` (version: `ls /etc/php`) | `rc-service php-fpm83 reload` |
| MySQL/MariaDB config | `systemctl restart mariadb` (or `mysql`) | `rc-service mariadb restart` |
| PostgreSQL config | `systemctl reload postgresql` | `rc-service postgresql reload` |
| website file (`/var/www/...`) | nothing, just reload the page | nothing |

**Service name doesn't match?** Check what's actually running on that box:

```bash
ansible $H -m shell -a "systemctl list-units --type=service --state=running"   # most boxes
ansible $H -m shell -a "rc-status"                                              # Alpine
```

**reload vs restart:** `reload` re-reads the config without dropping connections (use it when the
service supports it). `restart` fully stops and starts the service (needed for Gitea and most databases).
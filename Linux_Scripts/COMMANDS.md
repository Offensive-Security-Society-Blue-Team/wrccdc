# INV3 command cheat sheet: Linux, team 12

Boxes: haf .67 (Lubuntu), kvigindis .44 (Ubuntu 24.04), djupi .222 (Mint), gufu .100 (Rocky, Gitea),
thorska .231 (Fedora 44), kolla .30 (Alpine), skerja .97 (Alpine), vigra .2 (OpenWRT router).
Internal 192.168.220.x, external 10.100.112.x.

**Before any change:** back up the file (`cp f f.bak`), change one thing, test the service, write it down.

---

## 1. The scripts in this kit (all read-only except backup.sh)

```bash
sudo sh user_audit.sh | tee ua_$(hostname)_$(date +%H%M).txt   # accounts, sudo, SSH keys, sshd
sudo sh cron_audit.sh | tee ca_$(hostname)_$(date +%H%M).txt   # cron, at, systemd, rc.local, .bashrc hooks
sudo sh hunt.sh       | tee hu_$(hostname)_$(date +%H%M).txt   # reverse shells, /tmp processes, SUID, web shells
grep '^\[!\]' *.txt                                             # flagged lines only
diff ua_box_0915.txt ua_box_1000.txt                            # what changed between two runs
sudo sh backup.sh                                               # -> /var/tmp/bk-<host>-<time>.tgz, then scp it off
```
Get a script onto a box without Ansible: `scp hunt.sh root@192.168.220.67:/root/`, or paste it in with `cat > hunt.sh << 'EOF'` … `EOF`.

## 2. Ansible one-liners (run from the inv3-ansible folder)

```bash
ansible linux -m ping                                   # who answers
ansible linux -K -b -m shell -a 'ss -tulpn'             # any command on every box
ansible gufu -K -b -m shell -a 'tail -20 /var/log/secure'
ansible linux -K -b -m script -a scripts/hunt.sh        # run a local script on every box
ansible 'linux:!alpine' -K -b -m shell -a 'who'         # everyone except Alpine
ansible linux -K -b -m shell -a 'systemctl is-active nginx apache2 httpd gitea 2>/dev/null'
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

```bash
H=gufu                        # which box
F=etc/gitea/app.ini           # the file's path WITHOUT the leading /
V=20261121-094512             # which backup version (the time in the filename)

mkdir -p /tmp/r /tmp/now
tar xzf loot/backups/$H-$V.tgz -C /tmp/r "$F"
ansible $H -K -b -m fetch -a "src=/$F dest=/tmp/now/ flat=yes"
diff /tmp/now/$(basename "$F") "/tmp/r/$F"
ansible $H -K -b -m copy -a "src=/tmp/r/$F dest=/$F backup=yes"
ansible $H -K -b -m shell -a "<test> && <reload>"     # e.g. "nginx -t && systemctl reload nginx"
ansible $H -K -b -m shell -a "systemctl is-active <service>"
# then: check Quotient, and note time / host / file / diff output for the incident report
```
## 17. After a restore: test, then reload/restart the service

The test part catches a broken config before the restart, so a bad file can't take the service down.
Run from the kit folder: `ansible $H -K -b -m shell -a "<command>"`

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
ansible $H -K -b -m shell -a "systemctl list-units --type=service --state=running"   # most boxes
ansible $H -K -b -m shell -a "rc-status"                                              # Alpine
```

**reload vs restart:** `reload` re-reads the config without dropping connections (use it when the
service supports it). `restart` fully stops and starts the service (needed for Gitea and most databases).
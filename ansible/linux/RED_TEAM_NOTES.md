# What past WRCCDC environments and red teams looked like

Collected Nov 2026 to decide what the scripts in `scripts/` should check. Sources at the bottom.
**INV3 (our own logs) is the strongest source**: same environment template, same red team.

## The environment template

- **Same addressing every year:** internal `192.168.220.0/24`, external `10.100.1<team>.x` (1:1 NAT).
  The 2021 regionals pcaps use exactly this layout, so last octets and host roles tend to carry over.
- **Mixed fleet:** a Windows AD domain controller (DNS, LDAP 389/636, Kerberos 88, GC 3268), Windows
  servers with IIS/ASP.NET and RDP, and Linux boxes for web apps, mail, files, Git and databases.
  At INV3: Ubuntu/Lubuntu/Mint, Rocky + Fedora, two Alpine, OpenWrt router. Linux boxes join AD (sssd).
- **Services seen as scored or present (2021 pcaps + INV3 + 2026 practice-range packet):**

| Kind | Seen |
|---|---|
| Web | nginx, Apache 2.4, IIS 8/10, Caddy, Jetty (Jenkins), Tomcat manager, Python WSGI apps |
| Web apps | WordPress, DokuWiki, Adminer, osTicket, Home Assistant / ESPHome, payment / inventory / shop apps |
| PHP | 5.3 to 8.x, often old (PHP2Shell at INV3) |
| Git / CI | Gitea (port 3000) **plus Gitea Actions runners** (act_runner) |
| DB | MySQL / MariaDB 3306 (often listening on all interfaces), PostgreSQL |
| Mail | POP3 110, SMTP 587, IMAP, XMPP 5269, webmail |
| Other | FTP 21 (custom banners), telnet 23, SSH (OpenSSH on Linux and Windows), WinRM 5985, VNC 5800, Webmin 10000, Monit 2812, Nessus 8834, Splunk, step-ca (TLS + SSH certs), Podman containers |

## How the red team got in and stayed

From our INV3 logs (`out/`, `logs/ansible.log`) unless marked otherwise.

| Technique | INV3 example | Checked by |
|---|---|---|
| Default / reused creds | web apps, DBs, Gitea `gitadmin` (all write-ups list this as #1) | rotate early (04, harden.sh) |
| SSH keys everywhere | `kali@kali`, `deploy@management`, `root@localhost`; hidden `/etc/ssh/.ssh` via `AuthorizedKeysFile` | verify_clean, keys_pick, lockdown_ssh |
| Forged SSH certificates | `forged-root-cert` signed by an extra trusted CA (`vault-ca.conf`) | revoke_certs, **user_audit (trusted CAs)** |
| Cron + systemd re-creators | `cron.d/syshealth`, `sysintegrity`, `health-check.timer` re-adding `svc_health` | verify_clean, cleanup_persist, cron_audit |
| Units with system-looking names | `systemd-journal-flush-helper.service` -> `/usr/local/sbin/dbus_session`, `kworker-gc.service` | **verify_clean, cleanup_persist** |
| Drop-ins into real services | `zz-udev-cache.conf` in `ssh.service.d`, `sshd.service.d`, `nginx.service.d` | **cron_audit, verify_clean, cleanup_persist** |
| Unit hidden among package units | `devnode-syncd.service` in `/usr/lib/systemd/system`, owned by no package | **cron_audit (orphan check)** |
| Fileless implant | kvigindis process running from `memfd: (deleted)` | **verify_clean (MEMFD-PROC)**, hunt, implant_triage |
| **CI/CD as persistence** | red team commit to the Gitea repo; workflow on `cron: */5` ran `deploy.yml` as root on thorska ("Deploy management keys") | **cron_audit (CI runners)** |
| Shell startup files | `.bashrc` "# system health monitor" line | cleanup_persist, cron_audit |
| PAM / login stack | PAM files rewritten on kvigindis (`.pam-old` copies); write-ups: PAM is a password-logging spot | **user_audit (PAM section)** |
| Password sniffing via ptrace | write-up "Hawk": reads passwords out of sshd/sudo/su memory, so rotated passwords leak too | **hunt (traced processes)** |
| Web shells, LFI, scanners | 2021 pcaps: Nessus, Nuclei, Shellshock user-agents, `../../etc/passwd`; write-ups: www-data running bash | hunt (web shells, **service accounts running shells**) |
| Backdoor listeners | write-ups: unexpected ports like 4444, 2222 | **hunt (backdoor ports)** |
| Trojaned programs / PAM modules | a swapped `pam_unix.so` or `sshd` that logs passwords (write-ups: PAM is a password-logging spot). Boxes start clean, so any changed package file is theirs | **hunt (package files that no longer match their package)** |
| Blocking us / scoring | firewalld rich rules dropping `10.234.234.234` | by hand (`firewall-cmd --list-rich-rules`) |
| Destructive (late in the day) | write-ups: delete `/etc/fstab` + reboot, drop DBs, stop services | 02_backup.yml, keep backups OFF the box |

**Bold** = added in this change.

## Takeaways for next time

1. Pull the Gitea repos' recent commits and every runner's workflows early: a CI runner is root code execution on a timer.
2. Rotating a password on a box the red team still controls is not enough (ptrace sniffing). Clean first, then rotate.
3. Look in `/usr/lib/systemd/system` and `*.service.d/` too, not just `/etc/systemd/system`.
4. Keep backups somewhere the red team can't reach. Write-ups describe teams whose backups sat in the scored folder.

## Sources

- WRCCDC pcap archive (2021 regionals and qualifiers, via the Wayback Machine; the live site was down): https://archive.wrccdc.org/pcaps/
- Practice range modeled on a 2026 WRCCDC Invitational packet: https://github.com/Cdanner7766/ccdc-environ-2027
- Red teaming at WRCCDC 2023: https://bri5ee.sh/red%20team/2023/04/10/red-teaming-at-wrccdc-2023.html
- Hawk, credential harvesting at WRCCDC: https://platformsecurity.com/blog/hawk-wrccdc
- How to win CCDC, dealing with red team (2026): https://www.winterknight.net/how-to-win-ccdc-red-team/

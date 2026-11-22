#!/bin/sh
# account_use.sh <user> - READ-ONLY: is this account in use? Logged in now, recent
# logins, SSH logins + sudo use from the logs, running processes, last commands.
# Run on every box:  ansible linux -m script -a "scripts/account_use.sh admin"
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
U=${1:?usage: account_use.sh <user>}
echo "===== $(hostname): account '$U' ====="
if grep -q "^$U:" /etc/passwd; then grep "^$U:" /etc/passwd; id "$U" 2>/dev/null
else echo "(no local account '$U' - may still be a domain/AD account)"; fi

echo "-- logged in now"
who 2>/dev/null | grep -w "$U" || echo "(not logged in)"

echo "-- recent logins"
last -n 10 "$U" 2>/dev/null | grep -v -e '^$' -e '^wtmp' || echo "(no login history)"

echo "-- SSH logins, sudo and su use (from the logs)"
PAT="Accepted [a-z-]+ for $U |sudo(\[[0-9]+\])?: +$U :|su(\[[0-9]+\])?:.* $U"
for f in /var/log/auth.log /var/log/secure /var/log/messages; do
    [ -f "$f" ] && { grep -hE "$PAT" "$f" 2>/dev/null; }
done | tail -n 20
if ! [ -f /var/log/auth.log ] && ! [ -f /var/log/secure ] && command -v journalctl >/dev/null 2>&1; then
    journalctl --since today --no-pager 2>/dev/null | grep -E "$PAT" | tail -n 20
fi

echo "-- running processes"
if ps -eo user:20,pid,lstart,args >/dev/null 2>&1; then
    ps -eo user:20,pid,lstart,args | awk -v u="$U" '$1 == u' | head -n 15
else
    ps -o user,pid,args | awk -v u="$U" '$1 == u' | head -n 15
fi

H=$(awk -F: -v u="$U" '$1 == u {print $6}' /etc/passwd)
if [ -n "$H" ] && [ -s "$H/.bash_history" ]; then
    echo "-- last commands ($H/.bash_history)"
    tail -n 15 "$H/.bash_history"
fi
true

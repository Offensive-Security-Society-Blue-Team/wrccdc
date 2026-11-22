#!/bin/sh
# reissue_cert.sh ENVFILE - re-issue an EXPIRED step-ca TLS cert (renew can't), keeping the same key + names.
# ENVFILE is the step renew file for that cert (CA_URL, ROOT_FILE, CERT_FILE, KEY_FILE, KEY_PASSWORD_FILE, RELOAD_UNIT).
# Usage (from ansible/linux):
#   ansible haf -m raw -a "ls /etc/step/renew/"                               # find the .env first
#   ansible haf -m script -a "scripts/reissue_cert.sh /etc/step/renew/haf.env"
#   ansible djupi -m script -a "scripts/reissue_cert.sh /etc/step/renew/pos.env"
# On a box:  sudo sh reissue_cert.sh /etc/step/renew/<name>.env      Help: sh reissue_cert.sh -h
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
usage() {
    [ -n "${1:-}" ] && echo "error: $1" >&2
    cat >&2 <<'USAGE'
usage: reissue_cert.sh ENVFILE     (path ON THE BOX to the step renew .env; CHANGES the cert; run as root)
  ansible haf -m raw -a "ls /etc/step/renew/"                     # list the .env files first
  ansible haf -m script -a "scripts/reissue_cert.sh /etc/step/renew/haf.env"
  sudo sh reissue_cert.sh /etc/step/renew/pos.env
USAGE
    [ -n "${1:-}" ] && exit 1
    exit 0
}
case "${1:-}" in -h|--help) usage ;; esac
[ $# -eq 1 ] || usage "give exactly one .env file"
[ -f "$1" ] || usage "no such file on this box: $1"
[ "$(id -u)" -eq 0 ] || usage "must run as root"
. "$1"
echo "===== $(hostname -s): $CERT_FILE"
cp -p "$CERT_FILE" "$CERT_FILE.expired.$(date +%H%M%S)"
CN=$(openssl x509 -in "$CERT_FILE" -noout -subject -nameopt multiline | awk -F' = ' '/commonName/{print $2}')
SANS=$(openssl x509 -in "$CERT_FILE" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr -d ' ' | sed 's/IPAddress/IP/g')
PASSIN=""; [ -s "$KEY_PASSWORD_FILE" ] && PASSIN="-passin file:$KEY_PASSWORD_FILE"
# shellcheck disable=SC2086
openssl req -new -key "$KEY_FILE" $PASSIN -subj "/CN=$CN" ${SANS:+-addext "subjectAltName=$SANS"} -out /tmp/reissue.csr || { echo "FAILED: CSR"; exit 0; }
step ca sign --provisioner admin --provisioner-password-file /etc/step/provisioner-password --ca-url "$CA_URL" --root "$ROOT_FILE" --force /tmp/reissue.csr "$CERT_FILE" || { echo "FAILED: sign"; exit 0; }
echo "new cert: CN=$CN SANs=$SANS $(openssl x509 -in "$CERT_FILE" -noout -enddate)"
systemctl try-reload-or-restart "$RELOAD_UNIT" && echo "RELOADED $RELOAD_UNIT"
rm -f /tmp/reissue.csr

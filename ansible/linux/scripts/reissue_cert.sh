#!/bin/sh
# reissue_cert.sh ENVFILE - re-issue an EXPIRED step-ca TLS cert (renew can't), keeping the same key + names.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
[ -f "$1" ] || { echo "usage: reissue_cert.sh /etc/step/renew/<name>.env"; exit 0; }
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

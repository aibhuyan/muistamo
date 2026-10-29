#!/usr/bin/env bash
# Development only: a throwaway CA and certificates for mutual TLS between agentgateway and the
# control plane's authorization and ingest endpoints in the compose gateway profile. Production
# uses operator-provided certificates (customer PKI, cert-manager or a vault); Muistamo never
# generates or stores production keys. Files are gitignored (*.pem, *.key) and valid for 30 days.
set -euo pipefail
dir="$(dirname "$0")/tls"
mkdir -p "$dir"
cd "$dir"
current=1
for f in ca authz ingest gateway; do
  if ! { [ -s "$f.pem" ] && openssl x509 -in "$f.pem" -noout -checkend 86400 >/dev/null 2>&1; }; then current=0; fi
  if [ "$f" != ca ] && ! [ -s "$f.key" ]; then current=0; fi
done
if [ "$current" = 1 ]; then
  echo "dev certificates in $dir are current"
  exit 0
fi
rm -f ./*.pem ./*.key
key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }
key ca.key
MSYS_NO_PATHCONV=1 openssl req -x509 -new -key ca.key -sha256 -days 30 -subj "/CN=muistamo dev gateway CA (throwaway)" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.pem
leaf() { # name, subjectAltName, extendedKeyUsage
  key "$1.key"
  MSYS_NO_PATHCONV=1 openssl req -new -key "$1.key" -subj "/CN=$1 (throwaway)" -out "$1.csr"
  printf 'subjectAltName=%s\nextendedKeyUsage=%s\nkeyUsage=critical,digitalSignature\nbasicConstraints=critical,CA:FALSE\n' "$2" "$3" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -sha256 -days 30 -extfile "$1.ext" -out "$1.pem" 2>/dev/null
  rm -f "$1.csr" "$1.ext"
}
leaf authz "DNS:gateway-authz" serverAuth
leaf ingest "DNS:gateway-ingest" serverAuth
leaf gateway "URI:spiffe://muistamo.dev/agentgateway" clientAuth
# Nothing is ever issued later: the CA key is not kept, so it cannot leak or be mounted.
rm -f ca.srl ca.key
# Readable by the containers' non-root users; development material only.
chmod 644 ./*.pem ./*.key
echo "dev certificates written to $dir"

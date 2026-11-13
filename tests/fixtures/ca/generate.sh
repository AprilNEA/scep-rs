#!/usr/bin/env sh
# Regenerates the test CA in this directory with the openssl CLI.
#
# Test fixtures only: the keys are committed and must never be trusted outside
# this repository's tests. Validity is 100 years so the tests do not expire.
#
# Files:
#   root.pem / root.key        self-signed root CA that also signs and decrypts SCEP messages
#   ra.pem / ra.key            RA identity issued by the root (digitalSignature, keyEncipherment)
#   ra.pkcs1.key               the same RA key in PKCS#1 ("RSA PRIVATE KEY") PEM form
#   ra-sign-only.pem           the RA key with KeyUsage digitalSignature only (must be rejected)
#   chain.p7b                  openssl certificates-only SignedData (DER) with root.pem and ra.pem
set -eu
cd "$(dirname "$0")"

DAYS=36500

openssl req -x509 -newkey rsa:2048 -noenc -keyout root.key -out root.pem -days "$DAYS" \
  -subj '/CN=scep-rs test root/O=scep-rs tests' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash'

openssl req -newkey rsa:2048 -noenc -keyout ra.key -out ra.csr \
  -subj '/CN=scep-rs test RA/O=scep-rs tests'
openssl pkey -in ra.key -traditional -out ra.pkcs1.key

cat > ra.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOF
openssl x509 -req -in ra.csr -CA root.pem -CAkey root.key -set_serial 2 -days "$DAYS" \
  -extfile ra.ext -out ra.pem

cat > ra-sign-only.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOF
openssl x509 -req -in ra.csr -CA root.pem -CAkey root.key -set_serial 3 -days "$DAYS" \
  -extfile ra-sign-only.ext -out ra-sign-only.pem

openssl crl2pkcs7 -nocrl -certfile root.pem -certfile ra.pem -outform DER -out chain.p7b

rm -f ra.csr ra.ext ra-sign-only.ext

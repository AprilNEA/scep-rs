# sscep PKCSReq capture

A `PKCSReq` that `sscep` 0.10.0 (devenv `pkgs.sscep`) sent to `scep serve`
acting as `../ca/ra.pem` behind `../ca/root.pem`. Test fixtures only: the client
key is committed and must never be trusted outside this repository's tests.

| File | Content |
| --- | --- |
| `pkcsreq.der` | The `PKIOperation` POST body, recorded with `scep serve --capture-dir`. Outer `SignedData` (SHA-256, signed by a self-signed certificate), inner `EnvelopedData` to `ra.pem` (RSA PKCS#1 v1.5 key transport, AES-128-CBC), content `client.csr` as DER. |
| `client.key` | The PKCS#8 key the CSR and the self-signed certificate certify. |
| `client.csr` | The CSR, with `challengePassword` `secret` and a `keyUsage` extension request. |
| `client-req.cnf` | The `openssl req` configuration that produced `client.csr`. |

Reproduce:

```sh
openssl req -new -key client.key -out client.csr -config client-req.cnf \
  -addext 'keyUsage=digitalSignature,keyEncipherment'
scep serve --cert ../ca/ra.pem --key ../ca/ra.key --chain ../ca/root.pem \
  --listen 127.0.0.1:18080 --capture-dir /tmp/capture &
sscep getca -u http://127.0.0.1:18080/scep -c /tmp/ca.crt
sscep enroll -u http://127.0.0.1:18080/scep -c /tmp/ca.crt \
  -k client.key -r client.csr -l /tmp/client.crt -S sha256 -E aes
```

Pass the common `-c` filename base so sscep loads the CA/RA set and selects both
the responder's signing and encryption certificate. Capture mode returns HTTP
501 and issues no certificate; the request bytes are still recorded.

The self-signed signer certificate carries a 32-byte serial number (the
transaction ID as ASCII). `x509_cert::Certificate` with the default `Rfc5280`
profile rejects serials longer than 21 bytes, so unpatched `cms::SignedData`
cannot decode this message.

M2 uses the pinned upstream CMS profile extension to decode peer certificates
and identifiers as `Raw`, while local identities and issued certificates remain
strict. Both key-binding policies now return the original CSR and challenge
from this fixture, and replies preserve the long recipient serial. The
upstream changes are unreleased; see the [dependency pins and publication gate](../../../docs/design.md#4-dependencies).

Real M2 enrollment with the test CA also succeeds with default sscep algorithm
negotiation, AES-192 and AES-256. OpenSSL independently verifies the returned
CMS signature, decrypts the certificate set and verifies the issued chain. See
the root [usage example](../../../README.md#usage) to run issuance instead of
capture mode.

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
sscep enroll -u http://127.0.0.1:18080/scep -c /tmp/ca.crt-1 -e /tmp/ca.crt-0 \
  -k client.key -r client.csr -l /tmp/client.crt -S sha256 -E aes
```

The self-signed signer certificate carries a 32-byte serial number (the
transaction ID as ASCII). `x509_cert::Certificate` with the default `Rfc5280`
profile rejects serials longer than 21 bytes, so `cms::SignedData` cannot decode
this message; see `docs/design.md` for the consequence.

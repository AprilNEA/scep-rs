# Apple PKCSReq capture

Captured on 2026-11-08 from the native SCEP profile installer on macOS 27.2 (build 26B123). The server used `../ca/ra.pem` and `../ca/root.pem`. All identities and the challenge are disposable test data. No device identifiers or production credentials were supplied to the profile.

| File | Content |
| --- | --- |
| `pkcsreq.ber` | The original 2,689-byte PKIOperation POST body, without normalization. BER SignedData with SHA-256, an RSA signer certificate, and an EnvelopedData payload encrypted to the test RA using RSA PKCS#1 v1.5 and AES-128-CBC. |
| `client.csr.der` | The expected CSR, extracted by OpenSSL decryption of the captured message. The CSR requests an RSA-2048 certificate for `CN=Apple test client,O=scep-rs tests`. |
| `capture.mobileconfig` | The profile used for capture, including a public dummy challenge. The URL requires a server reachable at localhost port 18080 on the Mac. |

SHA-256 of `pkcsreq.ber`: `b7ddb0720e6577e4e3749973664748781102499fb48edcaa9c01fe066606cd93`.

## Capture

From this directory, run the server in one terminal:

```sh
scep serve --cert ../ca/ra.pem --key ../ca/ra.key --chain ../ca/root.pem \
  --listen 127.0.0.1:18080 --capture-dir /tmp/scep-apple-capture
```

On the Mac, open `capture.mobileconfig`, open System Settings → General → Device Management, and approve installation of the downloaded profile. When the server runs on another machine, forward Mac localhost port 18080 to the server first. A new capture has fresh keys and nonces and will not match the committed bytes.

The client retrieved GetCACaps and GetCACert, then sent the captured PKCSReq. M1 returned HTTP 501, so profile installation failed as expected. This is a real enrollment request, not successful enrollment. The Mac-generated private keys were not exported; `../ca/ra.key` is sufficient to decrypt the request.

## Independent verification

Run from this directory with OpenSSL. Despite the `-inform DER` spelling, OpenSSL accepts the BER encoding.

```sh
tmp=$(mktemp -d)
openssl cms -verify -inform DER -in pkcsreq.ber -noverify -binary \
  -out "$tmp/envelope.ber" -signer "$tmp/signer.pem"
openssl cms -decrypt -inform DER -in "$tmp/envelope.ber" \
  -recip ../ca/ra.pem -inkey ../ca/ra.key -out "$tmp/client.csr.der"
cmp client.csr.der "$tmp/client.csr.der"
openssl req -inform DER -in client.csr.der -verify -noout
```

Both signatures verify, and the decrypted CSR matches byte for byte. `-noverify` skips trust-chain validation of the self-signed transport certificate, not verification of the CMS signature.

## Historical ASN.1 blocker and key binding

### BER eContent loses its constructed-string metadata through Any

With unpatched `der 0.8.3` and `cms 0.3.0-rc.1`, `ContentInfo::from_ber` and BER decoding of its `SignedData` both succeed. The signer certificate has serial `01`, so this capture does not hit the sscep serial-number limit.

The eContent at offset 52 is a constructed indefinite-length OCTET STRING containing one 1,147-byte fragment. `SignedData.encap_content_info.econtent` stores that value as `Any`, which retains the fragment headers but not the constructed/indefinite header metadata. Decoding that `Any` as `OctetString` returns 1,151 bytes beginning `04 82 04 7b 30 80`, rather than the 1,147 envelope bytes beginning `30 80`. Inner `ContentInfo::from_ber` therefore fails with `expected SEQUENCE, got OCTET STRING`.

The same issue reproduces without the capture: direct `OctetString::from_ber` on `24 80 04 01 61 04 01 62 00 00` yields `ab`; decoding through unpatched `Any::from_ber` and `decode_as_encoding(EncodingRules::Ber)` yields `04 01 61 04 01 62`.

The pinned upstream fix assembles the OCTET STRING fragments in owned `Any`. M2 verifies the digest over the original envelope octets and decrypts this capture without rewriting the signed message. These dependency changes are not released; see the [dependency pins and publication gate](../../../docs/design.md#4-dependencies).

### The signer key differs from the CSR key

The actual signer certificate and CSR contain different RSA public keys. This comparison exits 1 for the captured request:

```sh
openssl x509 -in "$tmp/signer.pem" -pubkey -noout -out "$tmp/signer-public.pem"
openssl req -inform DER -in client.csr.der -pubkey -noout -out "$tmp/csr-public.pem"
cmp "$tmp/signer-public.pem" "$tmp/csr-public.pem"
rm -rf "$tmp"
```

This finding applies to the captured macOS version and profile; other Apple versions and configurations have not been tested. M2 implements the [key-binding policy](../../../docs/design.md#key-binding-policy): all strict entry points reject this request, while explicit `AllowDistinctKeys` returns `client.csr.der` and the expected challenge. Both signatures are verified in either mode; authorization remains the issuer's responsibility. There is no Cargo feature or Apple autodetection.

The Apple private keys were not exported, so tests of encrypted response recovery use synthetic distinct-key requests. No M2 test installs an issued certificate through the native profile installer; that remains M5 acceptance.

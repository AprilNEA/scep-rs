# scep-rs

Pure-Rust implementation of SCEP, the Simple Certificate Enrolment Protocol ([RFC 8894](https://www.rfc-editor.org/rfc/rfc8894)), for a sans-IO server and client. Built on the RustCrypto `cms`, `x509-cert`, and `rsa` crates; no OpenSSL or C dependencies in the Rust implementation.

## Status

Pre-release. The `0.0.0` crates on crates.io reserve the names and contain no implementation. This checkout implements discovery and the M2 initial-enrollment server: request verification, CSR proof of possession, signed certificate replies, an application-owned issuer boundary, and a CLI test CA. The client and renewal/polling operations are not implemented.

**Unreleased dependencies:** M2 requires RustCrypto ASN.1 changes for BER eContent and peer certificate profiles. `Cargo.toml` pins both upstream PRs to exact Git revisions, so this checkout builds without local dependency overrides. Upstream review and crate releases are still pending. See [dependencies and publication gate](docs/design.md#4-dependencies), including the root patches required when another workspace consumes these libraries.

## Crates

| Crate | Path | Role |
| --- | --- | --- |
| `scep` | `/` | Facade: re-exports the crates below behind the `server` and `client` features (both default) |
| `scep-protocol` | `crates/protocol` | CMS signatures and encryption, CSR validation, discovery, identity and HTTP mapping |
| `scep-server` | `crates/server` | Sans-IO `Responder`, immutable `Enrollment`, async `Issuer`, framework-independent HTTP handler |
| `scep-client` | `crates/client` | Reserved; not implemented |
| `scep-cli` | `crates/cli` | Binary `scep`: `serve` for discovery, capture-only operation, or a static-challenge test CA |

## Usage

Run the test CA using the disposable fixtures:

```sh
printf '%s\n' 'secret' > /tmp/scep-test-challenge
devenv shell -- cargo run -p scep-cli -- serve \
  --cert tests/fixtures/ca/ra.pem --key tests/fixtures/ca/ra.key \
  --chain tests/fixtures/ca/root.pem \
  --issuer-cert tests/fixtures/ca/root.pem --issuer-key tests/fixtures/ca/root.key \
  --challenge-file /tmp/scep-test-challenge
```

From a second terminal, retrieve the CA/RA set and enroll. Pass the same `-c` base filename to both commands so sscep selects the signing and encryption certificates from the set:

```sh
devenv shell -- sscep getca -u http://127.0.0.1:8080/scep -c /tmp/scep-ca.crt
devenv shell -- sscep enroll -u http://127.0.0.1:8080/scep -c /tmp/scep-ca.crt \
  -k tests/fixtures/sscep/client.key -r tests/fixtures/sscep/client.csr \
  -l /tmp/scep-client.crt
```

`Responder::new` uses strict CSR/CMS key binding. Explicitly select `ServerConfig::key_binding = KeyBindingPolicy::AllowDistinctKeys`, or CLI `--key-binding allow-distinct-keys`, to accept distinct keys such as those in the [Apple capture](tests/fixtures/apple/README.md). Both signatures are still verified; the issued leaf uses the CSR key and the encrypted reply targets the CMS signer. There is no compatibility feature or peer autodetection.

For application integration, implement `scep::server::Issuer` and pass bounded `http::Request<Bytes>` values to `scep::server::handle`. The handler returns protocol rejections as HTTP responses and infrastructure failures as typed `HandleError` values. Direct sans-IO integrations use `Responder::{open, reply, reject}`. The [API and security contract](docs/design.md#3-library-design) describes authorization, retry handling and resource limits.

## Security and interoperability limits

Do not deploy this pre-release as a production CA. The CLI's static challenge authorizes any subject, ignores requested extensions, and uses a bounded process-local retry cache. Identical transaction/CSR retries return the same certificate; changed CSRs under one transaction ID are rejected. Cache state is lost on restart. Production authorization and durable transaction storage belong in the application's `Issuer`.

Without `--challenge-file`, issuance remains disabled. `--capture-dir` is mutually exclusive with issuance and stores unverified CMS bytes. Use only disposable identities; every private key under `tests/fixtures` is public test material. Normal request logs omit query strings and bodies.

The dependency set uses RSA 0.10 stable, which RustSec marks as patched for [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html); the previous advisory exception is removed. This is not a production security review. Native Apple certificate installation remains an M5 acceptance task; replaying its captured request does not prove keychain installation.

## Development

The toolchain and checks are defined once in `devenv.nix`; CI runs the same `devenv test`.

```sh
devenv shell -- check   # actionlint, fmt, clippy, doc, test, cargo-deny
devenv test             # the same, as CI runs it
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

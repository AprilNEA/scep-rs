# scep-rs

Pure-Rust implementation of SCEP, the Simple Certificate Enrolment Protocol ([RFC 8894](https://www.rfc-editor.org/rfc/rfc8894)), for a sans-IO server and client. Built on the RustCrypto `cms`, `x509-cert`, and `rsa` crates; no OpenSSL or C dependencies in the Rust implementation.

## Status

Pre-release. The `0.0.0` crates on crates.io reserve the names and contain no implementation. This checkout implements M1 discovery: `GetCACaps`, `GetCACert`, RSA identity loading, certificates-only CMS, and an HTTP capture server. `PKIOperation` returns HTTP 501 after optional capture; certificate issuance and the client are not implemented. The design, conformance matrix, and remaining milestones are in [docs/design.md](docs/design.md).

## Crates

| Crate | Path | Role |
| --- | --- | --- |
| `scep` | `/` | Facade: re-exports the crates below behind the `server` and `client` features (both default) |
| `scep-protocol` | `crates/protocol` | Capabilities, certs-only `SignedData`, `Identity`, HTTP mapping on `http` types |
| `scep-server` | `crates/server` | `Responder` discovery responses; issuance is planned |
| `scep-client` | `crates/client` | Reserved; not implemented |
| `scep-cli` | `crates/cli` | Binary `scep`: `serve` for discovery and request capture |

## Usage

Run the capture server with the disposable test identity:

```sh
devenv shell -- cargo run -p scep-cli -- serve \
  --cert tests/fixtures/ca/ra.pem --key tests/fixtures/ca/ra.key \
  --chain tests/fixtures/ca/root.pem --capture-dir /tmp/scep-capture
```

From a second terminal, retrieve the CA and RA certificates:

```sh
devenv shell -- sscep getca -u http://127.0.0.1:8080/scep -c /tmp/scep-ca.crt
```

For framework integration, parse requests with `scep::protocol::transport::Operation::try_from(request)` and return the responder's `http::Response<Bytes>`:

```rust,no_run
use scep::{Identity, server::Responder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let certificate = std::fs::read_to_string("ca.pem")?;
    let key = std::fs::read_to_string("ca.key")?;
    let identity = Identity::from_pem(&certificate, &key)?;
    let responder = Responder::new(identity, vec![])?;
    let response = responder.ca_cert_response();
    assert_eq!(response.status(), 200);
    Ok(())
}
```

## Security and interoperability limits

Do not deploy this pre-release as a production CA. The `rsa` dependency remains affected by [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html), a private-key timing side channel. Blinding and implicit rejection do not establish that the advisory is fixed. `deny.toml` records a development exception because M1 performs no signing or decryption; reassess that exception before adding private-key operations in M2.

`--capture-dir` stores unverified CMS bytes, not validated enrollment requests. Use only disposable identities; every private key under `tests/fixtures` is public test material. Normal request logs omit the query string so legacy GET messages are not logged. The advertised algorithms select modern test-client encodings; they do not mean this discovery-only server can issue a certificate.

CMS certificate sets have no chain order: select certificates by their content, never their position. The real [sscep](tests/fixtures/sscep/README.md) and [Apple](tests/fixtures/apple/README.md) captures expose upstream decoding limitations for long certificate serial numbers and BER eContent. These remain M2 blockers. The Apple request also requires an explicit opt-in under M2's planned [key-binding policy](docs/design.md#key-binding-policy), whose default stays strict. The policy is not implemented in M1; discovery and capture do not establish enrollment compatibility.

## Development

The toolchain and checks are defined once in `devenv.nix`; CI runs the same `devenv test`.

```sh
devenv shell -- check   # fmt, clippy, doc, test, cargo-deny
devenv test             # the same, as CI runs it
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

# scep-rs

Pure-Rust implementation of SCEP, the Simple Certificate Enrolment Protocol ([RFC 8894](https://www.rfc-editor.org/rfc/rfc8894)), for both roles: a sans-IO server (`Responder` plus an `Issuer` trait for certificate policy) and a client (`Transaction`, optional HTTP client). Built on the RustCrypto `cms`, `x509-cert`, and `rsa` crates; no OpenSSL or C dependencies.

## Status

Pre-release. The `0.0.0` crates on crates.io reserve the names and contain no code. The first usable release is `0.1.0`, which implements the RFC 8894 mandatory set: `GetCACaps`, `GetCACert`, `PKCSReq` with `CertRep`, HTTP POST, AES-128-CBC, and SHA-256. The design, conformance matrix, and milestones are in [docs/design.md](docs/design.md).

## Crates

| Crate | Path | Role |
| --- | --- | --- |
| `scep` | `/` | Facade: re-exports the crates below behind the `server` and `client` features (both default) |
| `scep-protocol` | `crates/protocol` | Wire format: SCEP attributes, capabilities, `pkiMessage` signing and verification, `pkcsPKIEnvelope`, certs-only `SignedData`, HTTP mapping on `http` types |
| `scep-server` | `crates/server` | `Responder`, `Enrollment`, `Issuer`, `handle()` |
| `scep-client` | `crates/client` | `CaChain`, `Transaction`, `csr()`, `Client` |
| `scep-cli` | `crates/cli` | Binary `scep`: `getcacaps`, `getcacert`, `enroll`, `serve` (file-backed test CA) |

## Usage (planned `0.1.0` API)

Server: mount `handle()` on any HTTP framework that uses `http` types and implement `Issuer` with your certificate policy.

```rust
use scep::server::{Enrollment, Issuance, Issuer, Responder, ServerConfig};

struct MyCa { /* CA key, storage */ }

impl Issuer for MyCa {
    type Error = MyError;
    async fn issue(&self, enrollment: &Enrollment) -> Result<Issuance, MyError> {
        // Check `enrollment.challenge`, the CSR subject, and your own policy, then sign.
        // `enrollment.csr.info.public_key` is proven: the request was signed with the same key.
        Ok(Issuance::Issued(vec![leaf, ca]))
    }
}

let responder = Responder::new(identity, chain, ServerConfig::default())?;
// axum: `post(|req| async move { scep::server::handle(&responder, &ca, req).await })`
```

Client: fetch the CA chain, build a CSR, run one transaction.

```rust
use scep::client::{Client, csr};

let client = Client::new("https://ca.example/scep")?;
let caps = client.ca_caps().await?;
let chain = client.ca_chain(None).await?;
let request = csr(&key, subject, Some("challenge"), vec![])?;
let outcome = client.enroll(key, request, None).await?;
```

## Development

The toolchain and checks are defined once in `devenv.nix`; CI runs the same `devenv test`.

```sh
devenv shell -- check   # fmt, clippy, doc, test, cargo-deny
devenv test             # the same, as CI runs it
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

# scep-rs

Pure-Rust implementation of SCEP, the Simple Certificate Enrolment Protocol ([RFC 8894](https://www.rfc-editor.org/rfc/rfc8894)), for both roles: a sans-IO server (`Responder` plus an `Issuer` trait for certificate policy) and a client (`Transaction`, optional HTTP client). Built on the RustCrypto `cms`, `x509-cert`, and `rsa` crates; no OpenSSL or C dependencies.

## Status

Pre-release. `scep 0.0.0` on crates.io reserves the name and contains no code. The first usable release is `0.1.0`, which implements the RFC 8894 mandatory set: `GetCACaps`, `GetCACert`, `PKCSReq` with `CertRep`, HTTP POST, AES-128-CBC, and SHA-256.

## Crates

| Crate | Path | Role |
| --- | --- | --- |
| `scep` | `/` | Facade: re-exports the crates below behind the `server`, `client`, and `reqwest` features |
| `scep-protocol` | `crates/protocol` | Wire format: SCEP attributes, capabilities, `pkiMessage` signing and verification, `pkcsPKIEnvelope`, certs-only `SignedData`, HTTP mapping on `http` types |
| `scep-server` | `crates/server` | `Responder`, `Enrollment`, `Issuer`, `handle()` |
| `scep-client` | `crates/client` | `CaChain`, `Transaction`, `csr()`, `Client` |
| `scep-cli` | `crates/cli` | Binary `scep`: `getcacaps`, `getcacert`, `enroll`, `serve` (file-backed test CA) |

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

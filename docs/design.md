# scep-rs design: pure-Rust SCEP (RFC 8894) server and client

Status: agreed 2026-11-07. Repository [AprilNEA/scep-rs](https://github.com/AprilNEA/scep-rs); published crates `scep`, `scep-protocol`, `scep-server`, `scep-client`, `scep-cli` (names reserved as `0.0.0`).

Facts marked **verified** were read from the referenced sources; everything else is a design decision or a proposal.

## 1. Goal and scope

Provide one Rust library that implements the mandatory-to-implement subset of RFC 8894 for both roles, with no C or OpenSSL dependency, so that an MDM server can replace an external SCEP provisioner (such as step-ca) with an in-process issuer, and so that other projects can use it as a general SCEP library.

RFC 8894 §2.9 mandatory functionality (**verified**): GetCACaps, GetCACert, PKCSReq with its CertRep responses, HTTP POST transport, AES-128-CBC, SHA-256.

### v0.1 in scope

| Area | Server (`scep::server`) | Client (`scep::client`) |
| --- | --- | --- |
| GetCACaps | Serve `AES`, `POSTPKIOperation`, `SHA-256`, `SCEPStandard` | Parse keywords, select algorithms |
| GetCACert | Single CA cert (`application/x-x509-ca-cert`) or certs-only SignedData chain (`application/x-x509-ca-ra-cert`) | Parse both forms, pick encryption and signing certs by KeyUsage, verify SHA-256 fingerprint |
| PKIOperation | POST body and GET `message=` base64; PKCSReq only | PKCSReq; self-signed signing cert generated from the CSR key |
| CertRep | SUCCESS (certs-only SignedData, an unordered certificate set), FAILURE (failInfo, optional failInfoText), PENDING (encoding only, for issuers that queue) | SUCCESS, FAILURE, PENDING surfaced as outcomes; select the issued leaf by its CSR key, not its position; no CertPoll loop |
| Algorithms | Digest SHA-256; signature RSA PKCS#1 v1.5 with SHA-256; key transport RSA PKCS#1 v1.5; content AES-CBC 128/192/256 inbound, AES-128-CBC outbound by default | Same |
| Keys | RSA only (Apple's SCEP payload supports only RSA, **verified** in Apple's `SCEP.PayloadContent` docs) | RSA only |
| Encoding | Accept BER with indefinite lengths on inbound pkiMessages (Apple's native encoder emits BER; see §4); emit DER | Same |

### Deferred (v0.2+)

RenewalReq, CertPoll on the client and PENDING storage on the server, GetCert, GetCRL, GetNextCACert, 3DES and SHA-1 legacy mode, PasswordRecipientInfo for non-RSA keys, and RSA-OAEP. Capability parsing recognizes all RFC keywords, but recognition does not implement an algorithm or operation. The HTTP `Operation` enum is exhaustive; adding an operation requires a breaking change so dispatchers handle every operation.

Out of scope for this repository: certificate policy, admission logic, storage, and any consumer's migration.

## 2. Repository layout

```
scep-rs/
├── Cargo.toml              # root package `scep` + [workspace] members = ["crates/*"]; [workspace.lints]; shared versions
├── src/lib.rs              # facade: `pub use scep_protocol as protocol`, `pub use scep_server as server`, `pub use scep_client as client`
├── tests/                  # integration tests that need both roles: roundtrip, mutation, fixtures (from M2)
│   └── fixtures/           # captured pkiMessages: Apple (BER), sscep (DER), micromdm CertRep, with the keys that decrypt them
├── crates/
│   ├── protocol/           # `scep-protocol`: wire format, no I/O (see §3.1)
│   ├── server/             # `scep-server`: Responder, Enrollment, Issuer, handle()
│   ├── client/             # `scep-client`: CaChain, Transaction, csr(), Client (feature `reqwest`)
│   └── cli/                # `scep-cli`, binary `scep`: getcacaps, getcacert, enroll, serve (test CA)
├── fuzz/                   # cargo-fuzz targets against scep-protocol and scep-server (from M4; excluded from the workspace)
├── docs/design.md          # this document
├── devenv.nix, devenv.yaml, devenv.lock   # the single toolchain and check definition (see §8)
├── deny.toml               # cargo-deny: licenses, advisories, sources (see §8)
├── README.md, LICENSE-MIT, LICENSE-APACHE
└── .github/workflows/      # ci.yml (devenv test), interop.yml (sscep + Go scepserver, from M3), fuzz.yml (scheduled, from M4)
```

Five crates. The root package `scep` is the crate users depend on; it re-exports the three library crates behind features `server` and `client` (both default) and, from M3, `reqwest`, in the same way `sqlx` fronts `sqlx-core` and its drivers. The split follows dependency direction: `scep-protocol` is the only crate that touches `cms`, `x509-cert`, `rsa`, and `aes`; `scep-server` and `scep-client` depend on it and not on each other, so a server deployment compiles no client code and no `reqwest`. `scep-cli` holds the demo file-backed CA (`scep serve`) because it is the only consumer of that code; the libraries ship no CA. Directory names omit the `scep-` prefix that the path already states.

## 3. Library design

### 3.1 Module map

Each file owns one protocol concept; no `util` module. Target under 500 lines per file. Unit tests live in a sibling `tests.rs`, integration tests in the root `tests/`.

| Crate | File | Owns |
| --- | --- | --- |
| `scep` | `src/lib.rs` | Crate docs with the README example; `pub use scep_protocol as protocol` plus explicit root re-exports of the shared types (`Identity`, `TransactionId`, `Nonce`, `FailInfo`, `CaCapabilities`, `Error`); `pub use scep_server as server` and `pub use scep_client as client` behind features |
| `scep-protocol` | `error.rs` | `Error` (thiserror) and `FailInfo` mapping |
| `scep-protocol` | `attr.rs` | SCEP signed attributes: `MessageType`, `PkiStatus`, `FailInfo`, `TransactionId`, `Nonce`; conversion to and from `x509_cert::attr::Attributes` using `const_oid::db::rfc8894` |
| `scep-protocol` | `caps.rs` | `CaCapabilities`: parse and format the GetCACaps body; algorithm selection |
| `scep-protocol` | `pki_message.rs` | Signed layer: build and sign a pkiMessage; parse, verify signature and signed attributes, return header + optional envelope |
| `scep-protocol` | `envelope.rs` | pkcsPKIEnvelope: encrypt for a recipient certificate; decrypt with an RSA key; algorithm allowlist |
| `scep-protocol` | `certs_only.rs` | Degenerate certificates-only SignedData encode and decode (CertRep payload, GetCACert chain) |
| `scep-protocol` | `transport.rs` | Sans-IO HTTP mapping on `http` types: `Operation` parsing (`operation`, `message`), content types, response bodies |
| `scep-protocol` | `identity.rs` | `Identity { certificate, key }` used by both roles to sign and decrypt; self-signed certificate generation |
| `scep-server` | `responder.rs`, `enrollment.rs`, `issuer.rs`, `handle.rs` | `Responder`, `Enrollment` + `Rejected`, `Issuer` + `Issuance`, `handle()` |
| `scep-client` | `chain.rs`, `transaction.rs`, `csr.rs`, `http.rs` | `CaChain`, `Transaction` + `Outcome`, `csr()`, `Client` behind feature `reqwest` |
| `scep-cli` | `main.rs`, `serve.rs`, `enroll.rs`, `ca.rs` | clap commands; file-backed test CA implementing `Issuer` |

### 3.2 Public API sketch

Sans-IO core: all cryptography is synchronous and runtime-free. Async appears only at the `Issuer` boundary and in the optional HTTP client.

M1 implements `Identity::{new, from_pem, certificate, key}`, `CaCapabilities` (`FromStr`, `Display`, and capability queries), `certs_only::{encode, decode}`, `Operation::try_from(http::Request<B>)`, and the discovery methods of `Responder`. Discovery returns `http::Response<Bytes>` directly, without a separate response wrapper. `ServerConfig`, `KeyBindingPolicy`, enrollment, the issuer boundary, and all client APIs below remain planned.

```rust
// Shared (scep-protocol)
pub struct Identity { /* private certificate and key; construction validates the pair */ }
pub struct TransactionId(String);            // PrintableString, 1..=256 bytes
pub struct Nonce([u8; 16]);
pub enum FailInfo { BadAlg, BadMessageCheck, BadRequest, BadTime, BadCertId }
pub struct CaCapabilities { /* set of known keywords; unknown keywords kept as strings */ }

// Server: sans-IO (scep-server)
pub enum KeyBindingPolicy { RequireSameKey, AllowDistinctKeys }
pub struct ServerConfig { pub key_binding: KeyBindingPolicy, /* request limits */ }
pub struct Responder { /* identity, chain, caps, config */ }
impl Responder {
    pub fn new(identity: Identity, chain: Vec<Certificate>) -> Result<Self, Error>;
    pub fn with_config(identity: Identity, chain: Vec<Certificate>, config: ServerConfig) -> Result<Self, Error>;
    pub fn ca_caps(&self) -> &CaCapabilities;
    pub fn ca_caps_response(&self) -> http::Response<Bytes>;
    pub fn ca_cert_response(&self) -> http::Response<Bytes>;
    pub fn open(&self, pki_message: &[u8]) -> Result<Enrollment, Rejected>;
    pub fn reply(&self, enrollment: &Enrollment, issuance: Issuance) -> Result<Vec<u8>, Error>;
    pub fn reject(&self, rejected: &Rejected) -> Option<Vec<u8>>; // FAILURE CertRep when the header was recoverable
}
pub struct Enrollment {
    pub transaction_id: TransactionId,
    pub csr: x509_cert::request::CertReq,
    pub challenge: Option<Zeroizing<String>>,  // challengePassword, decoded from the CSR
    pub signer: Certificate,                   // the client's self-signed certificate; not an identity
    /* sender_nonce, selected algorithms: private */
}
pub struct Rejected { pub fail_info: FailInfo, /* header: Option<Header> */ }
pub enum Issuance { Issued(Vec<Certificate>) /* leaf first */, Pending, Rejected { fail_info: FailInfo, text: Option<String> } }

// Server: HTTP dispatch on `http` types (framework-agnostic; axum and hyper use them directly)
pub trait Issuer {
    type Error: std::error::Error + Send + Sync + 'static;
    /// May be called again for the same transaction when the client retries after a lost CertRep;
    /// return the same certificate for an identical CSR.
    async fn issue(&self, enrollment: &Enrollment) -> Result<Issuance, Self::Error>;
}
pub async fn handle<I: Issuer>(responder: &Responder, issuer: &I, request: http::Request<Bytes>) -> http::Response<Bytes>;

// Client: sans-IO (scep-client)
pub struct CaChain { pub certificates: Vec<Certificate> }
impl CaChain {
    pub fn parse(content_type: &str, body: &[u8]) -> Result<Self, Error>;
    pub fn verify_fingerprint(&self, sha256: &[u8; 32]) -> Result<(), Error>;
}
pub fn csr(key: &RsaPrivateKey, subject: Name, challenge: Option<&str>, extensions: Vec<Extension>) -> Result<CertReq, Error>;
pub struct Transaction { /* identity (self-signed), csr, recipient, verifier, transaction_id, sender_nonce, algorithms */ }
impl Transaction {
    pub fn new(key: RsaPrivateKey, csr: CertReq, ca: &CaChain, caps: &CaCapabilities) -> Result<Self, Error>;
    pub fn request(&self) -> Result<Vec<u8>, Error>;           // PKCSReq pkiMessage, DER
    pub fn cert_rep(&self, body: &[u8]) -> Result<Outcome, Error>;
}
pub enum Outcome { Issued(Vec<Certificate>), Pending, Failed { fail_info: FailInfo, text: Option<String> } }

// Client: HTTP, feature "reqwest"
pub struct Client { /* reqwest::Client, base URL */ }
impl Client {
    pub async fn ca_caps(&self) -> Result<CaCapabilities, Error>;
    pub async fn ca_chain(&self, message: Option<&str>) -> Result<CaChain, Error>;
    pub async fn pki_operation(&self, body: Vec<u8>) -> Result<Vec<u8>, Error>;
    pub async fn enroll(&self, key: RsaPrivateKey, csr: CertReq, expected_fingerprint: Option<[u8; 32]>) -> Result<Outcome, Error>;
}
```

Design choices:

- The library does not depend on axum. `handle()` works on `http::Request`/`http::Response` so an axum application mounts it with a two-line handler. An `axum` feature with a ready `Router` can be added later if a second consumer wants it.
- `Responder::open` performs cryptographic validation (signature, digest, nonce shape, algorithm allowlist, decrypt, CSR self-signature) and enforces the responder's key-binding policy. Authorization (challenge, subject, duplicate transaction) lives in `Issuer`. This keeps the library free of storage and of any consumer's concepts.
- `Issuer::issue` is a native `async fn` in trait; dyn dispatch is not needed because `handle` is generic.
- CMS certificates are a `SET OF`, not an ordered chain. DER encoding sorts them; BER decoding preserves the received order. A leaf-first application API must identify the leaf by its public key and reconstruct that order after decoding.

#### Key-binding policy

`ServerConfig::key_binding` selects one policy for each responder at construction. `Responder::new` uses `ServerConfig::default()`, whose key-binding policy is `KeyBindingPolicy::RequireSameKey`. A caller must use `Responder::with_config` and explicitly select `KeyBindingPolicy::AllowDistinctKeys` to accept different CSR and CMS signer keys. No Cargo feature, process-global switch, or peer detection changes the policy.

`RequireSameKey` compares the RSA modulus and public exponent, not certificate subjects or encoded certificate bytes. `AllowDistinctKeys` skips only this equality check. Both modes must verify the CMS signature, signed attributes, content digest, envelope, and CSR self-signature. `Responder::open` must enforce the selected policy before returning an `Enrollment`; an `Issuer` cannot bypass the check. The client continues to generate same-key requests.

M2's `scep serve` must expose the same policy through `--key-binding`, with its default derived from `ServerConfig` rather than defined separately. To accept the captured Apple request, select `--key-binding allow-distinct-keys`. This option is planned, not available in M1.

[RFC 8894 §2.3](https://www.rfc-editor.org/rfc/rfc8894.html#section-2.3) recommends the same subject and key with SHOULD, not MUST. Apple's [SCEP API](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/sec/Security/SecSCEP.h#L42-L59) accepts separate CSR keys and signer identity; the captured native profile uses different keys. The explicit policy preserves the strict default without treating every distinct-key request as a signature failure.

### 3.3 Message processing

Server, PKCSReq (`Responder::open`):

1. Size check (`ServerConfig::max_request_bytes`, default 256 KiB) before any decoding.
2. `cms::ContentInfo::from_ber` → `SignedData`; require `econtent_type == id-data`, exactly one `SignerInfo`, signer certificate present in `certificates` and matching `sid`.
3. Decode signed attributes; require `transactionID`, `messageType == 19`, `senderNonce` (16 bytes), CMS `contentType` and `messageDigest`.
4. Re-encode `signed_attrs` as DER `SET OF` (RFC 5652 §5.4; `SignedAttributes::to_der()`, **verified**) and verify with `rsa::pkcs1v15::VerifyingKey<Sha256>`; verify `messageDigest == SHA-256(econtent)`.
5. Decode the envelope: `KeyTransRecipientInfo` whose `rid` matches the responder's certificate; `RsaPrivateKey::decrypt_blinded(rng, Pkcs1v15Encrypt, enc_key)`; AES-CBC decrypt with PKCS#7 padding.
6. `CertReq::from_der` on the plaintext; verify the CSR self-signature; apply the configured [key-binding policy](#key-binding-policy); extract `challengePassword` (PKCS#9 `1.2.840.113549.1.9.7`, decoded as `DirectoryString`) into `Zeroizing<String>`.
7. Return `Enrollment`. Any failure maps to one `FailInfo` (§6) and a `Rejected` that can still produce a FAILURE CertRep when the signed header was readable and verified.

Server, CertRep (`Responder::reply`): the issued leaf must contain the CSR public key in both modes. Build certs-only SignedData (`ContentInfo::try_from(PkiPath)`, **verified** in cms 0.3.0-rc.1) → `EnvelopedDataBuilder` with `KeyTransRecipientInfoBuilder` for `enrollment.signer`, selected by the verified CMS signer identifier rather than by certificate-set position, and `ContentEncryptionAlgorithm::Aes128Cbc` → `SignedDataBuilder` signed by `Identity.key` with signed attributes `transactionID`, `messageType = 3`, `pkiStatus`, `recipientNonce = senderNonce`, fresh `senderNonce`, and `failInfo`/`failInfoText` on FAILURE. Never substitute the CSR key for the response recipient when the keys differ. FAILURE and PENDING omit the envelope (RFC 8894 §3.2, **verified**).

Client, PKCSReq (`Transaction::request`): generate a self-signed certificate with the CSR subject and key, KeyUsage `digitalSignature | keyEncipherment`, short validity, random serial; envelope the CSR for the CA encryption certificate; sign with the CSR key; attributes `transactionID` (random, 32 hex chars), `messageType = 19`, `senderNonce`.

Client, CertRep (`Transaction::cert_rep`): verify the signature with the CA signing certificate from `CaChain`; require `transactionID` equal and `recipientNonce == senderNonce`; map `pkiStatus`; on SUCCESS decrypt with the CSR key, parse certs-only SignedData, identify the issued leaf by its CSR public key, and return it before the remaining certificates. Never infer the leaf from the encoded position.

## 4. Dependencies

Use the RustCrypto der-0.8 generation. Versions and the APIs this design relies on were **verified** by reading the tagged sources (`cms/v0.3.0-rc.1`, `x509-cert/v0.3.0`, `der/v0.8.3`, `const-oid/v0.10.2`, `rsa/v0.10.0-rc.21`). Dependencies are added with `cargo add` in the milestone that first uses them.

The table describes the target feature set. M1 uses `cms` with default features disabled and only `std`, and `x509-cert` without `builder`. The `rsa` dependency is pinned exactly to `=0.10.0-rc.21`: rc.22 renames the RSA key types and changes features, while the planned `cms` builders use the rc.21 API. Reassess the pin together with the builder integration rather than upgrading RSA independently.

| Crate | Version | Why |
| --- | --- | --- |
| `cms` | 0.3.0-rc.1, features `builder`, `std` | `SignedDataBuilder`, `SignerInfoBuilder::add_signed_attribute`, `EnvelopedDataBuilder`, `KeyTransRecipientInfoBuilder` (RSA PKCS#1 v1.5), `ContentEncryptionAlgorithm::{Aes128Cbc,Aes192Cbc,Aes256Cbc}`, `ContentInfo::try_from(PkiPath)` for certs-only; enables `der/ber` |
| `x509-cert` | 0.3.0, features `builder`, `pem` | `CertReq`, `RequestBuilder` + `ChallengePassword`, `CertificateBuilder` with a custom `BuilderProfile` for the self-signed cert, `KeyUsage`, `SubjectKeyIdentifier` |
| `der` | 0.8.3, features `alloc`, `oid`, `ber` | `Decode::from_ber` accepts indefinite lengths and constructed indefinite OCTET STRINGs (**verified** tests in `asn1/octet_string.rs`); `from_der` stays strict |
| `const-oid` | 0.10.2, feature `db` | `db::rfc8894::{ID_TRANSACTION_ID, ID_MESSAGE_TYPE, ID_PKI_STATUS, ID_FAIL_INFO, ID_SENDER_NONCE, ID_RECIPIENT_NONCE, ID_SCEP_FAIL_INFO_TEXT}` and `db::rfc5912::PKCS_9_AT_CHALLENGE_PASSWORD` exist (**verified**), so the crate defines no OIDs |
| `rsa` | 0.10.0-rc.21, features `sha2`, `pem` | PKCS#1 v1.5 decryption implements implicit rejection (draft-irtf-cfrg-rsa-guidance §7.2) and blinding via `decrypt_blinded` (**verified** in `src/pkcs1v15.rs`); `pkcs1v15::{SigningKey, VerifyingKey, Signature}` satisfy the cms signer bounds |
| `sha2` 0.11, `aes` 0.9, `cbc` 0.2, `cipher` 0.5 (`block-padding`), `signature` 3 |  | Match cms 0.3.0-rc.1; `cbc::Decryptor::<Aes128>::new(key, iv).decrypt_padded_vec::<Pkcs7>(ct)` |
| `rand` 0.10 |  | `OsRng` for nonces, serials, CEK and IV (cms tests use `rand 0.10`) |
| `zeroize` 1, `thiserror` 2, `http` 1, `base64` 0.23 |  | Secrets, errors, sans-IO transport types, GET `message=` decoding |
| `reqwest` 0.13 (optional, `default-features = false`) | feature `reqwest` | Async client; TLS backend chosen by the application (CLI uses `rustls-tls`) |

Dev and interop: `tokio`, `axum` (CLI and tests), `hex-literal`, `cargo-fuzz`, the `openssl` CLI for cross-checks, `sscep` (nixpkgs) and micromdm `scepserver` (Go) for interop.

Why the rc generation and not `cms 0.2.3` / `rsa 0.9`: (1) BER acceptance for Apple's encoder exists only in der 0.8; (2) implicit rejection and blinding for PKCS#1 v1.5 decryption exist only in rsa 0.10 rc; (3) `sha2 0.11` and `hmac 0.13` are what current consumers already use, so no duplicate digest crates. Cost: the rc chain can break between rcs; pin exact versions in `Cargo.lock` and use caret ranges in `Cargo.toml` only once each crate reaches a stable release. Publishing `scep 0.1.0` with rc dependencies is allowed on crates.io but holds downstream users on the same rcs; see §10.

## 5. RFC 8894 conformance matrix (v0.1)

| RFC item | Server | Client |
| --- | --- | --- |
| §2.1.2 CA cert KeyUsage digitalSignature + keyEncipherment | `Responder::new` rejects an identity certificate missing either bit when KeyUsage is present | Selects the encryption cert by keyEncipherment and the verifier by digitalSignature; falls back to the single cert |
| §2.3 self-signed cert, same subject and key as CSR | Uses the explicit per-responder [key-binding policy](#key-binding-policy), strict by default; logs subject mismatch, does not reject | Always generates with same subject and key |
| §2.4 challengePassword | Exposed to `Issuer`; never logged; `Zeroizing` | Added through `csr()` when provided |
| §3.2 eContentType = id-data; signed attrs present | Enforced | Enforced |
| §3.2.1.1 transactionID PrintableString, unique | Length ≤ 256; uniqueness is `Issuer` policy | Random 128-bit hex |
| §3.2.1.2 unknown messageType | `FailInfo::BadRequest` | Error |
| §3.2.1.5 nonces 16 bytes, echo | Echoes senderNonce as recipientNonce, adds fresh senderNonce | Rejects CertRep whose recipientNonce ≠ sent senderNonce |
| §3.3.2.1 SUCCESS reply contains the issued leaf | `Issuance::Issued` requires a non-empty certificate set containing the issued leaf; CMS does not preserve input order | Selects the issued certificate by its CSR key; returns the leaf first at the application boundary |
| §3.4 certs-only SignedData with no content | `ContentInfo::try_from(PkiPath)` | Parses with and without `econtent` |
| §3.5 GetCACaps `text/plain` | Emits exactly `AES`, `POSTPKIOperation`, `SHA-256`, `SCEPStandard` | Ignores Content-Type, case-insensitive keywords, tolerates CRLF |
| §4.1 POST and GET | Both; GET `message=` is base64 (URL-decoded by the HTTP layer) | POST only |
| §4.2 GetCACert content types | `application/x-x509-ca-cert` for one cert, `application/x-x509-ca-ra-cert` for a chain | Parses both; `message=` parameter passed through |
| §4.3 `application/x-pki-message` | Request and response | Request and response |
| §7.5 downgrade | No 3DES/SHA-1 advertised or accepted | Errors when the CA does not advertise `SHA-256` and `AES` (v0.1 has no legacy mode); the error names the missing capability |

## 6. Security requirements

- Bound everything before cryptography: body size, BER nesting (der caps at 64), attribute counts, `transactionID` length, chain length (≤ 8 certificates).
- Algorithm allowlist, not denylist: `sha256` digest; `rsaEncryption`/`sha256WithRSAEncryption` signatures; `rsaEncryption` (PKCS#1 v1.5) key transport; `aes128/192/256-CBC` content. Anything else → `BadAlg` with no further processing.
- Fail uniformly. Server-side mapping: wrong or missing algorithm → `BadAlg`; signature, digest, decrypt, padding, CSR parse, CSR signature, key mismatch rejected by the configured policy → `BadMessageCheck`; wrong `messageType`, missing attributes → `BadRequest`. `failInfoText` is off by default for failures detected by `open`; the `Issuer` may set it for policy rejections.
- RSA decryption must use `decrypt_blinded` with `OsRng`. RUSTSEC-2023-0071 (Marvin) remains unpatched; implicit rejection and blinding are not proof that timing leakage is fixed. The dated `deny.toml` exception covers M1 development, which loads RSA identities but exposes no signing or decryption. Reassess the exception before M2 enables private-key operations; the current exception is not production approval. The README discloses the residual risk.
- Preserve the [key-binding policy](#key-binding-policy) contract: `Enrollment` always has verified CMS and CSR signatures, but only `RequireSameKey` binds both signatures to one RSA key. With `AllowDistinctKeys`, the CSR signature does not prove that the CMS signer holds the CSR private key.
- Treat the client's self-signed certificate as transport only: `Enrollment.signer` is documented as unauthenticated; no API returns its subject as an identity. In both modes, `Issuer` must authorize the requested subject and key and handle transaction replays independently of signature validation.
- Secrets: `challenge` is `Zeroizing<String>`; CEKs come from cms (zeroized after use); the library never logs message contents; `Debug` on `Enrollment` redacts the challenge.
- M1 capture is opt-in and accepts unverified bytes. Use disposable test identities, and keep raw captures out of application logs. HTTP request logs omit query strings because GET `message` contains the entire pkiMessage.
- The library does not require TLS (RFC 8894 §7.10) and does not validate server certificates itself; `reqwest` does when `https://` is used.
- No `unsafe` (`unsafe_code = "forbid"`), no `unwrap` outside tests except on local invariants with a comment.

## 7. Verification strategy

Unit tests (sibling `tests.rs`, not inline):

- `attr`: each attribute encodes to the RFC type and OID and decodes back; missing, duplicated, wrong-typed (`UTF8String` where `PrintableString` is required) and out-of-range values are rejected; `failInfoText` is optional.
- `caps`: `"AES\r\nPOSTPKIOperation\n"`, lower-case keywords, unknown keywords, empty body.
- `transport`: `operation` values, missing `message`, invalid base64, each content type.

Roundtrip and mutation tests (`tests/roundtrip.rs`): client `Transaction` against server `Responder` in process, then one test per mutation where a wrong implementation would still pass: flipped signature byte → `BadMessageCheck` and no `Enrollment`; recipientNonce altered → client rejects; envelope encrypted for another certificate → `BadMessageCheck`; AES-256 inbound accepted; 3DES OID inbound → `BadAlg`; body one byte over the limit → rejected before parsing; FAILURE CertRep without envelope decodes; SUCCESS CertRep selects the issued leaf by its CSR key even when DER sorting puts another certificate first.

Key-binding acceptance (M2, after the ASN.1 blockers are fixed):

- A valid same-key request succeeds under both policies, including when the signer subject differs from the CSR subject.
- The same valid distinct-key request is rejected with `BadMessageCheck` by `Responder::new`, `ServerConfig::default()`, and explicit `RequireSameKey`, but yields the expected CSR and challenge with explicit `AllowDistinctKeys`. Exercise both responders in one process and confirm that the strict responder still rejects after the permissive responder accepts. Include the real Apple capture.
- Both policies reject invalid CMS signatures, content digests, and CSR self-signatures. `AllowDistinctKeys` must not bypass an `Issuer` challenge rejection.
- A synthetic distinct-key request produces a certificate containing the CSR key. Only the selected CMS signer's private key, not the CSR private key, can recover the certificate from the encrypted CertRep. The Apple fixture has no exported client keys, so response decryption uses synthetic test keys.

Fixtures (`tests/fixtures/`): one PKCSReq captured from a real macOS client (BER, see M1) and one from `sscep` (DER), each with the responder key that decrypts it and the expected CSR; a CertRep captured from micromdm `scepserver`. These lock in interop with encodings our own code never produces.

Cross-checks with OpenSSL in CI: `openssl cms -verify -inform DER -noverify` on our PKCSReq and CertRep; `openssl cms -decrypt` on our envelope; `openssl req -verify` on `csr()` output.

Interop in CI (`interop.yml`): `sscep getca`/`enroll` against `scep serve`; `scep enroll` against micromdm `scepserver` (Go, built in the workflow). Both run on Linux.

Fuzzing (`fuzz.yml`, scheduled nightly, also `cargo fuzz run` locally): `Responder::open` with a fixed identity, `CaCapabilities::from_str`, `transport::Operation::try_from`. Corpus seeded from the fixtures.

Apple acceptance (manual, M5): on a Mac, run `scep serve --key-binding allow-distinct-keys` using the policy option planned for M2, install a `.mobileconfig` with a `com.apple.security.scep` payload (Challenge, Key Usage 1, RSA 2048) through System Settings, and confirm the issued certificate in the keychain. macOS requires user approval for profile installation, so this step is driven through the Mac screen, not a script.

## 8. Tooling and release

- `[workspace.lints]`: `rust.unsafe_code = "forbid"`, `rust.missing_docs = "warn"`, `clippy.all = "warn"`, `clippy.pedantic = "warn"`; crates inherit with `[lints] workspace = true`. Individual pedantic lints are allowed only with a reason, in the workspace table.
- `devenv.nix` is the single definition of the toolchain (rust-overlay stable, pinned version) and of the checks: the `check` script runs `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features -D warnings`, `cargo doc --no-deps` with `-D warnings`, `cargo test --workspace --all-features`, and `cargo deny check`; `enterTest` runs it, so `devenv test` locally and `ci.yml` execute the same command. There is no `rust-toolchain.toml`. Plain `cargo` still builds the library for users without Nix; `rust-version` in `[workspace.package]` is inherited by the published crates.
- `deny.toml`: license allowlist, `yanked = "deny"`, `wildcards = "deny"`, crates.io only. Advisory ignores are added with `reason` when the affected dependency arrives (§6).
- Release: `CHANGELOG.md` (Keep a Changelog); publish in dependency order `scep-protocol`, `scep-server`, `scep-client`, `scep`, `scep-cli` with one shared `[workspace.package].version`; Git tags `v0.1.0`. Dual license MIT OR Apache-2.0.

## 9. Milestones (demo-first)

Each milestone ends with something runnable.

| # | Deliverable | Exit criterion |
| --- | --- | --- |
| M0 | Repository bootstrap: workspace with the five crates, lints, CI, README with the planned API, `deny.toml`, devenv shell, this document | `devenv test` and CI green on empty crates; the five crate names reserved on crates.io as `0.0.0` (done 2026-11-07) |
| M1 | `caps`, `certs_only`, `transport`, `Responder::{ca_caps, ca_cert_response}`, `scep serve` answering GetCACaps/GetCACert, plus a capture mode that stores raw PKIOperation bodies | `sscep getca` succeeds against `scep serve`; a real macOS client's PKCSReq captured as a fixture and confirmed to decode with `ContentInfo::from_ber` |
| M2 | `attr`, `pki_message` verify path, `envelope` decrypt path, `Responder::open`, `Responder::reply`, explicit key-binding configuration, static-challenge `Issuer` in the CLI | `sscep enroll` receives a certificate with default settings; the Apple fixture is rejected by the strict default and yields the expected CSR and challenge only with explicit `AllowDistinctKeys`; the policy acceptance checks in §7 pass |
| M3 | `identity` self-signed cert, `pki_message` sign path, `envelope` encrypt path, `Transaction`, `csr()`, `Client`, `scep enroll` | `scep enroll` succeeds against `scep serve` and against micromdm `scepserver`; OpenSSL cross-checks pass |
| M4 | Hardening: limits, mutation tests, fuzz targets with 1 h of clean fuzzing, docs on every public item, `cargo deny` clean with documented ignores | CI green including `interop.yml` and `fuzz.yml` |
| M5 | Apple acceptance on a Mac; fixes found there | A macOS device enrolls with a challenge and the certificate appears in the keychain |
| M6 | `0.1.0` released for all five crates | Tags pushed, crates published, CHANGELOG written |

M1 interoperability evidence (2026-11-08): `sscep getca` retrieved the RA and root from the Rust server. A native macOS 27.2 profile installation produced the [Apple BER fixture](../tests/fixtures/apple/README.md); `ContentInfo::from_ber` and BER decoding of the outer `SignedData` succeed. OpenSSL verifies its CMS signature and CSR self-signature, and decryption reproduces the stored CSR. The server returned HTTP 501, so no certificate was issued. GET and POST transport preserve both captured requests byte for byte.

This meets M1's capture criterion, not M2 enrollment acceptance. The Apple capture confirms R1 and the distinct-key behavior in R6. The sscep capture confirms R5. The key-binding policy is decided in §3.2, but its implementation and acceptance checks remain M2 work. R1 and R5 remain upstream decoding blockers; the capture does not establish M2 or M5 compatibility.

Estimate: M0–M4 about three person-weeks, M5 about one week (dominated by Apple interop surprises).

## 10. Risks and decisions

Risks:

- **R1 BER econtent (confirmed).** The Apple fixture uses a constructed indefinite-length OCTET STRING. `EncapsulatedContentInfo.econtent` stores it as `Any`, which loses the constructed/indefinite header metadata but retains the fragment headers. Subsequent `OctetString` decoding returns the fragment wrapper rather than the envelope bytes. Outer CMS decoding succeeds, but inner `ContentInfo::from_ber` fails. The fixture README includes an independent minimal reproduction. Fix upstream (RustCrypto/formats), not with a local BER-to-DER rewriter.
- **R2 rc dependency chain.** `cms 0.3.0-rc.1` and `rsa 0.10.0-rc.21` can change between rcs. Mitigation: exact pins in `Cargo.lock`, CI on the pinned set, a tracking issue per rc crate.
- **R3 Marvin advisory.** Unpatched in the advisory database. M1's development exception and the mandatory reassessment before enabling private-key operations are defined in §6.
- **R4 Apple behaviour not in the RFC.** CA chain selection with `application/x-x509-ca-ra-cert`, retry behaviour on PENDING, fingerprint hash choice. Covered by M5 and by the Apple fixture.
- **R5 sscep serial numbers.** The captured sscep 0.10.0 PKCSReq contains a 32-byte serial in the self-signed signer certificate and its CMS signer identifier. The default `x509-cert` RFC 5280 profile rejects serials above 21 bytes, so `cms::SignedData` cannot decode this OpenSSL-verifiable message. M2 needs upstream support for a permissive peer-certificate/serial profile in `cms`; do not rewrite signed bytes or implicitly change the selected key-binding policy. A local copy of CMS structures is not the accepted solution. Reproduction and fixture provenance are in [tests/fixtures/sscep/README.md](../tests/fixtures/sscep/README.md).
- **R6 Apple key binding (policy decided; implementation pending).** OpenSSL verifies both signatures, but the captured macOS 27.2 CMS signer public key differs from the CSR public key. The [key-binding policy](#key-binding-policy) keeps strict rejection as the default and permits this request only after an explicit opt-in and successful validation. Other Apple versions and profile configurations remain untested; M2 and M5 must verify the configured behavior rather than infer interoperability from the capture.

Decisions (initially resolved 2026-11-07; updates dated below):

1. Home of the repository: `AprilNEA/scep-rs`.
2. License: MIT OR Apache-2.0.
3. Dependency generation: der-0.8 rc generation (§4).
4. Server integration surface: sans-IO `Responder` + `handle()` on `http` types, no axum in the library.
5. Key binding (updated 2026-11-08): explicit per-responder configuration, strict by default, no Cargo feature. The policy contract is defined in §3.2.
6. Crate name reservation: all five crates published as `0.0.0` with docs only.
7. Layout: root package `scep` in `src/` as a facade; modules split into `crates/{protocol,server,client,cli}`. Alternative kept on record: the root package could hold the protocol core itself, with `scep-server` and `scep-client` depending on `scep`; that gives users two crate names to import instead of one feature flag.
8. Default outbound content cipher: AES-128-CBC (RFC mandatory).

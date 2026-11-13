# scep-rs design: pure-Rust SCEP (RFC 8894) server and client

Status: design agreed 2026-11-07; M2 server implemented and locally verified 2026-11-12, with unreleased upstream PRs pinned for development (§4). Repository [AprilNEA/scep-rs](https://github.com/AprilNEA/scep-rs); published crates `scep`, `scep-protocol`, `scep-server`, `scep-client`, `scep-cli` still reserve names as `0.0.0`.

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

Five crates. The root package `scep` is the facade, with `server` and `client` features (both default); the HTTP client is planned for M3. `scep-protocol` owns the wire format and the direct RustCrypto dependencies. The server and client depend on protocol, not each other. The CLI uses the re-exported cryptographic types to implement a PEM-loaded test CA; its transaction cache is process-local, not file-backed. The libraries ship no CA or storage. The layout above includes planned client, interoperability and fuzz targets.

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
| `scep-protocol` | `csr.rs`, `limits.rs` | `VerifiedCsr` proof of possession and challenge extraction; configurable resource limits |
| `scep-protocol` | `certs_only.rs` | Degenerate certificates-only SignedData encode and decode (CertRep payload, GetCACert chain) |
| `scep-protocol` | `transport.rs` | Sans-IO HTTP mapping on `http` types: `Operation` parsing (`operation`, `message`), content types, response bodies |
| `scep-protocol` | `identity.rs` | `Identity { certificate, key }` used by both roles to sign and decrypt; self-signed certificate generation is planned for M3 |
| `scep-server` | `responder.rs`, `config.rs`, `enrollment.rs`, `issuer.rs`, `handle.rs`, `error.rs` | `Responder`, per-responder policy, immutable enrollment/rejection types, issuer boundary, HTTP dispatch and operational errors |
| `scep-client` | `chain.rs`, `transaction.rs`, `csr.rs`, `http.rs` | `CaChain`, `Transaction` + `Outcome`, `csr()`, `Client` behind feature `reqwest` |
| `scep-cli` | `main.rs`, `serve.rs`, `ca.rs` | clap command and static-challenge test CA implementing `Issuer`; `enroll.rs` is planned for M3 |

### 3.2 Public API sketch

Sans-IO core: all cryptography is synchronous and runtime-free. Async appears only at the `Issuer` boundary and in the optional HTTP client.

M1 provides discovery, identity loading and capture. M2 adds the server APIs below, `VerifiedMessage`, `VerifiedCsr`, envelope encryption/decryption and bounded `Operation::from_request(request, limits)`. All client APIs in the sketch remain planned. Discovery and protocol rejections return `http::Response<Bytes>` directly; infrastructure failures remain typed errors.

```rust
// Shared (scep-protocol)
pub struct Identity { /* private certificate and key; construction validates the pair */ }
pub struct TransactionId(String);            // Nonempty PrintableString; inbound length bounded by Limits
pub struct Nonce([u8; 16]);
pub enum FailInfo { BadAlg, BadMessageCheck, BadRequest, BadTime, BadCertId }
pub struct CaCapabilities { /* set of known keywords; unknown keywords kept as strings */ }

// Server: sans-IO (scep-server)
pub enum KeyBindingPolicy { RequireSameKey, AllowDistinctKeys }
pub struct ServerConfig { pub key_binding: KeyBindingPolicy, pub limits: Limits }
pub struct Responder { /* identity, chain, caps, config */ }
impl Responder {
    pub fn new(identity: Identity, chain: Vec<Certificate>) -> Result<Self, Error>;
    pub fn with_config(identity: Identity, chain: Vec<Certificate>, config: ServerConfig) -> Result<Self, Error>;
    pub fn ca_caps(&self) -> &CaCapabilities;
    pub fn ca_caps_response(&self) -> http::Response<Bytes>;
    pub fn ca_cert_response(&self) -> http::Response<Bytes>;
    pub fn open(&self, pki_message: &[u8]) -> Result<Enrollment, Error>;
    pub fn reply(&self, enrollment: &Enrollment, issuance: Issuance) -> Result<Vec<u8>, Error>;
    pub fn reject(&self, rejected: &Rejected) -> Result<Option<Vec<u8>>, Error>;
}
pub struct Enrollment { /* private, constructed only by Responder::open */ }
impl Enrollment {
    pub fn transaction_id(&self) -> &TransactionId;
    pub fn csr(&self) -> &x509_cert::request::CertReq;
    pub fn challenge(&self) -> Option<&str>;
    pub fn signer(&self) -> &CertificateInner<Raw>;
}
pub struct Rejected { /* private cause, failInfo and optional authenticated header */ }
pub enum Issuance {
    Issued { certificate: Box<Certificate>, chain: Vec<Certificate> },
    Pending,
    Rejected { fail_info: FailInfo, text: Option<String> },
}

// Server: HTTP dispatch on `http` types (framework-agnostic; axum and hyper use them directly)
pub trait Issuer: Sync {
    type Error: std::error::Error + Send + Sync + 'static;
    /// May be called again for the same transaction when the client retries after a lost CertRep;
    /// return the same certificate for an identical CSR.
    fn issue(&self, enrollment: &Enrollment) -> impl Future<Output = Result<Issuance, Self::Error>> + Send;
}
pub async fn handle<I: Issuer>(responder: &Responder, issuer: &I, request: http::Request<Bytes>) -> Result<http::Response<Bytes>, HandleError<I::Error>>;

// Client: sans-IO (scep-client)
pub struct CaChain { pub certificates: Vec<Certificate> }
impl CaChain {
    pub fn parse(content_type: &str, body: &[u8]) -> Result<Self, Error>;
    pub fn verify_fingerprint(&self, sha256: &[u8; 32]) -> Result<(), Error>;
}
pub fn csr(key: &PrivateKey, subject: Name, challenge: Option<&str>, extensions: Vec<Extension>) -> Result<CertReq, Error>;
pub struct Transaction { /* identity (self-signed), csr, recipient, verifier, transaction_id, sender_nonce, algorithms */ }
impl Transaction {
    pub fn new(key: PrivateKey, csr: CertReq, ca: &CaChain, caps: &CaCapabilities) -> Result<Self, Error>;
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
    pub async fn enroll(&self, key: PrivateKey, csr: CertReq, expected_fingerprint: Option<[u8; 32]>) -> Result<Outcome, Error>;
}
```

Design choices:

- The library does not depend on axum. `handle()` works on `http::Request`/`http::Response` so an axum application mounts it with a two-line handler. An `axum` feature with a ready `Router` can be added later if a second consumer wants it.
- `Responder::open` performs cryptographic validation (signature, digest, nonce shape, algorithm allowlist, decrypt, CSR self-signature) and enforces the responder's key-binding policy. Authorization (challenge, subject, duplicate transaction) lives in `Issuer`. This keeps the library free of storage and of any consumer's concepts.
- `Issuer::issue` returns a native `Send` future; implementations may use `async fn`. The bound allows HTTP executors to schedule handlers without boxing. `handle` is generic and requires no dynamic dispatch.
- `Error::Rejected` denotes peer validation failure. RNG and internal RSA failures remain `Error::Protocol`; `HandleError::Issuer` preserves application errors. `reject` returns `Ok(None)` without an authenticated header and propagates response-generation failures instead of swallowing them.
- CMS certificates are a `SET OF`, not an ordered chain. The issuer explicitly identifies the leaf. The responder checks its key against the CSR even if another certificate in the supplied chain has the right key.

#### Key-binding policy

`ServerConfig::key_binding` selects one policy for each responder at construction. `Responder::new` uses `ServerConfig::default()`, whose key-binding policy is `KeyBindingPolicy::RequireSameKey`. A caller must use `Responder::with_config` and explicitly select `KeyBindingPolicy::AllowDistinctKeys` to accept different CSR and CMS signer keys. No Cargo feature, process-global switch, or peer detection changes the policy.

`RequireSameKey` compares the RSA modulus and public exponent, not certificate subjects or encoded certificate bytes. `AllowDistinctKeys` skips only this equality check. Both modes must verify the CMS signature, signed attributes, content digest, envelope, and CSR self-signature. `Responder::open` must enforce the selected policy before returning an `Enrollment`; an `Issuer` cannot bypass the check. The client continues to generate same-key requests.

`scep serve --key-binding` uses the same policy, with its default derived from `ServerConfig`. To accept the captured Apple request, select `--key-binding allow-distinct-keys`; the issuer must still authorize its challenge, subject and key.

[RFC 8894 §2.3](https://www.rfc-editor.org/rfc/rfc8894.html#section-2.3) recommends the same subject and key with SHOULD, not MUST. Apple's [SCEP API](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/sec/Security/SecSCEP.h#L42-L59) accepts separate CSR keys and signer identity; the captured native profile uses different keys. The explicit policy preserves the strict default without treating every distinct-key request as a signature failure.

### 3.3 Message processing

Server, PKCSReq (`Responder::open`):

1. Check `ServerConfig::limits.max_request_bytes` (default 256 KiB) before decoding. HTTP adapters must also bound body collection and raw query bytes before URL/base64 decoding.
2. `ContentInfo::from_ber` → `SignedData<Raw>`; require one signer, one SHA-256 digest algorithm, supported versions and exactly one certificate matching `sid` by issuer/serial or subject key identifier. Local identities retain the strict `Rfc5280` profile.
3. Validate CMS `contentType` and `messageDigest`; hash the original encapsulated octets, not a re-encoded envelope. Reconstruct DER-sorted signed attributes and verify the RSA/SHA-256 signature.
4. Parse the authenticated `transactionID` and 16-byte `senderNonce`; require `messageType == 19`. Reject absent, multivalued, duplicated or mistyped required attributes.
5. Decode the envelope, select its RSA recipient by issuer/serial or subject key identifier, and check CMS versions and algorithm parameters. Use `PrivateKey::pkcs1v15_decrypt_with_rng` with `SysRng`, then AES-CBC decryption with PKCS#7 padding.
6. `CertReq::from_der` on the plaintext; verify the CSR self-signature; apply the configured [key-binding policy](#key-binding-policy); extract `challengePassword` (PKCS#9 `1.2.840.113549.1.9.7`, decoded as `DirectoryString`) into `Zeroizing<String>`.
7. Return an immutable `Enrollment`. Peer failures map to `Error::Rejected`, which can produce a signed FAILURE only after the header has been authenticated and validated. Operational failures remain separate errors.

Server, CertRep (`Responder::reply`): check the explicit leaf against the CSR key, build certificates-only SignedData, and encrypt with `EnvelopedDataBuilder` and `KeyTransRecipientInfoBuilder` to `Enrollment::signer()`. Use AES-128-CBC and sign with the responder identity, with `transactionID`, `messageType = 3`, `pkiStatus`, echoed `recipientNonce`, fresh `senderNonce`, and optional failure information. Never substitute the CSR key for the response recipient. FAILURE and PENDING omit eContent and sign the empty-content digest (RFC 8894 §3.2).

Client, PKCSReq (`Transaction::request`): generate a self-signed certificate with the CSR subject and key, KeyUsage `digitalSignature | keyEncipherment`, short validity, random serial; envelope the CSR for the CA encryption certificate; sign with the CSR key; attributes `transactionID` (random, 32 hex chars), `messageType = 19`, `senderNonce`.

Client, CertRep (`Transaction::cert_rep`): verify the signature with the CA signing certificate from `CaChain`; require `transactionID` equal and `recipientNonce == senderNonce`; map `pkiStatus`; on SUCCESS decrypt with the CSR key, parse certs-only SignedData, identify the issued leaf by its CSR public key, and return it before the remaining certificates. Never infer the leaf from the encoded position.

### 3.4 CLI test issuer

`--challenge-file` explicitly enables issuance. The challenge comparison uses `subtle`; a match authorizes any subject for this test CA. The issuer ignores CSR extension requests and emits an end-entity certificate with digitalSignature/keyEncipherment, SKI and AKI, a random positive serial, and validity capped at the issuing CA's expiry. `--issuer-cert`/`--issuer-key` separate the CA from an RA responder. Without a challenge file, PKIOperation remains capture-only/HTTP 501; capture and issuance modes are mutually exclusive.

The issuer keeps a bounded process-local map from transaction ID to CSR SHA-256 and issued certificate. Concurrent identical retries receive the same certificate. A different CSR under an existing ID receives a policy rejection; a full store is an operational error. Restarting loses the map. Production issuers must provide durable idempotency and authorization instead of relying on this demo. CLI validity and capacity are configurable; `serve --help` is the reference for flags and defaults.

## 4. Dependencies

Use the RustCrypto der-0.8 generation and RSA 0.10 stable. M2 migrates the earlier rc key names to `rsa::{PrivateKey, PublicKey}` and the matching CMS builders. Dependencies are added with `cargo add`; shared requirements are in the workspace manifest.

**Development dependency pins:** the root `[patch.crates-io]` in `Cargo.toml` pins exact revisions from [RustCrypto/formats#2534](https://github.com/RustCrypto/formats/pull/2534) (`der`) and [RustCrypto/formats#2535](https://github.com/RustCrypto/formats/pull/2535) (`cms` and `x509-cert`). Owned `der::Any` assembles BER OCTET STRING fragments correctly, and CMS models/builders propagate `P: Profile = Rfc5280` so peer certificates and identifiers can use `Raw`. The committed lockfile records these Git sources; this checkout and CI need no sibling checkout or local Cargo config. `cargo-deny` permits only this Git repository and requires revision pins. These are PR revisions, not merged or released upstream versions.

Cargo applies patches only from the root workspace. An application consuming the development libraries must copy this repository's `[patch.crates-io]` entries into its own root manifest. A Git dependency on `scep-rs` alone does not inherit the patches.

**Publication gate:** wait for upstream review and crate releases containing both fixes, then update dependency requirements and remove the Git patches. Publish the generic `x509-cert` macro support before the dependent CMS release. Do not publish the current library packages against the unpatched crates.io APIs, substitute local CMS types, or rewrite signed BER bytes.

| Crate | Version | Why |
| --- | --- | --- |
| `cms` | Git-pinned 0.3.0-rc.2, `builder`, `std` | Profile-aware SignedData/EnvelopedData models and builders; outgoing certificates-only CMS |
| `x509-cert` | Git-pinned 0.3.0, `builder`, `hazmat`, `pem` | `Raw` for peer material, strict local certificates, CSR and certificate types/builders |
| `der` | Git-pinned 0.8.3, `alloc`, `oid`, `ber`, `pem` | BER decoding with the owned-Any OCTET STRING fix; DER output and strict CSR parsing |
| `const-oid` | 0.10, `db` | SCEP OIDs from `db::rfc8894`; challengePassword from `db::rfc2985::PKCS_9_AT_CHALLENGE_PASSWORD` |
| `rsa` | 0.10 stable, `pkcs1v15` | Blinded, implicit-rejection key transport; RSA/SHA-256 signing and verification |
| `sha2` 0.11, `aes` 0.9, `cbc` 0.2, `signature` 3 |  | Digest/signature generation and AES-CBC with PKCS#7 padding |
| `rand` 0.10, `getrandom` 0.4 |  | `getrandom::fill` for nonces/serials, `SysRng` for private-key decryption, OS-seeded `StdRng` for CMS/certificate builders |
| `zeroize` 1, `thiserror` 2, `http` 1, `base64` 0.23 |  | Secrets, errors, sans-IO transport types, GET `message=` decoding |
| `subtle` 2 | CLI | Constant-time challenge comparison; also used transitively by RSA arithmetic |
| `reqwest` 0.13 (planned, optional) | feature `reqwest` | M3 async client; TLS backend chosen by the application |

Dev and interop: `tokio`, `axum` (CLI and tests), `hex-literal`, `cargo-fuzz`, the `openssl` CLI for cross-checks, `sscep` (nixpkgs) and micromdm `scepserver` (Go) for interop.

The older der-0.7/CMS generation does not support the required Apple BER path. RSA 0.10 also replaces the vulnerable RSA generation identified by RustSec (§6). CMS remains prerelease; the Git pins permit development builds but do not remove the publication gate above.

## 5. RFC 8894 conformance matrix (v0.1)

| RFC item | Server | Client |
| --- | --- | --- |
| §2.1.2 CA cert KeyUsage digitalSignature + keyEncipherment | `Responder::new` rejects an identity certificate missing either bit when KeyUsage is present | Selects the encryption cert by keyEncipherment and the verifier by digitalSignature; falls back to the single cert |
| §2.3 self-signed cert, same subject and key as CSR | Uses the explicit per-responder [key-binding policy](#key-binding-policy), strict by default; subject authorization belongs to `Issuer` | Always generates with same subject and key |
| §2.4 challengePassword | Exposed to `Issuer`; never logged; `Zeroizing` | Added through `csr()` when provided |
| §3.2 eContentType = id-data; signed attrs present | Enforced | Enforced |
| §3.2.1.1 transactionID PrintableString, unique | Nonempty; configurable maximum length; uniqueness is `Issuer` policy | Random 128-bit hex |
| §3.2.1.2 unknown messageType | `FailInfo::BadRequest` | Error |
| §3.2.1.5 nonces 16 bytes, echo | Echoes senderNonce as recipientNonce, adds fresh senderNonce | Rejects CertRep whose recipientNonce ≠ sent senderNonce |
| §3.3.2.1 SUCCESS reply contains the issued leaf | `Issuance::Issued { certificate, chain }` identifies the leaf explicitly and verifies its CSR key; CMS does not preserve input order | Selects the issued certificate by its CSR key; returns the leaf first at the application boundary |
| §3.4 certs-only SignedData with no content | `ContentInfo::try_from(PkiPath)` | Parses with and without `econtent` |
| §3.5 GetCACaps `text/plain` | Emits exactly `AES`, `POSTPKIOperation`, `SHA-256`, `SCEPStandard` | Ignores Content-Type, case-insensitive keywords, tolerates CRLF |
| §4.1 POST and GET | Both; GET `message=` is base64 (URL-decoded by the HTTP layer) | POST only |
| §4.2 GetCACert content types | `application/x-x509-ca-cert` for one cert, `application/x-x509-ca-ra-cert` for a chain | Parses both; `message=` parameter passed through |
| §4.3 `application/x-pki-message` | Request and response | Request and response |
| §7.5 downgrade | No 3DES/SHA-1 advertised or accepted | Errors when the CA does not advertise `SHA-256` and `AES` (v0.1 has no legacy mode); the error names the missing capability |

## 6. Security requirements

- Bound bytes before ASN.1 decoding and collections before their cryptographic use. `Limits` owns configurable body/query bytes, certificate/attribute/recipient counts and transaction ID length. The ASN.1 decoder caps nesting at 64. HTTP adapters must bound body collection separately.
- Algorithm allowlist, not denylist: `sha256` digest; `rsaEncryption`/`sha256WithRSAEncryption` signatures; `rsaEncryption` (PKCS#1 v1.5) key transport; `aes128/192/256-CBC` content. Anything else → `BadAlg` with no further processing.
- Fail uniformly. Unsupported algorithms/parameters → `BadAlg`; ASN.1, signature, digest, decrypt, padding, CSR proof of possession and configured key-binding failure → `BadMessageCheck`; unsupported message structures, missing/ambiguous attributes and resource limits → `BadRequest`. `failInfoText` is absent for failures detected by `open`; the `Issuer` may set it for policy rejections. RNG, internal RSA and issuer failures remain operational errors, not SCEP failures.
- RSA decryption uses `PrivateKey::pkcs1v15_decrypt_with_rng` with `SysRng`. RustSec marks RSA 0.10 stable as patched for RUSTSEC-2023-0071 (Marvin); M2 removes the earlier advisory exception. Blinding and implicit rejection are required, but this dependency update is not a production security review.
- Preserve the [key-binding policy](#key-binding-policy) contract: `Enrollment` always has verified CMS and CSR signatures, but only `RequireSameKey` binds both signatures to one RSA key. With `AllowDistinctKeys`, the CSR signature does not prove that the CMS signer holds the CSR private key.
- Treat the client's self-signed certificate as transport only: `Enrollment::signer()` is documented as unauthenticated; no API returns its subject as an identity. In both modes, `Issuer` must authorize the requested subject and key and handle transaction replays independently of signature validation.
- Secrets: `challenge` is `Zeroizing<String>`; CEKs come from cms (zeroized after use); the library never logs message contents; `Debug` on `Enrollment` redacts the challenge.
- Capture mode is opt-in, accepts unverified bytes, and cannot issue certificates. Use disposable test identities, and keep raw captures out of application logs. HTTP request logs omit query strings because GET `message` contains the entire pkiMessage.
- The library does not require TLS (RFC 8894 §7.10) and does not validate server certificates itself; `reqwest` does when `https://` is used.
- No `unsafe` (`unsafe_code = "forbid"`), no `unwrap` outside tests except on local invariants with a comment.

## 7. Verification strategy

Current regression tests:

- Protocol unit tests (sibling `tests.rs`): capability parsing, identity pairing, certificates-only CMS, GET/POST mapping and response types. `crates/protocol/tests/capture.rs` preserves the original Apple and sscep bytes through both HTTP transports.
- `tests/enrollment`: public server contracts using captured and re-signed/mutated requests. Covers both policies, CSR/challenge extraction, CMS digest/signature/algorithm checks, required attribute shapes, proof of possession, ambiguous signers, issuer/serial and SKI identifiers, supported AES sizes, envelope versions/parameters, request/query limits, explicit leaf identity, response recipient selection, FAILURE/PENDING, and protocol versus issuer errors.
- CLI issuer tests: concurrent retries return the same leaf at capacity; returned leaf subject/key/issuer/extensions are correct; challenge rejection remains distinct from operational capacity failure.

Future client roundtrips add `Transaction` against `Responder`, altered recipientNonce rejection and returned-leaf selection. These are M3 tests, not evidence for the current server implementation.

Key-binding acceptance (M2, using the pinned upstream fixes):

- A valid same-key request succeeds under both policies, including when the signer subject differs from the CSR subject.
- The same valid distinct-key request is rejected with `BadMessageCheck` by `Responder::new`, `ServerConfig::default()`, and explicit `RequireSameKey`, but yields the expected CSR and challenge with explicit `AllowDistinctKeys`. Exercise both responders in one process and confirm that the strict responder still rejects after the permissive responder accepts. Include the real Apple capture.
- Both policies reject invalid CMS signatures, content digests, and CSR self-signatures. `AllowDistinctKeys` must not bypass an `Issuer` challenge rejection.
- A synthetic distinct-key request produces a certificate containing the CSR key. Only the selected CMS signer's private key, not the CSR private key, can recover the certificate from the encrypted CertRep. The Apple fixture has no exported client keys, so response decryption uses synthetic test keys.

Fixtures (`tests/fixtures/`): one PKCSReq captured from a real macOS client (BER, see M1) and one from `sscep` (DER), each with the responder key that decrypts it and the expected CSR. A micromdm CertRep fixture is planned for M3. These lock in interop with encodings our own code never produces.

M2 manual cross-checks use a running `scep serve` and sscep with default algorithm negotiation, AES-192 and AES-256. OpenSSL independently verifies the CertRep signature, decrypts the envelope, verifies the issued chain and compares the certificate public key with the CSR. Repeating enrollment returns the same leaf; changing the CSR under the same transaction fails. Real HTTP body overflow returns 413.

Planned interop CI (`interop.yml`, M3): run the server checks above and `scep enroll` against micromdm `scepserver` on Linux, with OpenSSL checks of client requests and CSRs. The current CI runs the checks in `devenv.nix` using the committed dependency pins; live sscep/OpenSSL interoperability is not yet automated in CI.

Planned fuzzing (`fuzz.yml`, M4): `Responder::open` with a fixed identity, `CaCapabilities::from_str`, `transport::Operation::try_from`. Seed the corpus from the fixtures.

Apple acceptance (manual, M5): on a Mac, run the test CA with `--key-binding allow-distinct-keys` and a matching challenge file, install a `.mobileconfig` with a `com.apple.security.scep` payload (Challenge, Key Usage 1, RSA 2048) through System Settings, and confirm the issued certificate in the keychain. macOS requires user approval for profile installation. Replaying the captured request is not this acceptance test.

## 8. Tooling and release

- `[workspace.lints]`: `rust.unsafe_code = "forbid"`, `rust.missing_docs = "warn"`, `clippy.all = "warn"`, `clippy.pedantic = "warn"`; crates inherit with `[lints] workspace = true`. Individual pedantic lints are allowed only with a reason, in the workspace table.
- `devenv.nix` is the single definition of the toolchain and checks: `check` runs actionlint, formatting, strict workspace/all-target/all-feature Clippy, docs with `-D warnings`, workspace tests and cargo-deny. `enterTest` runs the same script as CI. There is no `rust-toolchain.toml`. Plain Cargo builds require no Nix or local upstream checkout; published crates inherit `rust-version` from `[workspace.package]`.
- `deny.toml`: license allowlist, `yanked = "deny"`, `wildcards = "deny"`, crates.io and revision-pinned RustCrypto/formats only. Unicode-3.0 is allowed; BSD-3-Clause is scoped to `subtle`, whose copyright/disclaimer must accompany binary redistribution. There is no Marvin advisory ignore.
- Release: `CHANGELOG.md` (Keep a Changelog); publish in dependency order `scep-protocol`, `scep-server`, `scep-client`, `scep`, `scep-cli` with one shared `[workspace.package].version`; Git tags `v0.1.0`. Dual license MIT OR Apache-2.0.

## 9. Milestones (demo-first)

Each milestone ends with something runnable.

| # | Deliverable | Exit criterion |
| --- | --- | --- |
| M0 | Repository bootstrap: workspace with the five crates, lints, CI, README with the planned API, `deny.toml`, devenv shell, this document | `devenv test` and CI green on empty crates; the five crate names reserved on crates.io as `0.0.0` (done 2026-11-07) |
| M1 | `caps`, `certs_only`, `transport`, `Responder::{ca_caps, ca_cert_response}`, `scep serve` answering GetCACaps/GetCACert, plus a capture mode that stores raw PKIOperation bodies | `sscep getca` succeeds against `scep serve`; a real macOS client's PKCSReq captured as a fixture and confirmed to decode with `ContentInfo::from_ber` |
| M2 | `attr`, `pki_message` verify path, `envelope` decrypt path, `Responder::open`, `Responder::reply`, explicit key-binding configuration, static-challenge `Issuer` in the CLI | `sscep enroll` receives a certificate with default settings; the Apple fixture is rejected by the strict default and yields the expected CSR and challenge only with explicit `AllowDistinctKeys`; the policy acceptance checks in §7 pass |
| M3 | Client self-signed identity and CSR generation, `Transaction`, `CaChain`, `Client`, `scep enroll`; reuse M2 signing/encryption | `scep enroll` succeeds against `scep serve` and against micromdm `scepserver`; OpenSSL cross-checks pass |
| M4 | Extend M2 limits/mutation coverage; fuzz targets with 1 h of clean fuzzing, public API docs and dependency audit | CI green including `interop.yml` and `fuzz.yml` |
| M5 | Apple acceptance on a Mac; fixes found there | A macOS device enrolls with a challenge and the certificate appears in the keychain |
| M6 | `0.1.0` released for all five crates | Tags pushed, crates published, CHANGELOG written |

M1 interoperability evidence (2026-11-08): `sscep getca` retrieved the RA and root from the Rust server. A native macOS 27.2 profile installation produced the [Apple BER fixture](../tests/fixtures/apple/README.md); `ContentInfo::from_ber` and BER decoding of the outer `SignedData` succeed. OpenSSL verifies its CMS signature and CSR self-signature, and decryption reproduces the stored CSR. The server returned HTTP 501, so no certificate was issued. GET and POST transport preserve both captured requests byte for byte.

M2 evidence (2026-11-12): sscep enrollment succeeds with default settings and AES-192/AES-256 requests. The Apple capture returns its exact CSR and challenge only under explicit `AllowDistinctKeys`; all strict entry points reject it. Synthetic distinct-key replies contain the CSR leaf but decrypt only with the CMS signer's key. OpenSSL independently verifies the sscep reply and issued chain. This satisfies the local M2 acceptance criteria, not upstream publication or native Apple installation (M5).

Estimate: M0–M4 about three person-weeks, M5 about one week (dominated by Apple interop surprises).

## 10. Risks and decisions

Risks:

- **R1 BER eContent (upstream PR pinned, unreleased).** Owned `der::Any` previously retained OCTET STRING fragment headers instead of concatenating the fragment contents. The upstream patch restores the original encapsulated octets; the real Apple request now passes digest verification and decrypts. The fixture README retains the original minimal reproduction. Publication remains gated on §4.
- **R2 prerelease dependency chain.** CMS profile support is unreleased. Exact PR revisions make this checkout reproducible, but review may require API changes. Downstream workspaces must apply the same root patches; crates.io publication remains blocked until upstream releases incorporate both fixes (§4).
- **R3 Marvin advisory (dependency updated).** RustSec marks RSA 0.10 stable patched. The M1 exception is removed; no independent timing audit has been performed.
- **R4 Apple behaviour not in the RFC.** CA chain selection with `application/x-x509-ca-ra-cert`, retry behaviour on PENDING, fingerprint hash choice. Covered by M5 and by the Apple fixture.
- **R5 sscep serial numbers (upstream PR pinned, unreleased).** The sscep signer certificate and identifier have a 32-byte serial. Upstream CMS profile propagation allows `Raw` peer decoding and response encryption without weakening local certificate validation or copying CMS types. Both policy modes accept the captured request; publication is still gated on §4. See [fixture provenance](../tests/fixtures/sscep/README.md).
- **R6 Apple key binding (implemented and fixture-tested).** The captured macOS 27.2 CMS signer key differs from the CSR key. The [key-binding policy](#key-binding-policy) rejects it by default and accepts it only after explicit opt-in and successful verification. Other Apple versions, profile configurations and actual certificate installation remain untested.

Decisions (initially resolved 2026-11-07; updates dated below):

1. Home of the repository: `AprilNEA/scep-rs`.
2. License: MIT OR Apache-2.0.
3. Dependency generation: der-0.8 rc generation (§4).
4. Server integration surface: sans-IO `Responder` + `handle()` on `http` types, no axum in the library.
5. Key binding (updated 2026-11-08): explicit per-responder configuration, strict by default, no Cargo feature. The policy contract is defined in §3.2.
6. Crate name reservation: all five crates published as `0.0.0` with docs only.
7. Layout: root package `scep` in `src/` as a facade; modules split into `crates/{protocol,server,client,cli}`. Alternative kept on record: the root package could hold the protocol core itself, with `scep-server` and `scep-client` depending on `scep`; that gives users two crate names to import instead of one feature flag.
8. Default outbound content cipher: AES-128-CBC (RFC mandatory).

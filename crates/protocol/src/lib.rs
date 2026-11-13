//! SCEP ([RFC 8894]) wire format, shared by the server and client crates. No I/O.
//!
//! This release covers the unauthenticated half of the protocol: CA
//! capabilities ([`caps`]), certificates-only `SignedData` ([`certs_only`]),
//! the HTTP mapping on [`http`] types ([`transport`]), and the certificate and
//! key pair both roles act with ([`Identity`]). The `pkiMessage` signed and
//! enveloped layers follow in the next release; the design and progress live in
//! the [repository].
//!
//! [RFC 8894]: https://www.rfc-editor.org/rfc/rfc8894
//! [repository]: https://github.com/AprilNEA/scep-rs

pub mod caps;
pub mod certs_only;
mod error;
mod identity;
pub mod transport;

pub use caps::{CaCapabilities, Capability};
pub use error::Error;
pub use identity::Identity;
// The ASN.1 and X.509 types that appear in this crate's API.
pub use rsa;
pub use x509_cert;

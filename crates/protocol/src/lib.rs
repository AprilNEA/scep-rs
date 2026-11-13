//! SCEP ([RFC 8894]) wire format, shared by the server and client crates. No I/O.
//!
//! Includes CA discovery, signed attributes ([`attr`]), CMS signatures
//! ([`pki_message`]), encrypted envelopes ([`envelope`]), PKCS#10 proofs of
//! possession ([`csr`]), and HTTP mapping ([`transport`]). Authentication and
//! certificate policy belong to the caller, not the wire decoder.
//!
//! [RFC 8894]: https://www.rfc-editor.org/rfc/rfc8894
//! [repository]: https://github.com/AprilNEA/scep-rs

pub mod attr;
pub mod caps;
pub mod certs_only;
pub mod csr;
pub mod envelope;
mod error;
mod identity;
mod limits;
pub mod pki_message;
pub mod transport;

pub use attr::{FailInfo, Nonce, TransactionId};
pub use caps::{CaCapabilities, Capability};
pub use error::Error;
pub use identity::Identity;
pub use limits::Limits;
// The ASN.1 and X.509 types that appear in this crate's API.
pub use rsa;
pub use x509_cert;

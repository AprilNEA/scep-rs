//! SCEP ([RFC 8894]) server: a sans-IO [`Responder`] for one CA or RA identity.
//!
//! A [`Responder`] verifies initial enrollment requests and constructs `CertRep`
//! responses. The application-owned [`Issuer`] authorizes the request and
//! obtains a certificate. Key binding is strict unless explicitly configured
//! otherwise; the client certificate is never an authenticated identity.
//!
//! [RFC 8894]: https://www.rfc-editor.org/rfc/rfc8894
//! [repository]: https://github.com/AprilNEA/scep-rs

mod config;
mod enrollment;
mod error;
mod handle;
mod issuer;
mod responder;

pub use config::{KeyBindingPolicy, ServerConfig};
pub use enrollment::{Enrollment, Rejected};
pub use error::Error;
pub use handle::{HandleError, handle};
pub use issuer::{Issuance, Issuer};
pub use responder::Responder;

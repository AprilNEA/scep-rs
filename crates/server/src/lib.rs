//! SCEP ([RFC 8894]) server: a sans-IO [`Responder`] for one CA or RA identity.
//!
//! This release answers the unauthenticated operations, `GetCACaps` and
//! `GetCACert`. The `PKIOperation` handling, an `Issuer` trait for certificate
//! policy, and a `handle()` function on [`http`] types follow in the next
//! release; the design and progress live in the [repository].
//!
//! [RFC 8894]: https://www.rfc-editor.org/rfc/rfc8894
//! [repository]: https://github.com/AprilNEA/scep-rs

mod error;
mod responder;

pub use error::Error;
pub use responder::Responder;

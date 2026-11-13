//! Pure-Rust SCEP ([RFC 8894]) server and client.
//!
//! This crate fronts three crates and selects them with features:
//!
//! - [`protocol`], always present: CMS, CSR verification, capabilities, identity
//!   loading, resource limits and HTTP transport mapping.
//! - [`server`] (feature `server`, default): sans-IO discovery and initial
//!   enrollment, with an application-owned asynchronous issuer boundary.
//! - [`client`] (feature `client`, default): reserved for the enrollment client.
//!
//! Key binding is strict by default; callers may explicitly allow distinct
//! CSR and CMS keys per responder. Verification never replaces authorization.
//! This development checkout pins unreleased upstream ASN.1 patches. The
//! published `0.0.0` packages only reserve the names. The design, dependency
//! release gate and security limitations live in the [repository].
//!
//! [RFC 8894]: https://www.rfc-editor.org/rfc/rfc8894
//! [repository]: https://github.com/AprilNEA/scep-rs

pub use scep_protocol as protocol;
pub use scep_protocol::{
    CaCapabilities, Capability, Error, FailInfo, Identity, Nonce, TransactionId,
};

#[cfg(feature = "client")]
pub use scep_client as client;
#[cfg(feature = "server")]
pub use scep_server as server;

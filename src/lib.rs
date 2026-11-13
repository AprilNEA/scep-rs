//! Pure-Rust SCEP ([RFC 8894]) server and client.
//!
//! This crate fronts three crates and selects them with features:
//!
//! - [`protocol`], always present: capabilities, certificates-only CMS, identity
//!   loading, and HTTP transport mapping.
//! - [`server`] (feature `server`, default): sans-IO discovery responses.
//! - [`client`] (feature `client`, default): reserved for the enrollment client.
//!
//! This checkout implements discovery and request capture, not certificate
//! issuance. The published `0.0.0` packages only reserve the names. The design,
//! security limitations, and progress live in the [repository].
//!
//! [RFC 8894]: https://www.rfc-editor.org/rfc/rfc8894
//! [repository]: https://github.com/AprilNEA/scep-rs

pub use scep_protocol as protocol;
pub use scep_protocol::{CaCapabilities, Capability, Error, Identity};

#[cfg(feature = "client")]
pub use scep_client as client;
#[cfg(feature = "server")]
pub use scep_server as server;

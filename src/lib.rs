//! Pure-Rust SCEP ([RFC 8894]) server and client.
//!
//! This crate fronts three crates and selects them with features:
//!
//! - [`protocol`], always present: the wire format shared by both roles.
//! - [`server`] (feature `server`, default): the sans-IO `Responder` and the
//!   `Issuer` trait.
//! - [`client`] (feature `client`, default): `CaChain`, `Transaction`, and the
//!   `csr()` helper.
//!
//! The first usable release is `0.1.0`; the design and progress live in the
//! [repository].
//!
//! [RFC 8894]: https://www.rfc-editor.org/rfc/rfc8894
//! [repository]: https://github.com/AprilNEA/scep-rs

pub use scep_protocol as protocol;

#[cfg(feature = "client")]
pub use scep_client as client;
#[cfg(feature = "server")]
pub use scep_server as server;

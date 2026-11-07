//! SCEP ([RFC 8894]) server: a sans-IO `Responder` that verifies and decrypts
//! `PKCSReq` messages and builds `CertRep` replies, an `Issuer` trait for
//! certificate policy, and a `handle()` function on `http` types.
//!
//! This release reserves the crate name. It contains no code. The first usable
//! release is `0.1.0`; the design and progress live in the [repository].
//!
//! [RFC 8894]: https://www.rfc-editor.org/rfc/rfc8894
//! [repository]: https://github.com/AprilNEA/scep-rs

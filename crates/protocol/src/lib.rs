//! SCEP ([RFC 8894]) wire format, shared by the server and client crates: signed
//! attributes, CA capabilities, `pkiMessage` signing and verification,
//! `pkcsPKIEnvelope`, certificates-only `SignedData`, and the HTTP mapping on
//! `http` types. No I/O.
//!
//! This release reserves the crate name. It contains no code. The first usable
//! release is `0.1.0`; the design and progress live in the [repository].
//!
//! [RFC 8894]: https://www.rfc-editor.org/rfc/rfc8894
//! [repository]: https://github.com/AprilNEA/scep-rs

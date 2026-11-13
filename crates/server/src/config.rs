//! Per-responder key binding and resource limits.

use scep_protocol::Limits;

/// Whether the two verified signatures must use the same RSA public key.
///
/// Distinct keys do not establish possession of the CSR key by the CMS signer.
/// Both modes require the issuer to authorize the requested subject and key.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, strum::Display, strum::EnumString)]
#[strum(serialize_all = "kebab-case")]
pub enum KeyBindingPolicy {
    /// Require identical RSA modulus and exponent. This is the default.
    #[default]
    RequireSameKey,
    /// Permit distinct keys after independently verifying both signatures.
    AllowDistinctKeys,
}

/// Configuration fixed when a responder is constructed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ServerConfig {
    /// The CSR-to-CMS key binding policy; strict by default.
    pub key_binding: KeyBindingPolicy,
    /// Resource limits shared with the HTTP adapter.
    pub limits: Limits,
}

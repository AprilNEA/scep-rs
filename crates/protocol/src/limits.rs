//! Resource limits shared by the wire decoder and its HTTP adapter.

/// Limits checked before cryptographic operations.
///
/// HTTP adapters must also limit the body while collecting it. The decoder's
/// byte limit cannot prevent an HTTP framework from allocating a larger body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum decoded CMS message size, in bytes.
    pub max_request_bytes: usize,
    /// Maximum raw HTTP query length, checked before form decoding allocates.
    pub max_query_bytes: usize,
    /// Maximum number of certificates in a CMS certificate set.
    pub max_certificates: usize,
    /// Maximum attributes in each CMS or CSR attribute set.
    pub max_attributes: usize,
    /// Maximum transaction ID length, in bytes.
    pub max_transaction_id_bytes: usize,
    /// Maximum recipients in an encrypted envelope.
    pub max_recipients: usize,
}

impl Default for Limits {
    fn default() -> Self {
        let max_request_bytes = 256 * 1024;
        Self {
            max_request_bytes,
            max_query_bytes: 4 * max_request_bytes + 1024,
            max_certificates: 8,
            max_attributes: 32,
            max_transaction_id_bytes: 256,
            max_recipients: 8,
        }
    }
}

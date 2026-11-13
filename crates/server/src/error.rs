//! Server errors.

use scep_protocol::x509_cert::{der, ext::pkix::KeyUsage};

/// Errors from configuring or running a [`Responder`](crate::Responder).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Protocol data failed to decode, encode, or validate.
    #[error(transparent)]
    Protocol(#[from] scep_protocol::Error),

    /// The responder certificate's `keyUsage` extension lacks `digitalSignature`
    /// or `keyEncipherment`. Clients verify signatures and encrypt to this
    /// certificate, so RFC 8894 Section 2.1.2 requires both bits.
    #[error("responder certificate keyUsage {0:?} lacks digitalSignature or keyEncipherment")]
    KeyUsage(KeyUsage),
}

impl From<der::Error> for Error {
    fn from(error: der::Error) -> Self {
        Self::Protocol(error.into())
    }
}

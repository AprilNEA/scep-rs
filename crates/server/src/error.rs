//! Server errors.

use scep_protocol::x509_cert::{der, ext::pkix::KeyUsage};

use crate::Rejected;

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

    /// A peer request failed validation, rather than an operational failure.
    #[error(transparent)]
    Rejected(Rejected),

    /// The issuer returned a leaf for a different public key.
    #[error("issued certificate does not contain the CSR public key")]
    IssuedKeyMismatch,
}

impl Error {
    pub(crate) fn request(
        cause: scep_protocol::Error,
        header: Option<scep_protocol::attr::Header>,
    ) -> Self {
        match cause.fail_info() {
            Some(fail_info) => Self::Rejected(Rejected {
                fail_info,
                cause,
                header,
            }),
            None => Self::Protocol(cause),
        }
    }
}

impl From<der::Error> for Error {
    fn from(error: der::Error) -> Self {
        Self::Protocol(error.into())
    }
}

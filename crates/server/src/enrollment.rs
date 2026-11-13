//! Verified enrollment requests and protocol rejection context.

use std::fmt;

use scep_protocol::{
    FailInfo, TransactionId,
    attr::Header,
    csr::VerifiedCsr,
    x509_cert::{
        certificate::{CertificateInner, Raw},
        request::CertReq,
    },
};

/// An immutable, cryptographically verified `PKCSReq`.
///
/// Only [`Responder::open`](crate::Responder::open) constructs an enrollment.
/// The issuer must still authorize the subject, key and challenge and enforce
/// retry/replay policy. The signer certificate is not an authenticated identity.
pub struct Enrollment {
    pub(crate) header: Header,
    pub(crate) csr: VerifiedCsr,
    pub(crate) signer: CertificateInner<Raw>,
}

impl Enrollment {
    /// The verified transaction ID. It is not proof of client identity.
    #[must_use]
    pub fn transaction_id(&self) -> &TransactionId {
        self.header.transaction_id()
    }

    /// The CSR whose proof of possession was verified.
    #[must_use]
    pub fn csr(&self) -> &CertReq {
        self.csr.request()
    }

    /// The challenge, if present. Never log this value or the CSR contents.
    #[must_use]
    pub fn challenge(&self) -> Option<&str> {
        self.csr.challenge()
    }

    /// The untrusted transport certificate selected by the CMS signer ID.
    ///
    /// `CertRep` encryption always uses this key, even when the CSR key differs.
    #[must_use]
    pub fn signer(&self) -> &CertificateInner<Raw> {
        &self.signer
    }
}

impl fmt::Debug for Enrollment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Enrollment")
            .field("transaction_id", self.transaction_id())
            .finish_non_exhaustive()
    }
}

/// An invalid request, optionally with authenticated transaction context.
///
/// Only the responder constructs this value. A parsed but unverified header is
/// never retained. Use [`Responder::reject`](crate::Responder::reject) to build
/// a FAILURE response when authenticated context is available.
#[derive(Debug, thiserror::Error)]
#[error("request rejected: {cause}")]
pub struct Rejected {
    pub(crate) fail_info: FailInfo,
    #[source]
    pub(crate) cause: scep_protocol::Error,
    pub(crate) header: Option<Header>,
}

impl Rejected {
    /// The uniform SCEP failure code; no detailed validation error is disclosed.
    #[must_use]
    pub fn fail_info(&self) -> FailInfo {
        self.fail_info
    }

    /// The local diagnostic cause, not a response body.
    #[must_use]
    pub fn cause(&self) -> &scep_protocol::Error {
        &self.cause
    }
}

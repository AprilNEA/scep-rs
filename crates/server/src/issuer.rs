//! The application-owned authorization and certificate issuance boundary.

use std::future::Future;

use scep_protocol::{FailInfo, x509_cert::Certificate};

use crate::Enrollment;

/// The issuer's decision for a verified enrollment.
pub enum Issuance {
    /// An explicitly identified leaf and its issuing chain.
    ///
    /// The leaf must contain the CSR key. CMS encodes an unordered certificate
    /// set; input order does not identify the leaf on the wire.
    Issued {
        /// The issued end-entity certificate.
        certificate: Box<Certificate>,
        /// Certificates needed to validate the issued leaf.
        chain: Vec<Certificate>,
    },
    /// Encode a PENDING response. Storage and polling are not provided.
    Pending,
    /// An authorization or policy rejection, not an operational failure.
    Rejected {
        /// The SCEP failure code.
        fail_info: FailInfo,
        /// Optional human-readable information safe to disclose to the peer.
        text: Option<String>,
    },
}

/// Authorizes a CSR and obtains a certificate from the application's CA.
///
/// Authorize the subject, extensions, key and challenge independently of CMS
/// verification. For a retry of the same transaction and CSR, return the same
/// certificate. Reject transaction IDs reused with a different CSR. Implement
/// these rules in application-owned storage; the protocol library has none.
pub trait Issuer: Sync {
    /// Operational errors, such as unavailable CA or storage services.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Returns an issuance decision or an operational failure.
    ///
    /// Implementations may use `async fn`; the returned future must be `Send`
    /// so HTTP frameworks can run a handler on their executor.
    fn issue(
        &self,
        enrollment: &Enrollment,
    ) -> impl Future<Output = Result<Issuance, Self::Error>> + Send;
}

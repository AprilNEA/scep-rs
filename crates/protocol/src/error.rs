//! Protocol errors.

use der::asn1::ObjectIdentifier;

/// Errors from decoding, encoding, or validating SCEP protocol data.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// ASN.1 or PEM encoding or decoding failed.
    #[error("ASN.1: {0}")]
    Asn1(#[from] der::Error),

    /// A PEM block has a label this operation does not accept.
    #[error("PEM label {label:?} is not one of {expected:?}")]
    PemLabel {
        /// The label found in the PEM encapsulation boundary.
        label: String,
        /// The labels the operation accepts.
        expected: &'static [&'static str],
    },

    /// A PKCS#8 private key could not be decoded.
    #[error("PKCS#8 key: {0}")]
    Pkcs8(#[from] rsa::pkcs8::Error),

    /// A PKCS#1 RSA key could not be decoded.
    #[error("PKCS#1 key: {0}")]
    Pkcs1(#[from] rsa::pkcs1::Error),

    /// A certificate's public key is not RSA or could not be decoded.
    #[error("certificate public key: {0}")]
    PublicKey(#[from] rsa::pkcs8::spki::Error),

    /// The certificate's public key does not match the private key.
    #[error("certificate public key does not match the private key")]
    KeyMismatch,

    /// The request has no `operation` query parameter.
    #[error("missing `operation` query parameter")]
    MissingOperation,

    /// The `operation` query parameter is not a SCEP operation.
    #[error("unknown SCEP operation {0:?}")]
    UnknownOperation(String),

    /// A `PKIOperation` GET request has no `message` query parameter.
    #[error("PKIOperation GET request without `message`")]
    MissingMessage,

    /// A `PKIOperation` request uses a method other than GET or POST.
    #[error("PKIOperation over {0} is not defined; use GET or POST")]
    UnsupportedMethod(http::Method),

    /// The `message` query parameter is not base64.
    #[error("`message` is not base64: {0}")]
    Base64(#[from] base64::DecodeError),

    /// A CMS `ContentInfo` carries a content type other than `SignedData`.
    #[error("CMS content type {0} is not SignedData")]
    NotSignedData(ObjectIdentifier),

    /// A CMS certificate set holds a certificate that is not an X.509 certificate.
    #[error("CMS certificate set holds a non-X.509 certificate")]
    UnsupportedCertificate,
}

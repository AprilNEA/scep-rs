//! Protocol errors.

use der::asn1::ObjectIdentifier;

use crate::FailInfo;

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

    /// The message exceeds the configured byte limit.
    #[error("message exceeds the configured byte limit")]
    MessageTooLarge,

    /// A decoded collection or field exceeds its configured limit.
    #[error("{0} exceeds its configured limit")]
    Limit(&'static str),

    /// A required signed attribute is absent.
    #[error("missing attribute {0}")]
    MissingAttribute(ObjectIdentifier),

    /// An attribute is duplicated, multivalued, mistyped or has an invalid value.
    #[error("invalid attribute {0}")]
    InvalidAttribute(ObjectIdentifier),

    /// The message is not a supported SCEP operation or CMS structure.
    #[error("invalid message: {0}")]
    InvalidMessage(&'static str),

    /// An algorithm or its parameters is outside the supported suite.
    #[error("unsupported algorithm or parameters: {0}")]
    Algorithm(ObjectIdentifier),

    /// A message integrity check failed.
    #[error("message integrity: {0}")]
    Integrity(&'static str),

    /// The configured policy requires one key for both proofs of possession.
    #[error("CSR key differs from the CMS signer key")]
    KeyBinding,

    /// An RSA operation failed. RNG and internal errors are operational errors.
    #[error("RSA: {0}")]
    Rsa(#[from] rsa::Error),

    /// A CMS or CSR signature is invalid.
    #[error("signature: {0}")]
    Signature(#[from] signature::Error),

    /// The content encryption key or initialization vector has the wrong size.
    #[error("AES key or IV length: {0}")]
    CipherLength(#[from] cbc::cipher::InvalidLength),

    /// The ciphertext has invalid PKCS#7 padding.
    #[error("AES padding: {0}")]
    Padding(#[from] cbc::cipher::block_padding::Error),

    /// Operating system randomness is unavailable.
    #[error("randomness: {0}")]
    Random(#[from] getrandom::Error),

    /// Construction of an outgoing CMS message failed.
    #[error("CMS builder: {0}")]
    CmsBuilder(#[from] cms::builder::Error),
}

impl Error {
    /// The uniform wire failure code for an invalid request.
    ///
    /// `None` denotes an operational failure, which must not be disguised as a
    /// client error or sent as a signed SCEP rejection.
    #[must_use]
    pub fn fail_info(&self) -> Option<FailInfo> {
        match self {
            Self::Random(_)
            | Self::CmsBuilder(_)
            | Self::Rsa(rsa::Error::Rng | rsa::Error::Internal) => None,
            Self::Algorithm(_) => Some(FailInfo::BadAlg),
            Self::Asn1(_)
            | Self::PublicKey(_)
            | Self::Pkcs1(_)
            | Self::Pkcs8(_)
            | Self::KeyMismatch
            | Self::Integrity(_)
            | Self::KeyBinding
            | Self::Rsa(_)
            | Self::Signature(_)
            | Self::CipherLength(_)
            | Self::Padding(_) => Some(FailInfo::BadMessageCheck),
            _ => Some(FailInfo::BadRequest),
        }
    }
}

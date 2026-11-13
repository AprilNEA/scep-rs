//! Degenerate certificates-only `SignedData` ([RFC 8894 §3.4]): the body of a
//! `GetCACert` chain response and the payload of a `CertRep`.
//!
//! [RFC 8894 §3.4]: https://www.rfc-editor.org/rfc/rfc8894#section-3.4

use cms::{cert::CertificateChoices, content_info::ContentInfo, signed_data::SignedData};
use const_oid::db::rfc5911::ID_SIGNED_DATA;
use der::{Decode as _, Encode as _, EncodingRules};
use x509_cert::Certificate;

use crate::error::Error;

#[cfg(test)]
mod tests;

/// Encodes `certificates` as a certificates-only `SignedData` in DER.
///
/// CMS stores certificates in a `SET OF`, which DER sorts by encoding, so the
/// output does not preserve the order of `certificates`. A reader that needs
/// a particular certificate must select it by content, for example by public
/// key or by subject, and never by position.
///
/// # Errors
///
/// Returns an error if a certificate cannot be re-encoded.
pub fn encode(certificates: Vec<Certificate>) -> Result<Vec<u8>, Error> {
    Ok(ContentInfo::try_from(certificates)?.to_der()?)
}

/// Decodes a certificates-only `SignedData` and returns its X.509 certificates
/// in encoded order.
///
/// Accepts BER as well as DER, because some clients, notably Apple's, emit
/// indefinite-length encodings. Signer infos are not verified: a degenerate
/// `SignedData` has none, and callers that need an authenticated chain must
/// obtain trust elsewhere ([RFC 8894 §2.2]).
///
/// # Errors
///
/// Returns an error if `bytes` is not a CMS `SignedData` or if the certificate
/// set holds a certificate that is not an X.509 certificate.
///
/// [RFC 8894 §2.2]: https://www.rfc-editor.org/rfc/rfc8894#section-2.2
pub fn decode(bytes: &[u8]) -> Result<Vec<Certificate>, Error> {
    let content_info = ContentInfo::from_ber(bytes)?;
    if content_info.content_type != ID_SIGNED_DATA {
        return Err(Error::NotSignedData(content_info.content_type));
    }
    let signed_data: SignedData = content_info
        .content
        .decode_as_encoding(EncodingRules::Ber)?;
    signed_data
        .certificates
        .map(|set| set.0.into_vec())
        .unwrap_or_default()
        .into_iter()
        .map(|choice| match choice {
            CertificateChoices::Certificate(certificate) => Ok(certificate),
            CertificateChoices::Other(_) => Err(Error::UnsupportedCertificate),
        })
        .collect()
}

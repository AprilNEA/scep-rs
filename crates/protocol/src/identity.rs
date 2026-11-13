//! The certificate and RSA private key a SCEP party signs and decrypts with.

use std::fmt;

use der::{SecretDocument, pem::PemLabel as _};
use pkcs1::{DecodeRsaPrivateKey as _, RsaPrivateKeyRef};
use pkcs8::{DecodePrivateKey as _, DecodePublicKey as _, PrivateKeyInfoRef};
use rsa::{RsaPrivateKey, RsaPublicKey};
use x509_cert::{Certificate, der::DecodePem as _, der::Encode as _};

use crate::error::Error;

#[cfg(test)]
mod tests;

/// A certificate paired with the RSA private key it certifies.
///
/// Construction checks that the certificate's public key is the public key of
/// `key`, so a message signed or decrypted with an `Identity` always matches
/// the certificate the peer sees. The role-specific requirements, such as the
/// key usage bits a CA certificate needs, are checked by the server and client
/// crates.
#[derive(Clone)]
pub struct Identity {
    certificate: Certificate,
    key: RsaPrivateKey,
}

impl Identity {
    /// Pairs `certificate` with `key`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PublicKey`] if the certificate's public key is not an
    /// RSA key and [`Error::KeyMismatch`] if it is not the public key of `key`.
    pub fn new(certificate: Certificate, key: RsaPrivateKey) -> Result<Self, Error> {
        let spki = certificate
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()?;
        let certified = RsaPublicKey::from_public_key_der(&spki)?;
        if certified != key.to_public_key() {
            return Err(Error::KeyMismatch);
        }
        Ok(Self { certificate, key })
    }

    /// Pairs a PEM `CERTIFICATE` with a PEM private key in PKCS#8
    /// (`PRIVATE KEY`) or PKCS#1 (`RSA PRIVATE KEY`) form.
    ///
    /// # Errors
    ///
    /// Returns an error if either input is not PEM, if the key block has
    /// another label, such as an encrypted key, or if the pair fails the checks
    /// of [`Identity::new`].
    pub fn from_pem(certificate: &str, key: &str) -> Result<Self, Error> {
        let certificate = Certificate::from_pem(certificate)?;
        let (label, document) = SecretDocument::from_pem(key)?;
        let key = match label {
            PrivateKeyInfoRef::PEM_LABEL => RsaPrivateKey::from_pkcs8_der(document.as_bytes())?,
            RsaPrivateKeyRef::PEM_LABEL => RsaPrivateKey::from_pkcs1_der(document.as_bytes())?,
            _ => {
                return Err(Error::PemLabel {
                    label: label.to_owned(),
                    expected: &[PrivateKeyInfoRef::PEM_LABEL, RsaPrivateKeyRef::PEM_LABEL],
                });
            }
        };
        Self::new(certificate, key)
    }

    /// The certificate.
    #[must_use]
    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    /// The private key.
    #[must_use]
    pub fn key(&self) -> &RsaPrivateKey {
        &self.key
    }
}

impl fmt::Debug for Identity {
    /// Shows the certificate subject and omits the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field(
                "subject",
                &self.certificate.tbs_certificate().subject().to_string(),
            )
            .finish_non_exhaustive()
    }
}

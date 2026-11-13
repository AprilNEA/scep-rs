//! PKCS#10 proof of possession and challenge extraction.

use const_oid::db::{rfc2985::PKCS_9_AT_CHALLENGE_PASSWORD, rfc5912::SHA_256_WITH_RSA_ENCRYPTION};
use der::{Decode as _, Encode as _};
use rsa::{
    PublicKey,
    pkcs1v15::{Signature, VerifyingKey},
    pkcs8::DecodePublicKey as _,
};
use sha2::Sha256;
use signature::Verifier as _;
use x509_cert::{ext::pkix::name::DirectoryString, request::CertReq};
use zeroize::Zeroizing;

use crate::{Error, Limits, attr, pki_message::check_algorithm};

/// A DER request whose signature proves possession of the requested RSA key.
///
/// This is not authorization to issue a certificate. The issuer must authorize
/// the challenge, requested subject, extensions and public key independently.
pub struct VerifiedCsr {
    request: CertReq,
    public_key: PublicKey,
    challenge: Option<Zeroizing<String>>,
}

impl VerifiedCsr {
    /// Verifies the request's signature and extracts its optional challenge.
    ///
    /// # Errors
    /// Rejects invalid DER, unsupported algorithms, invalid proofs of
    /// possession, oversized attribute sets, and ambiguous challenges.
    pub fn verify(bytes: &[u8], limits: &Limits) -> Result<Self, Error> {
        if bytes.len() > limits.max_request_bytes {
            return Err(Error::MessageTooLarge);
        }
        let request = CertReq::from_der(bytes)?;
        if request.info.attributes.len() > limits.max_attributes {
            return Err(Error::Limit("CSR attributes"));
        }
        check_algorithm(&request.algorithm, &[SHA_256_WITH_RSA_ENCRYPTION])?;
        let public_key = PublicKey::from_public_key_der(&request.info.public_key.to_der()?)?;
        let signature = request
            .signature
            .as_bytes()
            .ok_or(Error::Integrity("CSR signature bit alignment"))?;
        VerifyingKey::<Sha256>::new(public_key.clone())
            .verify(&request.info.to_der()?, &Signature::try_from(signature)?)?;
        let challenge = attr::optional(&request.info.attributes, PKCS_9_AT_CHALLENGE_PASSWORD)?
            .map(|value| {
                value
                    .decode_as::<DirectoryString>()
                    .map(|value| Zeroizing::new(value.value().into_owned()))
            })
            .transpose()?;
        Ok(Self {
            request,
            public_key,
            challenge,
        })
    }

    /// The verified CSR. Its fields cannot be mutated through this reference.
    #[must_use]
    pub fn request(&self) -> &CertReq {
        &self.request
    }

    /// The RSA key whose proof of possession was verified.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Whether an issued certificate contains this request's RSA key.
    ///
    /// Compares modulus and exponent, not SPKI parameter encoding.
    ///
    /// # Errors
    /// Returns an error if the certificate does not contain a valid RSA key.
    pub fn matches_certificate(&self, certificate: &x509_cert::Certificate) -> Result<bool, Error> {
        let key = PublicKey::from_public_key_der(
            &certificate
                .tbs_certificate()
                .subject_public_key_info()
                .to_der()?,
        )?;
        Ok(key == self.public_key)
    }

    /// The challenge, if present. Never log this value or the raw CSR.
    #[must_use]
    pub fn challenge(&self) -> Option<&str> {
        self.challenge.as_ref().map(|value| value.as_str())
    }
}

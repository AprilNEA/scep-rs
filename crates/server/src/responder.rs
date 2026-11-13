//! The server side of SCEP for one CA or RA identity.

use bytes::Bytes;
use http::{HeaderValue, Response};
use scep_protocol::{
    CaCapabilities, Identity,
    attr::{self, Header, MessageType, PkiStatus},
    certs_only,
    csr::VerifiedCsr,
    envelope,
    pki_message::{self, VerifiedMessage},
    transport,
    x509_cert::{Certificate, der::Encode as _, ext::pkix::KeyUsage},
};

use crate::{Enrollment, Error, Issuance, KeyBindingPolicy, Rejected, ServerConfig};

#[cfg(test)]
mod tests;

/// Answers SCEP operations for one CA or RA identity.
///
/// A `Responder` holds the certificate and key the server acts with, the
/// certificates clients need to validate it, and the capabilities it
/// advertises. It performs no I/O: the caller maps each HTTP request to a
/// [`transport::Operation`] and sends back the [`Response`] the responder
/// returns.
#[derive(Debug)]
pub struct Responder {
    identity: Identity,
    caps: CaCapabilities,
    ca_cert: (HeaderValue, Bytes),
    config: ServerConfig,
}

impl Responder {
    /// Creates a responder acting as `identity`.
    ///
    /// `chain` holds the certificates that issued `identity`, nearest issuer
    /// first, up to and including the root; clients receive them with the
    /// identity certificate in `GetCACert` responses. Pass an empty `chain`
    /// when `identity` is the CA itself.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyUsage`] if the identity certificate has a `keyUsage`
    /// extension without both `digitalSignature` and `keyEncipherment`, and
    /// [`Error::Protocol`] if the `GetCACert` response cannot be encoded.
    pub fn new(identity: Identity, chain: Vec<Certificate>) -> Result<Self, Error> {
        Self::with_config(identity, chain, ServerConfig::default())
    }

    /// Creates a responder with an explicit key-binding policy and limits.
    ///
    /// `chain` has the same meaning as in [`Self::new`]. The responder identity
    /// is for communication and need not hold the issuer's CA private key.
    ///
    /// # Errors
    /// Returns the errors of [`Self::new`], including excess certificates.
    pub fn with_config(
        identity: Identity,
        chain: Vec<Certificate>,
        config: ServerConfig,
    ) -> Result<Self, Error> {
        if chain.len() >= config.limits.max_certificates {
            return Err(scep_protocol::Error::Limit("responder certificates").into());
        }
        let certificate = identity.certificate();
        if let Some((_, usage)) = certificate.tbs_certificate().get_extension::<KeyUsage>()? {
            if !(usage.digital_signature() && usage.key_encipherment()) {
                return Err(Error::KeyUsage(usage));
            }
        }
        let ca_cert = if chain.is_empty() {
            (transport::CA_CERT, Bytes::from(certificate.to_der()?))
        } else {
            let mut certificates = Vec::with_capacity(chain.len() + 1);
            certificates.push(certificate.clone());
            certificates.extend(chain);
            let signed_data = certs_only::encode(certificates)?;
            (transport::CA_RA_CERT, Bytes::from(signed_data))
        };
        Ok(Self {
            identity,
            caps: CaCapabilities::standard(),
            ca_cert,
            config,
        })
    }

    /// The immutable policy and resource limits used by this responder.
    #[must_use]
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// The certificate and key this responder acts with.
    #[must_use]
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// The capabilities advertised in `GetCACaps` responses.
    #[must_use]
    pub fn ca_caps(&self) -> &CaCapabilities {
        &self.caps
    }

    /// The `GetCACaps` response (RFC 8894 Section 3.5.2).
    #[must_use]
    pub fn ca_caps_response(&self) -> Response<Bytes> {
        transport::ca_caps_response(&self.caps)
    }

    /// The `GetCACert` response (RFC 8894 Section 4.2.1).
    ///
    /// Without a chain, the body is the identity certificate as DER with
    /// `application/x-x509-ca-cert`. With a chain, the body is a
    /// certificates-only `SignedData` holding the identity certificate and the
    /// chain with `application/x-x509-ca-ra-cert`; clients select the
    /// responder's certificate from the set by content, not by position.
    #[must_use]
    pub fn ca_cert_response(&self) -> Response<Bytes> {
        let (content_type, body) = &self.ca_cert;
        transport::ok(content_type.clone(), body.clone())
    }

    /// Verifies, decrypts and validates an initial enrollment request.
    ///
    /// Signature validation is not authorization. Only an [`Issuer`](crate::Issuer)
    /// may decide whether the verified CSR should receive a certificate.
    ///
    /// # Errors
    /// Returns [`Error::Rejected`] for peer errors. Only authenticated CMS
    /// context is retained for [`Self::reject`]. Operational failures, including
    /// unavailable randomness, remain separate [`Error::Protocol`] errors.
    pub fn open(&self, pki_message: &[u8]) -> Result<Enrollment, Error> {
        let limits = &self.config.limits;
        let signed = VerifiedMessage::verify(pki_message, limits)
            .map_err(|cause| Error::request(cause, None))?;
        let header = Header::from_attributes(signed.attributes(), limits)
            .map_err(|cause| Error::request(cause, None))?;
        let csr = (|| {
            if attr::message_type(signed.attributes())? != MessageType::PkcsReq {
                return Err(scep_protocol::Error::InvalidMessage("expected PKCSReq"));
            }
            let content = signed
                .content()
                .ok_or(scep_protocol::Error::InvalidMessage(
                    "missing PKCSReq envelope",
                ))?;
            let plaintext = envelope::decrypt(
                content,
                self.identity.certificate(),
                self.identity.key(),
                limits,
            )?;
            let csr = VerifiedCsr::verify(&plaintext, limits)?;
            if self.config.key_binding == KeyBindingPolicy::RequireSameKey
                && csr.public_key() != signed.public_key()
            {
                return Err(scep_protocol::Error::KeyBinding);
            }
            Ok(csr)
        })()
        .map_err(|cause| Error::request(cause, Some(header.clone())))?;
        Ok(Enrollment {
            header,
            csr,
            signer: signed.signer().clone(),
        })
    }

    /// Encodes the issuer's decision as a signed DER `CertRep`.
    ///
    /// SUCCESS encrypts the certificate set to the verified CMS signer, never
    /// to a different CSR key. FAILURE and PENDING have no envelope.
    ///
    /// # Errors
    /// Rejects an issued leaf with a different key or an oversized certificate
    /// set. Encoding, randomness and cryptographic failures propagate.
    pub fn reply(&self, enrollment: &Enrollment, issuance: Issuance) -> Result<Vec<u8>, Error> {
        let (attributes, content) = match issuance {
            Issuance::Issued { certificate, chain } => {
                if chain.len() >= self.config.limits.max_certificates {
                    return Err(scep_protocol::Error::Limit("issued certificates").into());
                }
                if !enrollment.csr.matches_certificate(&certificate)? {
                    return Err(Error::IssuedKeyMismatch);
                }
                let mut certificates = Vec::with_capacity(chain.len() + 1);
                certificates.push(*certificate);
                certificates.extend(chain);
                let content =
                    envelope::encrypt(&certs_only::encode(certificates)?, enrollment.signer())?;
                (
                    enrollment
                        .header
                        .reply_attributes(PkiStatus::Success, None)?,
                    Some(content),
                )
            }
            Issuance::Pending => (
                enrollment
                    .header
                    .reply_attributes(PkiStatus::Pending, None)?,
                None,
            ),
            Issuance::Rejected { fail_info, text } => (
                enrollment
                    .header
                    .reply_attributes(PkiStatus::Failure, Some((fail_info, text.as_deref())))?,
                None,
            ),
        };
        Ok(pki_message::sign(
            &self.identity,
            attributes,
            content.as_deref(),
        )?)
    }

    /// Builds a signed FAILURE only when the rejection has verified context.
    ///
    /// `Ok(None)` means no safe transaction ID and nonce were available; the
    /// HTTP adapter should reject the request without a SCEP response. Detailed
    /// validation errors are not included in the `CertRep`.
    ///
    /// # Errors
    /// Returns encoding, randomness or signing failures; never silently drops
    /// an error while attempting to construct a response.
    pub fn reject(&self, rejected: &Rejected) -> Result<Option<Vec<u8>>, Error> {
        rejected
            .header
            .as_ref()
            .map(|header| {
                let attributes = header
                    .reply_attributes(PkiStatus::Failure, Some((rejected.fail_info(), None)))?;
                Ok(pki_message::sign(&self.identity, attributes, None)?)
            })
            .transpose()
    }
}

//! The server side of SCEP for one CA or RA identity.

use bytes::Bytes;
use http::{HeaderValue, Response};
use scep_protocol::{
    CaCapabilities, Identity, certs_only, transport,
    x509_cert::{Certificate, der::Encode as _, ext::pkix::KeyUsage},
};

use crate::error::Error;

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
        })
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
}

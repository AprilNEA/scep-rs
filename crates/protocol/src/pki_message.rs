//! CMS signatures over SCEP attributes and the original encapsulated octets.

use cms::{
    builder::{SignedDataBuilder, SignerInfoBuilder},
    cert::{CertificateChoices, IssuerAndSerialNumber},
    content_info::{CmsVersion, ContentInfo},
    signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier},
};
use const_oid::{
    ObjectIdentifier,
    db::{
        rfc5911::{ID_CONTENT_TYPE, ID_DATA, ID_MESSAGE_DIGEST, ID_SIGNED_DATA},
        rfc5912::{ID_SHA_256, RSA_ENCRYPTION, SHA_256_WITH_RSA_ENCRYPTION},
    },
};
use der::{
    Any, Decode as _, Encode as _, EncodingRules,
    asn1::{Null, OctetString, SetOfVec},
};
use rand::{
    SeedableRng as _,
    rngs::{StdRng, SysRng},
};
use rsa::{
    PublicKey,
    pkcs1v15::{Signature, SigningKey, VerifyingKey},
    pkcs8::DecodePublicKey as _,
};
use sha2::{Digest as _, Sha256};
use signature::Verifier as _;
use x509_cert::{
    attr::Attributes,
    certificate::{CertificateInner, Raw},
    ext::pkix::SubjectKeyIdentifier,
    spki::AlgorithmIdentifierOwned,
};

use crate::{Error, Identity, Limits, attr};

/// A message with a verified CMS signature and content digest.
///
/// The signer certificate is untrusted transport material. This type proves
/// possession of its key, not the signer's identity or authorization.
pub struct VerifiedMessage {
    signer: CertificateInner<Raw>,
    public_key: PublicKey,
    attributes: Attributes,
    content: Option<OctetString>,
}

impl VerifiedMessage {
    /// Verifies a BER or DER message, without normalizing the content bytes.
    ///
    /// # Errors
    /// Rejects excess resources, ambiguous signer selection, unsupported
    /// algorithms, malformed signed attributes, and invalid signatures/digests.
    pub fn verify(bytes: &[u8], limits: &Limits) -> Result<Self, Error> {
        if bytes.len() > limits.max_request_bytes {
            return Err(Error::MessageTooLarge);
        }
        let info = ContentInfo::from_ber(bytes)?;
        if info.content_type != ID_SIGNED_DATA {
            return Err(Error::NotSignedData(info.content_type));
        }
        let data: SignedData<Raw> = info.content.decode_as_encoding(EncodingRules::Ber)?;
        let [signer_info] = <[_; 1]>::try_from(data.signer_infos.0.into_vec())
            .map_err(|_| Error::InvalidMessage("expected exactly one SignerInfo"))?;
        check_algorithm(&signer_info.digest_alg, &[ID_SHA_256])?;
        check_algorithm(
            &signer_info.signature_algorithm,
            &[RSA_ENCRYPTION, SHA_256_WITH_RSA_ENCRYPTION],
        )?;
        let [digest_algorithm] = data.digest_algorithms.as_slice() else {
            return Err(Error::InvalidMessage(
                "expected exactly one digest algorithm",
            ));
        };
        check_algorithm(digest_algorithm, &[ID_SHA_256])?;
        let version = match &signer_info.sid {
            SignerIdentifier::IssuerAndSerialNumber(_) => CmsVersion::V1,
            SignerIdentifier::SubjectKeyIdentifier(_) => CmsVersion::V3,
        };
        if signer_info.version != version || data.version != version || data.crls.is_some() {
            return Err(Error::InvalidMessage("unsupported SignedData structure"));
        }
        let certificates = data
            .certificates
            .ok_or(Error::InvalidMessage("missing signer certificate"))?;
        if certificates.0.len() > limits.max_certificates {
            return Err(Error::Limit("certificates"));
        }
        let mut signer = None;
        for choice in certificates.0.into_vec() {
            let CertificateChoices::Certificate(certificate) = choice else {
                return Err(Error::UnsupportedCertificate);
            };
            let tbs = certificate.tbs_certificate();
            let matches = match &signer_info.sid {
                SignerIdentifier::IssuerAndSerialNumber(id) => {
                    id.issuer == *tbs.issuer() && id.serial_number == *tbs.serial_number()
                }
                SignerIdentifier::SubjectKeyIdentifier(id) => tbs
                    .get_extension::<SubjectKeyIdentifier>()?
                    .is_some_and(|(_, ski)| ski == *id),
            };
            if matches && signer.replace(certificate).is_some() {
                return Err(Error::InvalidMessage("ambiguous signer certificate"));
            }
        }
        let signer = signer.ok_or(Error::InvalidMessage("signer certificate not found"))?;
        let attributes = signer_info
            .signed_attrs
            .ok_or(Error::InvalidMessage("missing signed attributes"))?;
        if attributes.len() > limits.max_attributes
            || signer_info
                .unsigned_attrs
                .as_ref()
                .is_some_and(|attrs| attrs.len() > limits.max_attributes)
        {
            return Err(Error::Limit("CMS attributes"));
        }
        let mut attributes = attributes.into_vec();
        for attribute in &mut attributes {
            let values = std::mem::take(&mut attribute.values);
            attribute.values = SetOfVec::try_from(values.into_vec())?;
        }
        let attributes = Attributes::try_from(attributes)?;
        if data.encap_content_info.econtent_type != ID_DATA
            || attr::required(&attributes, ID_CONTENT_TYPE)?.decode_as::<ObjectIdentifier>()?
                != ID_DATA
        {
            return Err(Error::InvalidMessage("content type is not id-data"));
        }
        let content = data
            .encap_content_info
            .econtent
            .map(|content| content.decode_as::<OctetString>())
            .transpose()?;
        let digest = attr::required(&attributes, ID_MESSAGE_DIGEST)?.decode_as::<OctetString>()?;
        if digest.as_bytes()
            != Sha256::digest(content.as_ref().map_or(&[][..], OctetString::as_bytes)).as_slice()
        {
            return Err(Error::Integrity("content digest"));
        }
        let spki = signer.tbs_certificate().subject_public_key_info();
        let public_key = PublicKey::from_public_key_der(&spki.to_der()?)?;
        VerifyingKey::<Sha256>::new(public_key.clone()).verify(
            &attributes.to_der()?,
            &Signature::try_from(signer_info.signature.as_bytes())?,
        )?;
        Ok(Self {
            signer,
            public_key,
            attributes,
            content,
        })
    }

    /// The certificate selected by the CMS signer identifier, never set position.
    #[must_use]
    pub fn signer(&self) -> &CertificateInner<Raw> {
        &self.signer
    }

    /// The RSA key that verified the message signature.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// The signed attributes. SCEP-specific fields still need validation.
    #[must_use]
    pub fn attributes(&self) -> &Attributes {
        &self.attributes
    }

    /// The original encapsulated octets, whose digest was verified.
    #[must_use]
    pub fn content(&self) -> Option<&[u8]> {
        self.content.as_ref().map(OctetString::as_bytes)
    }
}

/// Signs attributes and optional content as a DER SCEP `SignedData`.
///
/// Adds the CMS content type and digest attributes. The caller supplies the
/// SCEP attributes, not `contentType` or `messageDigest`. For FAILURE/PENDING,
/// pass `None`: the absent envelope is authenticated with the empty digest.
///
/// # Errors
/// Returns encoding, randomness or signing errors.
pub fn sign(
    identity: &Identity,
    attributes: Attributes,
    content: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let encapsulated = EncapsulatedContentInfo {
        econtent_type: ID_DATA,
        econtent: content
            .map(OctetString::new)
            .transpose()?
            .map(|value| Any::encode_from(&value))
            .transpose()?,
    };
    let digest_algorithm = AlgorithmIdentifierOwned {
        oid: ID_SHA_256,
        parameters: Some(Any::from(Null)),
    };
    let tbs = identity.certificate().tbs_certificate();
    let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: tbs.issuer().clone(),
        serial_number: tbs.serial_number().clone(),
    });
    let empty_digest = Sha256::digest([]);
    let mut signer = SignerInfoBuilder::new(
        sid,
        digest_algorithm.clone(),
        &encapsulated,
        content.is_none().then_some(empty_digest.as_slice()),
    )?;
    for attribute in attributes.into_vec() {
        if attribute.oid == ID_CONTENT_TYPE || attribute.oid == ID_MESSAGE_DIGEST {
            return Err(Error::InvalidAttribute(attribute.oid));
        }
        signer.add_signed_attribute(attribute)?;
    }
    let mut builder = SignedDataBuilder::new(&encapsulated);
    builder.add_digest_algorithm(digest_algorithm)?;
    builder.add_certificate(CertificateChoices::Certificate(
        identity.certificate().clone(),
    ))?;
    let mut rng = StdRng::try_from_rng(&mut SysRng)?;
    builder.add_signer_info_with_rng::<_, Signature, _>(
        signer,
        &SigningKey::<Sha256>::new(identity.key().clone()),
        &mut rng,
    )?;
    Ok(builder.build()?.to_der()?)
}

pub(crate) fn check_algorithm(
    algorithm: &AlgorithmIdentifierOwned,
    allowed: &[ObjectIdentifier],
) -> Result<(), Error> {
    if !allowed.contains(&algorithm.oid)
        || algorithm.parameters.as_ref().is_some_and(|p| !p.is_null())
    {
        return Err(Error::Algorithm(algorithm.oid));
    }
    Ok(())
}

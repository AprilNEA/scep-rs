//! RSA key transport and AES-CBC content encryption for pkcsPKIEnvelope.

use aes::{Aes128, Aes192, Aes256};
use cbc::cipher::{BlockModeDecrypt as _, KeyIvInit as _, block_padding::Pkcs7};
use cms::{
    builder::{
        ContentEncryptionAlgorithm, EnvelopedDataBuilder, KeyEncryptionInfo,
        KeyTransRecipientInfoBuilder,
    },
    cert::IssuerAndSerialNumber,
    content_info::{CmsVersion, ContentInfo},
    enveloped_data::{EnvelopedData, RecipientIdentifier, RecipientInfo},
};
use const_oid::db::{
    rfc5911::{ID_AES_128_CBC, ID_AES_192_CBC, ID_AES_256_CBC, ID_DATA, ID_ENVELOPED_DATA},
    rfc5912::RSA_ENCRYPTION,
};
use der::{Any, Decode as _, Encode as _, EncodingRules, asn1::OctetString};
use rand::{
    SeedableRng as _,
    rngs::{StdRng, SysRng},
};
use rsa::{PrivateKey, PublicKey, pkcs8::DecodePublicKey as _};
use x509_cert::{
    certificate::{CertificateInner, Profile, Raw},
    ext::pkix::SubjectKeyIdentifier,
};
use zeroize::Zeroizing;

use crate::{Error, Limits, pki_message::check_algorithm};

/// Decrypts an envelope addressed to `certificate` with `key`.
///
/// RSA PKCS#1 v1.5 decryption uses blinding and implicit rejection. Keys and
/// decrypted content are zeroized on drop. Both inputs must belong to the same
/// identity; constructing an [`Identity`](crate::Identity) checks this pairing.
///
/// # Errors
/// Rejects unsupported algorithms, ambiguous/missing recipients, invalid
/// ciphertext or resource limits. RNG failures remain operational errors.
pub fn decrypt<P: Profile>(
    bytes: &[u8],
    certificate: &CertificateInner<P>,
    key: &PrivateKey,
    limits: &Limits,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if bytes.len() > limits.max_request_bytes {
        return Err(Error::MessageTooLarge);
    }
    let info = ContentInfo::from_ber(bytes)?;
    if info.content_type != ID_ENVELOPED_DATA {
        return Err(Error::InvalidMessage("content is not EnvelopedData"));
    }
    let envelope: EnvelopedData<Raw> = info.content.decode_as_encoding(EncodingRules::Ber)?;
    if envelope.recip_infos.0.len() > limits.max_recipients {
        return Err(Error::Limit("recipients"));
    }
    if envelope.originator_info.is_some() || envelope.unprotected_attrs.is_some() {
        return Err(Error::InvalidMessage("unsupported EnvelopedData structure"));
    }
    let mut recipient = None;
    let mut envelope_version = CmsVersion::V0;
    let tbs = certificate.tbs_certificate();
    for info in envelope.recip_infos.0.iter() {
        let RecipientInfo::Ktri(info) = info else {
            return Err(Error::InvalidMessage("recipient is not RSA key transport"));
        };
        let (matches, version) = match &info.rid {
            RecipientIdentifier::IssuerAndSerialNumber(id) => (
                id.issuer == *tbs.issuer()
                    && id.serial_number.as_bytes() == tbs.serial_number().as_bytes(),
                CmsVersion::V0,
            ),
            RecipientIdentifier::SubjectKeyIdentifier(id) => (
                tbs.get_extension::<SubjectKeyIdentifier>()?
                    .is_some_and(|(_, ski)| ski == *id),
                CmsVersion::V2,
            ),
        };
        if info.version != version {
            return Err(Error::InvalidMessage("recipient version"));
        }
        if version == CmsVersion::V2 {
            envelope_version = CmsVersion::V2;
        }
        if matches && recipient.replace(info).is_some() {
            return Err(Error::InvalidMessage("ambiguous recipient"));
        }
    }
    if envelope.version != envelope_version {
        return Err(Error::InvalidMessage("envelope version"));
    }
    let recipient = recipient.ok_or(Error::Integrity("recipient not found"))?;
    check_algorithm(&recipient.key_enc_alg, &[RSA_ENCRYPTION])?;
    let encrypted = &envelope.encrypted_content;
    if encrypted.content_type != ID_DATA {
        return Err(Error::InvalidMessage(
            "encrypted content type is not id-data",
        ));
    }
    let algorithm = &encrypted.content_enc_alg;
    if ![ID_AES_128_CBC, ID_AES_192_CBC, ID_AES_256_CBC].contains(&algorithm.oid) {
        return Err(Error::Algorithm(algorithm.oid));
    }
    let iv = algorithm
        .parameters
        .as_ref()
        .ok_or(Error::Algorithm(algorithm.oid))?
        .decode_as::<OctetString>()?;
    let ciphertext = encrypted
        .encrypted_content
        .as_ref()
        .ok_or(Error::Integrity("missing ciphertext"))?;
    let cek =
        Zeroizing::new(key.pkcs1v15_decrypt_with_rng(&mut SysRng, recipient.enc_key.as_bytes())?);
    let mut plaintext = Zeroizing::new(ciphertext.as_bytes().to_vec());
    let length = match algorithm.oid {
        ID_AES_128_CBC => cbc::Decryptor::<Aes128>::new_from_slices(&cek, iv.as_bytes())?
            .decrypt_padded::<Pkcs7>(&mut plaintext)?
            .len(),
        ID_AES_192_CBC => cbc::Decryptor::<Aes192>::new_from_slices(&cek, iv.as_bytes())?
            .decrypt_padded::<Pkcs7>(&mut plaintext)?
            .len(),
        ID_AES_256_CBC => cbc::Decryptor::<Aes256>::new_from_slices(&cek, iv.as_bytes())?
            .decrypt_padded::<Pkcs7>(&mut plaintext)?
            .len(),
        _ => return Err(Error::Algorithm(algorithm.oid)),
    };
    plaintext.truncate(length);
    Ok(plaintext)
}

/// Encrypts content for the recipient certificate using AES-128-CBC and RSA.
///
/// The peer profile is preserved in the recipient identifier, including serial
/// numbers that are not valid for locally issued RFC 5280 certificates.
///
/// # Errors
/// Returns errors for non-RSA recipients, encoding, randomness or encryption.
pub fn encrypt<P: Profile>(
    content: &[u8],
    recipient: &CertificateInner<P>,
) -> Result<Vec<u8>, Error> {
    let tbs = recipient.tbs_certificate();
    let key = PublicKey::from_public_key_der(&tbs.subject_public_key_info().to_der()?)?;
    let rid = RecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: tbs.issuer().clone(),
        serial_number: tbs.serial_number().clone(),
    });
    let mut builder =
        EnvelopedDataBuilder::new(None, content, ContentEncryptionAlgorithm::Aes128Cbc, None)?;
    builder.add_recipient_info(KeyTransRecipientInfoBuilder::<StdRng, P>::new(
        rid,
        KeyEncryptionInfo::Rsa(key),
    )?)?;
    let mut rng = StdRng::try_from_rng(&mut SysRng)?;
    Ok(ContentInfo {
        content_type: ID_ENVELOPED_DATA,
        content: Any::encode_from(&builder.build_with_rng(&mut rng)?)?,
    }
    .to_der()?)
}

use cms::{
    builder::{
        ContentEncryptionAlgorithm, EnvelopedDataBuilder, KeyEncryptionInfo,
        KeyTransRecipientInfoBuilder,
    },
    cert::{CertificateChoices, IssuerAndSerialNumber},
    content_info::CmsVersion,
    enveloped_data::{EnvelopedData, RecipientIdentifier, RecipientInfo, RecipientInfos},
    signed_data::SignerIdentifier,
};
use const_oid::{
    ObjectIdentifier,
    db::{
        rfc2985::PKCS_9_AT_CHALLENGE_PASSWORD,
        rfc5911::{DES_EDE_3_CBC, ID_ENVELOPED_DATA},
        rfc5912::ID_SHA_512,
    },
};
use der::asn1::{BitString, BmpString, Utf8StringRef};
use scep::protocol::x509_cert::{
    attr::{Attribute, Attributes},
    certificate::CertificateInner,
    ext::pkix::SubjectKeyIdentifier,
};
use sha2::Digest as _;

use super::*;

fn set_attribute(attributes: &mut Attributes, oid: ObjectIdentifier, value: Any) {
    let mut values = std::mem::take(attributes).into_vec();
    values.retain(|attribute| attribute.oid != oid);
    values.push(Attribute {
        oid,
        values: SetOfVec::try_from(vec![value]).unwrap(),
    });
    *attributes = values.try_into().unwrap();
}

fn set_content(data: &mut SignedData<Raw>, info: &mut SignerInfo<Raw>, bytes: &[u8]) {
    data.encap_content_info.econtent =
        Some(Any::encode_from(&OctetString::new(bytes).unwrap()).unwrap());
    set_attribute(
        info.signed_attrs.as_mut().unwrap(),
        ID_MESSAGE_DIGEST,
        Any::encode_from(&OctetString::new(Sha256::digest(bytes).to_vec()).unwrap()).unwrap(),
    );
    resign(info);
}

fn request_for_csr(csr: &CertReq) -> Vec<u8> {
    let content = envelope::encrypt(&csr.to_der().unwrap(), ra().certificate()).unwrap();
    amend_message(SSCEP, |data, info| set_content(data, info, &content))
}

fn sign_csr(csr: &mut CertReq) {
    let signature: Signature = SigningKey::<Sha256>::new(client_key())
        .try_sign_with_rng(
            &mut StdRng::from_seed([61; 32]),
            &csr.info.to_der().unwrap(),
        )
        .unwrap();
    csr.signature = BitString::from_bytes(&signature.to_bytes()).unwrap();
}

#[test]
fn digest_signature_and_algorithm_checks_cannot_be_skipped_by_either_policy() {
    let content = amend_message(SSCEP, |data, _| {
        let mut bytes = data
            .encap_content_info
            .econtent
            .as_ref()
            .unwrap()
            .decode_as::<OctetString>()
            .unwrap()
            .into_bytes();
        bytes[50] ^= 1;
        data.encap_content_info.econtent =
            Some(Any::encode_from(&OctetString::new(bytes).unwrap()).unwrap());
    });
    let digest = amend_message(&content, |data, info| {
        let bytes = data
            .encap_content_info
            .econtent
            .as_ref()
            .unwrap()
            .decode_as::<OctetString>()
            .unwrap();
        set_attribute(
            info.signed_attrs.as_mut().unwrap(),
            ID_MESSAGE_DIGEST,
            Any::encode_from(&OctetString::new(Sha256::digest(bytes.as_bytes()).to_vec()).unwrap())
                .unwrap(),
        );
    });
    let algorithm = amend_message(SSCEP, |_, info| info.signature_algorithm.oid = ID_SHA_512);
    let parameters = amend_message(SSCEP, |_, info| {
        info.digest_alg.parameters =
            Some(Any::encode_from(&OctetString::new([0]).unwrap()).unwrap());
    });
    for policy in [
        KeyBindingPolicy::RequireSameKey,
        KeyBindingPolicy::AllowDistinctKeys,
    ] {
        let server = responder(Some(ServerConfig {
            key_binding: policy,
            ..ServerConfig::default()
        }));
        for (bytes, expected) in [
            (&content, FailInfo::BadMessageCheck),
            (&digest, FailInfo::BadMessageCheck),
            (&algorithm, FailInfo::BadAlg),
            (&parameters, FailInfo::BadAlg),
        ] {
            let Error::Rejected(rejected) = server.open(bytes).unwrap_err() else {
                panic!("expected peer rejection")
            };
            assert_eq!(rejected.fail_info(), expected);
            assert!(server.reject(&rejected).unwrap().is_none());
        }
    }
}

#[test]
fn signed_headers_reject_ambiguous_ids_and_invalid_nonces_but_accept_exact_id_limit() {
    for kind in [
        "missing",
        "duplicate",
        "multivalued",
        "wrong type",
        "empty",
        "oversized",
        "short nonce",
        "long nonce",
    ] {
        let bytes = amend_message(SSCEP, |_, info| {
            let mut attributes = info.signed_attrs.take().unwrap().into_vec();
            let id = attributes
                .iter()
                .position(|attr| attr.oid == rfc8894::ID_TRANSACTION_ID)
                .unwrap();
            match kind {
                "missing" => {
                    attributes.remove(id);
                }
                "duplicate" | "multivalued" => {
                    let other =
                        Any::encode_from(&PrintableStringRef::new("another transaction").unwrap())
                            .unwrap();
                    if kind == "duplicate" {
                        attributes.push(Attribute {
                            oid: rfc8894::ID_TRANSACTION_ID,
                            values: vec![other].try_into().unwrap(),
                        });
                    } else {
                        let mut values = attributes[id].values.clone().into_vec();
                        values.push(other);
                        attributes[id].values = values.try_into().unwrap();
                    }
                }
                "wrong type" => {
                    attributes[id].values = vec![
                        Any::encode_from(&Utf8StringRef::new("valid looking ID").unwrap()).unwrap(),
                    ]
                    .try_into()
                    .unwrap();
                }
                "empty" | "oversized" => {
                    let value = if kind == "empty" {
                        String::new()
                    } else {
                        "x".repeat(Limits::default().max_transaction_id_bytes + 1)
                    };
                    attributes[id].values =
                        vec![Any::encode_from(&PrintableStringRef::new(&value).unwrap()).unwrap()]
                            .try_into()
                            .unwrap();
                }
                _ => {
                    let nonce = attributes
                        .iter_mut()
                        .find(|attr| attr.oid == rfc8894::ID_SENDER_NONCE)
                        .unwrap();
                    nonce.values = vec![
                        Any::encode_from(
                            &OctetString::new(vec![3; if kind == "short nonce" { 15 } else { 17 }])
                                .unwrap(),
                        )
                        .unwrap(),
                    ]
                    .try_into()
                    .unwrap();
                }
            }
            info.signed_attrs = Some(attributes.try_into().unwrap());
            resign(info);
        });
        assert!(
            VerifiedMessage::verify(&bytes, &Limits::default()).is_ok(),
            "{kind}"
        );
        let server = responder(None);
        let Error::Rejected(rejected) = server.open(&bytes).unwrap_err() else {
            panic!("expected peer rejection: {kind}")
        };
        assert!(server.reject(&rejected).unwrap().is_none(), "{kind}");
    }
    let id = "x".repeat(Limits::default().max_transaction_id_bytes);
    let exact = amend_message(SSCEP, |_, info| {
        set_attribute(
            info.signed_attrs.as_mut().unwrap(),
            rfc8894::ID_TRANSACTION_ID,
            Any::encode_from(&PrintableStringRef::new(&id).unwrap()).unwrap(),
        );
        resign(info);
    });
    assert_eq!(
        responder(None)
            .open(&exact)
            .unwrap()
            .transaction_id()
            .as_ref(),
        id
    );
}

#[test]
fn csr_proof_of_possession_precedes_binding_and_challenge_preserves_directory_strings() {
    let mut csr = client_csr();
    let mut signature = csr.signature.as_bytes().unwrap().to_vec();
    signature[0] ^= 1;
    csr.signature = BitString::from_bytes(&signature).unwrap();
    for request in [request_for_csr(&csr), distinct_key_request(&csr)] {
        assert!(VerifiedMessage::verify(&request, &Limits::default()).is_ok());
        for policy in [
            KeyBindingPolicy::RequireSameKey,
            KeyBindingPolicy::AllowDistinctKeys,
        ] {
            let server = responder(Some(ServerConfig {
                key_binding: policy,
                ..ServerConfig::default()
            }));
            let Error::Rejected(rejected) = server.open(&request).unwrap_err() else {
                panic!("expected peer rejection")
            };
            assert!(matches!(rejected.cause(), ProtocolError::Signature(_)));
            assert!(server.reject(&rejected).unwrap().is_some());
        }
    }
    for value in [
        Any::encode_from(&Utf8StringRef::new("sëcret 密码").unwrap()).unwrap(),
        Any::encode_from(&BmpString::from_utf8("sëcret 密码").unwrap()).unwrap(),
    ] {
        let mut csr = client_csr();
        csr.info.subject = "CN=Different subject,O=Enrollment tests".parse().unwrap();
        set_attribute(
            &mut csr.info.attributes,
            PKCS_9_AT_CHALLENGE_PASSWORD,
            value,
        );
        sign_csr(&mut csr);
        let enrollment = responder(None).open(&request_for_csr(&csr)).unwrap();
        assert_eq!(enrollment.challenge(), Some("sëcret 密码"));
        assert_eq!(enrollment.csr(), &csr);
        assert_ne!(
            enrollment.signer().tbs_certificate().subject(),
            &csr.info.subject
        );
    }
}

#[test]
fn signer_selection_uses_the_identifier_and_rejects_ambiguity() {
    let request = distinct_key_request(&client_csr());
    let ski = ra()
        .certificate()
        .tbs_certificate()
        .get_extension::<SubjectKeyIdentifier>()
        .unwrap()
        .unwrap()
        .1;
    let request = amend_message(&request, |data, info| {
        info.sid = SignerIdentifier::SubjectKeyIdentifier(ski);
        info.version = CmsVersion::V3;
        data.version = CmsVersion::V3;
        let mut certificates = data.certificates.take().unwrap().0.into_vec();
        certificates.push(CertificateChoices::Certificate(
            CertificateInner::<Raw>::from_pem(include_str!("../fixtures/ca/root.pem")).unwrap(),
        ));
        data.certificates = Some(certificates.try_into().unwrap());
    });
    let server = responder(Some(ServerConfig {
        key_binding: KeyBindingPolicy::AllowDistinctKeys,
        ..ServerConfig::default()
    }));
    let enrollment = server.open(&request).unwrap();
    assert_eq!(
        enrollment.signer().to_der().unwrap(),
        ra().certificate().to_der().unwrap()
    );
    let ambiguous = amend_message(&request, |data, _| {
        let mut bytes = ra().certificate().to_der().unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        let mut certificates = data.certificates.take().unwrap().0.into_vec();
        certificates.push(CertificateChoices::Certificate(
            CertificateInner::<Raw>::from_der(&bytes).unwrap(),
        ));
        data.certificates = Some(certificates.try_into().unwrap());
    });
    let Error::Rejected(rejected) = server.open(&ambiguous).unwrap_err() else {
        panic!("expected peer rejection")
    };
    assert!(matches!(rejected.cause(), ProtocolError::InvalidMessage(_)));
    assert!(server.reject(&rejected).unwrap().is_none());
}

#[test]
fn all_aes_sizes_and_ski_recipients_decrypt_without_using_set_position() {
    let csr = client_csr().to_der().unwrap();
    let identity = ra();
    let other = Identity::from_pem(
        include_str!("../fixtures/ca/root.pem"),
        include_str!("../fixtures/ca/root.key"),
    )
    .unwrap();
    for algorithm in [
        ContentEncryptionAlgorithm::Aes128Cbc,
        ContentEncryptionAlgorithm::Aes192Cbc,
        ContentEncryptionAlgorithm::Aes256Cbc,
    ] {
        for ski in [false, true] {
            let mut builder =
                EnvelopedDataBuilder::new(None, &csr, algorithm.clone(), None).unwrap();
            for recipient in [&other, &identity] {
                let tbs = recipient.certificate().tbs_certificate();
                let id = if ski {
                    RecipientIdentifier::SubjectKeyIdentifier(
                        tbs.get_extension::<SubjectKeyIdentifier>()
                            .unwrap()
                            .unwrap()
                            .1,
                    )
                } else {
                    RecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                        issuer: tbs.issuer().clone(),
                        serial_number: tbs.serial_number().clone(),
                    })
                };
                builder
                    .add_recipient_info(
                        KeyTransRecipientInfoBuilder::<StdRng>::new(
                            id,
                            KeyEncryptionInfo::Rsa(recipient.key().to_public_key()),
                        )
                        .unwrap(),
                    )
                    .unwrap();
            }
            let envelope = builder
                .build_with_rng(&mut StdRng::from_seed([73; 32]))
                .unwrap();
            let content = ContentInfo {
                content_type: ID_ENVELOPED_DATA,
                content: Any::encode_from(&envelope).unwrap(),
            }
            .to_der()
            .unwrap();
            let request = amend_message(SSCEP, |data, info| set_content(data, info, &content));
            assert_eq!(
                responder(None)
                    .open(&request)
                    .unwrap()
                    .csr()
                    .to_der()
                    .unwrap(),
                csr
            );
        }
    }
}

#[test]
fn invalid_envelopes_produce_authenticated_failures_not_enrollments() {
    let message = VerifiedMessage::verify(SSCEP, &Limits::default()).unwrap();
    let envelope: EnvelopedData<Raw> = ContentInfo::from_der(message.content().unwrap())
        .unwrap()
        .content
        .decode_as()
        .unwrap();
    for kind in [
        "recipient",
        "ambiguous",
        "transport",
        "cipher",
        "iv",
        "padding",
        "version",
        "missing ciphertext",
    ] {
        let mut envelope = envelope.clone();
        let mut recipients = envelope.recip_infos.0.into_vec();
        let RecipientInfo::Ktri(recipient) = &mut recipients[0] else {
            panic!("expected key transport")
        };
        match kind {
            "recipient" => {
                recipient.rid = RecipientIdentifier::SubjectKeyIdentifier(SubjectKeyIdentifier(
                    OctetString::new([0; 20]).unwrap(),
                ));
                recipient.version = CmsVersion::V2;
                envelope.version = CmsVersion::V2;
            }
            "ambiguous" => {
                let mut other = recipient.clone();
                other.enc_key = OctetString::new([0; 256]).unwrap();
                recipients.push(RecipientInfo::Ktri(other));
            }
            "transport" => recipient.key_enc_alg.oid = ID_SHA_512,
            "cipher" => envelope.encrypted_content.content_enc_alg.oid = DES_EDE_3_CBC,
            "iv" => {
                envelope.encrypted_content.content_enc_alg.parameters =
                    Some(Any::encode_from(&OctetString::new([0; 15]).unwrap()).unwrap());
            }
            "padding" => {
                envelope.encrypted_content.encrypted_content =
                    Some(OctetString::new([0; 17]).unwrap());
            }
            "version" => envelope.version = CmsVersion::V4,
            _ => envelope.encrypted_content.encrypted_content = None,
        }
        envelope.recip_infos = RecipientInfos(recipients.try_into().unwrap());
        let content = ContentInfo {
            content_type: ID_ENVELOPED_DATA,
            content: Any::encode_from(&envelope).unwrap(),
        }
        .to_der()
        .unwrap();
        let bytes = amend_message(SSCEP, |data, info| set_content(data, info, &content));
        let server = responder(None);
        let Error::Rejected(rejected) = server.open(&bytes).expect_err(kind) else {
            panic!("expected peer rejection: {kind}")
        };
        let expected = match kind {
            "transport" | "cipher" => FailInfo::BadAlg,
            "ambiguous" | "version" => FailInfo::BadRequest,
            _ => FailInfo::BadMessageCheck,
        };
        assert_eq!(rejected.fail_info(), expected, "{kind}");
        let failure = server.reject(&rejected).unwrap().unwrap();
        let reply = VerifiedMessage::verify(&failure, &Limits::default()).unwrap();
        assert!(reply.content().is_none(), "{kind}");
    }
}

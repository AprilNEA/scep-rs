use cms::cert::CertificateChoices;
use scep::{
    protocol::{
        certs_only,
        rsa::{PublicKey, pkcs8::DecodePublicKey as _},
        x509_cert::{
            builder::{Builder as _, CertificateBuilder, profile::devid::DevId},
            certificate::CertificateInner,
            serial_number::SerialNumber,
        },
    },
    server::Issuance,
};

use super::*;

fn issued(csr: &CertReq) -> (Certificate, Certificate) {
    let ca = Identity::from_pem(
        include_str!("../fixtures/ca/root.pem"),
        include_str!("../fixtures/ca/root.key"),
    )
    .unwrap();
    let tbs = ca.certificate().tbs_certificate();
    let builder = CertificateBuilder::new(
        DevId::new(tbs.subject().clone(), csr.info.subject.clone(), None).unwrap(),
        SerialNumber::from(23_u32),
        *tbs.validity(),
        csr.info.public_key.clone(),
    )
    .unwrap();
    let certificate = builder
        .build_with_rng::<_, Signature, _>(
            &SigningKey::<Sha256>::new(ca.key().clone()),
            &mut StdRng::from_seed([51; 32]),
        )
        .unwrap();
    (certificate, ca.certificate().clone())
}

#[test]
fn success_contains_the_csr_leaf_and_encrypts_only_to_the_selected_cms_signer() {
    let csr = client_csr();
    let (certificate, ca) = issued(&csr);
    let different = distinct_key_request(&csr);
    let decoy = CertificateInner::<Raw>::from_der(&ca.to_der().unwrap()).unwrap();
    let different = amend_message(&different, |data, _| {
        let mut certificates = data.certificates.take().unwrap().0.into_vec();
        certificates.push(CertificateChoices::Certificate(decoy));
        data.certificates = Some(certificates.try_into().unwrap());
    });
    for (request, policy, key) in [
        (SSCEP, KeyBindingPolicy::RequireSameKey, client_key()),
        (
            different.as_slice(),
            KeyBindingPolicy::AllowDistinctKeys,
            ra().key().clone(),
        ),
    ] {
        let server = responder(Some(ServerConfig {
            key_binding: policy,
            ..ServerConfig::default()
        }));
        let enrollment = server.open(request).unwrap();
        let response = server
            .reply(
                &enrollment,
                Issuance::Issued {
                    certificate: Box::new(certificate.clone()),
                    chain: vec![ca.clone()],
                },
            )
            .unwrap();
        let verified = VerifiedMessage::verify(&response, &Limits::default()).unwrap();
        assert_eq!(
            verified.signer().to_der().unwrap(),
            server.identity().certificate().to_der().unwrap(),
        );
        let header = Header::from_attributes(verified.attributes(), &Limits::default()).unwrap();
        assert_eq!(header.transaction_id(), enrollment.transaction_id());
        let envelope = verified.content().unwrap();
        let plaintext =
            envelope::decrypt(envelope, enrollment.signer(), &key, &Limits::default()).unwrap();
        let certificates = certs_only::decode(&plaintext).unwrap();
        assert_eq!(certificates.len(), 2);
        assert!(certificates.contains(&certificate));
        assert!(certificates.contains(&ca));
        let leaf_key = PublicKey::from_public_key_der(
            &certificate
                .tbs_certificate()
                .subject_public_key_info()
                .to_der()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(leaf_key, client_key().to_public_key());
        let wrong_key = if policy == KeyBindingPolicy::AllowDistinctKeys {
            client_key()
        } else {
            ra().key().clone()
        };
        assert!(
            envelope::decrypt(
                envelope,
                enrollment.signer(),
                &wrong_key,
                &Limits::default()
            )
            .is_err()
        );
    }
}

#[test]
fn issued_leaf_is_explicit_and_must_match_even_if_the_chain_contains_the_right_key() {
    let server = responder(None);
    let enrollment = server.open(SSCEP).unwrap();
    let (correct_leaf, _) = issued(enrollment.csr());
    let result = server.reply(
        &enrollment,
        Issuance::Issued {
            certificate: Box::new(ra().certificate().clone()),
            chain: vec![correct_leaf],
        },
    );
    assert!(matches!(result, Err(Error::IssuedKeyMismatch)));
}

#[test]
fn pending_and_policy_failure_sign_empty_content_and_echo_the_request_nonce() {
    let server = responder(None);
    let enrollment = server.open(SSCEP).unwrap();
    let request = VerifiedMessage::verify(SSCEP, &Limits::default()).unwrap();
    let request_header = Header::from_attributes(request.attributes(), &Limits::default()).unwrap();
    let mut previous_nonce = None;
    for (issuance, status) in [
        (Issuance::Pending, "3"),
        (
            Issuance::Rejected {
                fail_info: FailInfo::BadRequest,
                text: Some("not authorized".into()),
            },
            "2",
        ),
    ] {
        let response = server.reply(&enrollment, issuance).unwrap();
        let verified = VerifiedMessage::verify(&response, &Limits::default()).unwrap();
        assert!(verified.content().is_none());
        let header = Header::from_attributes(verified.attributes(), &Limits::default()).unwrap();
        assert_eq!(header.transaction_id(), request_header.transaction_id());
        assert_ne!(Some(header.sender_nonce()), previous_nonce);
        previous_nonce = Some(header.sender_nonce());
        let attributes = verified.attributes();
        let value = |oid| {
            attributes
                .iter()
                .find(|attr| attr.oid == oid)
                .unwrap()
                .values
                .get(0)
                .unwrap()
        };
        assert_eq!(
            value(rfc8894::ID_MESSAGE_TYPE)
                .decode_as::<PrintableStringRef<'_>>()
                .unwrap()
                .as_str(),
            "3"
        );
        assert_eq!(
            value(rfc8894::ID_PKI_STATUS)
                .decode_as::<PrintableStringRef<'_>>()
                .unwrap()
                .as_str(),
            status
        );
        assert_eq!(
            value(rfc8894::ID_RECIPIENT_NONCE)
                .decode_as::<OctetString>()
                .unwrap()
                .as_bytes(),
            request_header.sender_nonce().as_ref()
        );
        if status == "2" {
            assert_eq!(
                value(rfc8894::ID_FAIL_INFO)
                    .decode_as::<PrintableStringRef<'_>>()
                    .unwrap()
                    .as_str(),
                "2"
            );
            assert_eq!(
                value(rfc8894::ID_SCEP_FAIL_INFO_TEXT)
                    .decode_as::<der::asn1::Utf8StringRef<'_>>()
                    .unwrap()
                    .as_str(),
                "not authorized"
            );
        } else {
            assert!(
                attributes
                    .iter()
                    .all(|attr| attr.oid != rfc8894::ID_FAIL_INFO
                        && attr.oid != rfc8894::ID_SCEP_FAIL_INFO_TEXT)
            );
        }
    }
}

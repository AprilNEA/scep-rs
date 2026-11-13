//! Initial enrollment through the public server API, including real captures.

#![cfg(feature = "server")]

use cms::{
    content_info::ContentInfo,
    signed_data::{SignedData, SignerInfo, SignerInfos},
};
use const_oid::db::{
    rfc5911::{ID_CONTENT_TYPE, ID_MESSAGE_DIGEST, ID_SIGNED_DATA},
    rfc8894,
};
use der::{
    Any, Decode as _, DecodePem as _, Encode as _,
    asn1::{OctetString, PrintableStringRef, SetOfVec},
};
use rand::{SeedableRng as _, rngs::StdRng};
use scep::{
    Identity,
    protocol::{
        Error as ProtocolError, FailInfo, Limits,
        attr::Header,
        envelope,
        pki_message::{self, VerifiedMessage},
        rsa::{
            PrivateKey,
            pkcs1v15::{Signature, SigningKey},
            pkcs8::DecodePrivateKey as _,
        },
        x509_cert::{Certificate, certificate::Raw, request::CertReq},
    },
    server::{Error, KeyBindingPolicy, Responder, ServerConfig},
};
use sha2::Sha256;
use signature::{RandomizedSigner as _, SignatureEncoding as _};

mod replies;
mod transport;
mod validation;

const APPLE: &[u8] = include_bytes!("../fixtures/apple/pkcsreq.ber");
const SSCEP: &[u8] = include_bytes!("../fixtures/sscep/pkcsreq.der");

fn ra() -> Identity {
    Identity::from_pem(
        include_str!("../fixtures/ca/ra.pem"),
        include_str!("../fixtures/ca/ra.key"),
    )
    .unwrap()
}

fn client_key() -> PrivateKey {
    PrivateKey::from_pkcs8_pem(include_str!("../fixtures/sscep/client.key")).unwrap()
}

fn client_csr() -> CertReq {
    CertReq::from_pem(include_str!("../fixtures/sscep/client.csr")).unwrap()
}

fn responder(config: Option<ServerConfig>) -> Responder {
    let identity = ra();
    let chain = vec![Certificate::from_pem(include_str!("../fixtures/ca/root.pem")).unwrap()];
    match config {
        Some(config) => Responder::with_config(identity, chain, config).unwrap(),
        None => Responder::new(identity, chain).unwrap(),
    }
}

fn amend_message(
    bytes: &[u8],
    amend: impl FnOnce(&mut SignedData<Raw>, &mut SignerInfo<Raw>),
) -> Vec<u8> {
    let mut data: SignedData<Raw> = ContentInfo::from_der(bytes)
        .unwrap()
        .content
        .decode_as()
        .unwrap();
    let mut infos = std::mem::take(&mut data.signer_infos.0).into_vec();
    assert_eq!(infos.len(), 1);
    let mut info = infos.pop().unwrap();
    amend(&mut data, &mut info);
    data.signer_infos = SignerInfos(SetOfVec::try_from(vec![info]).unwrap());
    ContentInfo {
        content_type: ID_SIGNED_DATA,
        content: Any::encode_from(&data).unwrap(),
    }
    .to_der()
    .unwrap()
}

fn resign(info: &mut SignerInfo<Raw>) {
    let signature: Signature = SigningKey::<Sha256>::new(client_key())
        .try_sign_with_rng(
            &mut StdRng::from_seed([37; 32]),
            &info.signed_attrs.as_ref().unwrap().to_der().unwrap(),
        )
        .unwrap();
    info.signature = OctetString::new(signature.to_bytes()).unwrap();
}

fn distinct_key_request(csr: &CertReq) -> Vec<u8> {
    let identity = ra();
    let captured = VerifiedMessage::verify(SSCEP, &Limits::default()).unwrap();
    let attributes = captured
        .attributes()
        .iter()
        .filter(|attr| attr.oid != ID_CONTENT_TYPE && attr.oid != ID_MESSAGE_DIGEST)
        .cloned()
        .collect::<Vec<_>>();
    let content = envelope::encrypt(&csr.to_der().unwrap(), identity.certificate()).unwrap();
    pki_message::sign(&identity, attributes.try_into().unwrap(), Some(&content)).unwrap()
}

#[test]
fn sscep_long_serial_request_yields_the_original_csr_under_both_policies() {
    let expected = client_csr();
    for policy in [
        KeyBindingPolicy::RequireSameKey,
        KeyBindingPolicy::AllowDistinctKeys,
    ] {
        let server = responder(Some(ServerConfig {
            key_binding: policy,
            ..ServerConfig::default()
        }));
        let enrollment = server.open(SSCEP).unwrap();
        assert_eq!(enrollment.csr(), &expected);
        assert_eq!(enrollment.challenge(), Some("secret"));
        assert_eq!(
            enrollment
                .signer()
                .tbs_certificate()
                .serial_number()
                .as_bytes()
                .len(),
            32
        );
        assert!(!format!("{enrollment:?}").contains("secret"));
    }
}

#[test]
fn apple_requires_explicit_per_responder_opt_in_and_returns_exact_csr() {
    let strict = responder(None);
    let permissive = responder(Some(ServerConfig {
        key_binding: KeyBindingPolicy::AllowDistinctKeys,
        ..ServerConfig::default()
    }));
    let enrollment = permissive.open(APPLE).unwrap();
    assert_eq!(
        enrollment.csr().to_der().unwrap(),
        include_bytes!("../fixtures/apple/client.csr.der")
    );
    assert_eq!(enrollment.challenge(), Some("scep-rs-m1-fixture"));
    for server in [
        strict,
        responder(Some(ServerConfig::default())),
        responder(Some(ServerConfig {
            key_binding: KeyBindingPolicy::RequireSameKey,
            ..ServerConfig::default()
        })),
    ] {
        let Error::Rejected(rejected) = server.open(APPLE).unwrap_err() else {
            panic!("expected protocol rejection");
        };
        assert_eq!(rejected.fail_info(), FailInfo::BadMessageCheck);
        assert!(matches!(rejected.cause(), ProtocolError::KeyBinding));
        let reply = server.reject(&rejected).unwrap().unwrap();
        let verified = VerifiedMessage::verify(&reply, &Limits::default()).unwrap();
        assert!(verified.content().is_none());
        let attributes = verified.attributes();
        let status = attributes
            .iter()
            .find(|attribute| attribute.oid == rfc8894::ID_PKI_STATUS)
            .unwrap();
        assert_eq!(
            status
                .values
                .get(0)
                .unwrap()
                .decode_as::<PrintableStringRef<'_>>()
                .unwrap()
                .as_str(),
            "2"
        );
        let request = VerifiedMessage::verify(APPLE, &Limits::default()).unwrap();
        let request_header =
            Header::from_attributes(request.attributes(), &Limits::default()).unwrap();
        let reply_header = Header::from_attributes(attributes, &Limits::default()).unwrap();
        assert_eq!(
            reply_header.transaction_id(),
            request_header.transaction_id()
        );
        let nonce = attributes
            .iter()
            .find(|attribute| attribute.oid == rfc8894::ID_RECIPIENT_NONCE)
            .unwrap();
        assert_eq!(
            nonce
                .values
                .get(0)
                .unwrap()
                .decode_as::<OctetString>()
                .unwrap()
                .as_bytes(),
            request_header.sender_nonce().as_ref()
        );
    }
}

#[test]
fn corrupt_signature_has_no_authenticated_failure_context() {
    let mut bytes = SSCEP.to_vec();
    *bytes.last_mut().unwrap() ^= 1;
    for policy in [
        KeyBindingPolicy::RequireSameKey,
        KeyBindingPolicy::AllowDistinctKeys,
    ] {
        let server = responder(Some(ServerConfig {
            key_binding: policy,
            ..ServerConfig::default()
        }));
        let Error::Rejected(rejected) = server.open(&bytes).unwrap_err() else {
            panic!("expected protocol rejection");
        };
        assert_eq!(rejected.fail_info(), FailInfo::BadMessageCheck);
        assert!(server.reject(&rejected).unwrap().is_none());
    }
}

#[test]
fn byte_limit_precedes_parsing_and_accepts_the_exact_boundary() {
    let server = responder(Some(ServerConfig {
        limits: Limits {
            max_request_bytes: SSCEP.len(),
            ..Limits::default()
        },
        ..ServerConfig::default()
    }));
    assert!(server.open(SSCEP).is_ok());
    let Error::Rejected(rejected) = server.open(&vec![0xff; SSCEP.len() + 1]).unwrap_err() else {
        panic!("expected protocol rejection");
    };
    assert!(matches!(rejected.cause(), ProtocolError::MessageTooLarge));
    assert!(server.reject(&rejected).unwrap().is_none());
}

#[test]
fn authenticated_unsupported_message_types_produce_signed_bad_request() {
    let server = responder(None);
    for message_type in ["3", "20", "999"] {
        let request = amend_message(SSCEP, |_, info| {
            let mut attributes = info.signed_attrs.take().unwrap().into_vec();
            let attribute = attributes
                .iter_mut()
                .find(|attribute| attribute.oid == rfc8894::ID_MESSAGE_TYPE)
                .unwrap();
            attribute.values =
                vec![Any::encode_from(&PrintableStringRef::new(message_type).unwrap()).unwrap()]
                    .try_into()
                    .unwrap();
            info.signed_attrs = Some(attributes.try_into().unwrap());
            resign(info);
        });
        assert!(VerifiedMessage::verify(&request, &Limits::default()).is_ok());
        let Error::Rejected(rejected) = server.open(&request).unwrap_err() else {
            panic!("expected peer rejection")
        };
        assert_eq!(rejected.fail_info(), FailInfo::BadRequest);
        let reply = server.reject(&rejected).unwrap().unwrap();
        let verified = VerifiedMessage::verify(&reply, &Limits::default()).unwrap();
        assert!(verified.content().is_none());
        assert_eq!(
            verified
                .attributes()
                .iter()
                .find(|attribute| attribute.oid == rfc8894::ID_FAIL_INFO)
                .unwrap()
                .values
                .get(0)
                .unwrap()
                .decode_as::<PrintableStringRef<'_>>()
                .unwrap()
                .as_str(),
            "2"
        );
    }
}

#[test]
fn collection_limits_accept_exact_boundaries_and_reject_one_over() {
    let request = amend_message(SSCEP, |data, _| {
        let mut certificates = data.certificates.take().unwrap().0.into_vec();
        certificates.push(cms::cert::CertificateChoices::Certificate(
            scep::protocol::x509_cert::certificate::CertificateInner::<Raw>::from_pem(
                include_str!("../fixtures/ca/root.pem"),
            )
            .unwrap(),
        ));
        data.certificates = Some(certificates.try_into().unwrap());
    });
    let exact = Limits {
        max_certificates: 2,
        max_attributes: 6,
        max_recipients: 1,
        ..Limits::default()
    };
    assert!(
        responder(Some(ServerConfig {
            limits: exact,
            ..ServerConfig::default()
        }))
        .open(&request)
        .is_ok()
    );
    for (limits, authenticated) in [
        (
            Limits {
                max_certificates: 1,
                ..exact
            },
            false,
        ),
        (
            Limits {
                max_attributes: 5,
                ..exact
            },
            false,
        ),
        (
            Limits {
                max_recipients: 0,
                ..exact
            },
            true,
        ),
    ] {
        let server = Responder::with_config(
            ra(),
            vec![],
            ServerConfig {
                limits,
                ..ServerConfig::default()
            },
        )
        .unwrap();
        let Error::Rejected(rejected) = server.open(&request).unwrap_err() else {
            panic!("expected peer rejection")
        };
        assert!(matches!(rejected.cause(), ProtocolError::Limit(_)));
        assert_eq!(rejected.fail_info(), FailInfo::BadRequest);
        assert_eq!(server.reject(&rejected).unwrap().is_some(), authenticated);
    }
}

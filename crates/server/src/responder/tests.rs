use http::{StatusCode, header::CONTENT_TYPE};
use scep_protocol::{
    CaCapabilities, Identity, certs_only, transport,
    x509_cert::{
        Certificate,
        der::{Decode as _, DecodePem as _},
    },
};

use super::Responder;
use crate::Error;

const ROOT_PEM: &str = include_str!("../../../../tests/fixtures/ca/root.pem");
const ROOT_KEY: &str = include_str!("../../../../tests/fixtures/ca/root.key");
const RA_PEM: &str = include_str!("../../../../tests/fixtures/ca/ra.pem");
const RA_KEY: &str = include_str!("../../../../tests/fixtures/ca/ra.key");
const RA_SIGN_ONLY_PEM: &str = include_str!("../../../../tests/fixtures/ca/ra-sign-only.pem");

fn root() -> Certificate {
    Certificate::from_pem(ROOT_PEM).unwrap()
}

fn ra_behind_root() -> Responder {
    Responder::new(Identity::from_pem(RA_PEM, RA_KEY).unwrap(), vec![root()]).unwrap()
}

#[test]
fn ra_with_chain_answers_get_ca_cert_with_certificates_only_signed_data() {
    let response = ra_behind_root().ca_cert_response();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[CONTENT_TYPE], transport::CA_RA_CERT);

    let certificates = certs_only::decode(response.body()).unwrap();
    assert_eq!(certificates.len(), 2);
    assert!(certificates.contains(&Certificate::from_pem(RA_PEM).unwrap()));
    assert!(certificates.contains(&root()));
}

#[test]
fn ca_without_chain_answers_get_ca_cert_with_its_der_certificate() {
    let identity = Identity::from_pem(ROOT_PEM, ROOT_KEY).unwrap();
    let response = Responder::new(identity, Vec::new())
        .unwrap()
        .ca_cert_response();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[CONTENT_TYPE], transport::CA_CERT);
    assert_eq!(Certificate::from_der(response.body()).unwrap(), root());
}

#[test]
fn rejects_an_identity_whose_key_usage_lacks_key_encipherment() {
    let identity = Identity::from_pem(RA_SIGN_ONLY_PEM, RA_KEY).unwrap();
    let error = Responder::new(identity, vec![root()]).unwrap_err();
    assert!(
        matches!(&error, Error::KeyUsage(usage)
            if usage.digital_signature() && !usage.key_encipherment()),
        "{error}"
    );
}

#[test]
fn answers_get_ca_caps_with_the_standard_capabilities() {
    let responder = ra_behind_root();
    let response = responder.ca_caps_response();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[CONTENT_TYPE], transport::CA_CAPS);

    let advertised: CaCapabilities = str::from_utf8(response.body()).unwrap().parse().unwrap();
    assert_eq!(advertised, CaCapabilities::standard());
    assert_eq!(responder.ca_caps(), &advertised);
}

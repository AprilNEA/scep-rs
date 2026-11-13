use pkcs8::DecodePrivateKey as _;
use rsa::RsaPrivateKey;
use x509_cert::{Certificate, der::DecodePem as _};

use super::Identity;
use crate::Error;

const ROOT_PEM: &str = include_str!("../../../../tests/fixtures/ca/root.pem");
const ROOT_KEY: &str = include_str!("../../../../tests/fixtures/ca/root.key");
const RA_PEM: &str = include_str!("../../../../tests/fixtures/ca/ra.pem");
const RA_KEY: &str = include_str!("../../../../tests/fixtures/ca/ra.key");
const RA_PKCS1_KEY: &str = include_str!("../../../../tests/fixtures/ca/ra.pkcs1.key");

#[test]
fn pairs_a_certificate_with_its_key() {
    let identity = Identity::from_pem(RA_PEM, RA_KEY).unwrap();
    assert_eq!(
        identity.certificate(),
        &Certificate::from_pem(RA_PEM).unwrap()
    );
    assert_eq!(
        identity.key(),
        &RsaPrivateKey::from_pkcs8_pem(RA_KEY).unwrap()
    );
}

#[test]
fn accepts_pkcs1_and_pkcs8_forms_of_the_same_key() {
    let pkcs8 = Identity::from_pem(RA_PEM, RA_KEY).unwrap();
    let pkcs1 = Identity::from_pem(RA_PEM, RA_PKCS1_KEY).unwrap();
    assert_eq!(pkcs8.key(), pkcs1.key());
}

#[test]
fn rejects_a_key_that_does_not_match_the_certificate() {
    assert!(matches!(
        Identity::from_pem(RA_PEM, ROOT_KEY),
        Err(Error::KeyMismatch)
    ));
    assert!(matches!(
        Identity::from_pem(ROOT_PEM, RA_KEY),
        Err(Error::KeyMismatch)
    ));
}

#[test]
fn rejects_key_pem_with_another_label() {
    let error = Identity::from_pem(RA_PEM, RA_PEM).unwrap_err();
    assert!(
        matches!(&error, Error::PemLabel { label, expected }
            if label == "CERTIFICATE" && *expected == ["PRIVATE KEY", "RSA PRIVATE KEY"]),
        "{error}"
    );
}

#[test]
fn rejects_non_pem_input() {
    assert!(matches!(
        Identity::from_pem("not a certificate", RA_KEY),
        Err(Error::Asn1(_))
    ));
    assert!(matches!(
        Identity::from_pem(RA_PEM, "not a key"),
        Err(Error::Asn1(_))
    ));
}

#[test]
fn debug_output_omits_the_key() {
    let identity = Identity::from_pem(RA_PEM, RA_KEY).unwrap();
    let debug = format!("{identity:?}");
    assert!(debug.contains("scep-rs test RA"), "{debug}");
    assert!(!debug.contains("key"), "{debug}");
}

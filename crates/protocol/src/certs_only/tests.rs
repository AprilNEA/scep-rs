use cms::content_info::ContentInfo;
use const_oid::db::rfc5911::ID_DATA;
use der::{
    Encode as _,
    asn1::{Any, OctetString},
};
use x509_cert::{Certificate, der::DecodePem as _};

use super::{decode, encode};
use crate::Error;

const ROOT_PEM: &str = include_str!("../../../../tests/fixtures/ca/root.pem");
const RA_PEM: &str = include_str!("../../../../tests/fixtures/ca/ra.pem");
/// `openssl crl2pkcs7 -nocrl -certfile root.pem -certfile ra.pem -outform DER`.
const OPENSSL_CHAIN: &[u8] = include_bytes!("../../../../tests/fixtures/ca/chain.p7b");

fn root() -> Certificate {
    Certificate::from_pem(ROOT_PEM).unwrap()
}

fn ra() -> Certificate {
    Certificate::from_pem(RA_PEM).unwrap()
}

fn sorted_by_der(mut certificates: Vec<Certificate>) -> Vec<Certificate> {
    certificates.sort_by_cached_key(|certificate| certificate.to_der().unwrap());
    certificates
}

#[test]
fn decodes_openssl_certificates_only_output_in_encoded_order() {
    // OpenSSL writes the SET OF in insertion order, root then RA, which is not
    // DER order here (the RA encoding sorts first). Decoding must accept that
    // and keep the order it found.
    let certificates = decode(OPENSSL_CHAIN).unwrap();
    assert_eq!(certificates, [root(), ra()]);
    assert_ne!(certificates, sorted_by_der(vec![root(), ra()]));
}

#[test]
fn encode_sorts_so_input_order_is_not_preserved() {
    assert_eq!(
        encode(vec![ra(), root()]).unwrap(),
        encode(vec![root(), ra()]).unwrap()
    );
    let certificates = decode(&encode(vec![root(), ra()]).unwrap()).unwrap();
    assert_eq!(certificates, sorted_by_der(vec![root(), ra()]));
}

#[test]
fn encode_carries_the_same_certificates_as_openssl() {
    // The encodings differ in two ways that both decoders accept: the order
    // inside the SET OF, and the empty `crls` set that cms writes as `A1 00`
    // and OpenSSL omits.
    let ours = encode(vec![root(), ra()]).unwrap();
    assert_eq!(ours.len(), OPENSSL_CHAIN.len() + 2);
    assert_eq!(
        sorted_by_der(decode(&ours).unwrap()),
        sorted_by_der(decode(OPENSSL_CHAIN).unwrap())
    );
}

#[test]
fn single_certificate_round_trips() {
    let certificates = decode(&encode(vec![ra()]).unwrap()).unwrap();
    assert_eq!(certificates, [ra()]);
}

#[test]
fn empty_certificate_set_decodes_to_no_certificates() {
    let certificates = decode(&encode(Vec::new()).unwrap()).unwrap();
    assert_eq!(certificates, Vec::new());
}

#[test]
fn decodes_indefinite_length_ber() {
    // Re-wrap the DER ContentInfo as an indefinite-length SEQUENCE, the outer
    // shape Apple's encoder produces: 30 80 <contents> 00 00.
    let der = encode(vec![root(), ra()]).unwrap();
    let (header_len, contents) = split_sequence(&der);
    let mut ber = vec![0x30, 0x80];
    ber.extend_from_slice(&der[header_len..header_len + contents]);
    ber.extend_from_slice(&[0x00, 0x00]);

    let certificates = decode(&ber).unwrap();
    assert_eq!(certificates, sorted_by_der(vec![root(), ra()]));
}

/// Splits a DER SEQUENCE into its header length and contents length.
fn split_sequence(der: &[u8]) -> (usize, usize) {
    assert_eq!(der[0], 0x30);
    let first = der[1];
    assert!(first & 0x80 != 0, "fixture is longer than 127 bytes");
    let length_bytes = usize::from(first & 0x7f);
    let contents = der[2..2 + length_bytes]
        .iter()
        .fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte));
    (2 + length_bytes, contents)
}

#[test]
fn rejects_content_that_is_not_signed_data() {
    let data = ContentInfo {
        content_type: ID_DATA,
        content: Any::encode_from(&OctetString::new(&b"payload"[..]).unwrap()).unwrap(),
    };
    assert!(matches!(
        decode(&data.to_der().unwrap()),
        Err(Error::NotSignedData(oid)) if oid == ID_DATA
    ));
}

#[test]
fn rejects_garbage() {
    assert!(matches!(decode(b"not cms"), Err(Error::Asn1(_))));
    assert!(matches!(decode(&[]), Err(Error::Asn1(_))));
}

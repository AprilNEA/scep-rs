use bytes::Bytes;
use http::{Method, Request, StatusCode, header};

use super::{CA_CAPS, Operation, ca_caps_response, status_for};
use crate::{CaCapabilities, Error};

fn get(uri: &str) -> Request<Bytes> {
    Request::get(uri).body(Bytes::new()).expect("valid request")
}

fn parse(request: Request<Bytes>) -> Result<Operation, Error> {
    Operation::try_from(request)
}

#[test]
fn selects_operation_from_query() {
    assert_eq!(
        parse(get("/scep?operation=GetCACaps")).unwrap(),
        Operation::GetCaCaps
    );
    assert_eq!(
        parse(get("/cgi-bin/pkiclient.exe?operation=GetCACert")).unwrap(),
        Operation::GetCaCert { identifier: None }
    );
}

#[test]
fn operation_name_ignores_ascii_case() {
    assert_eq!(
        parse(get("/scep?operation=getcacaps")).unwrap(),
        Operation::GetCaCaps
    );
}

#[test]
fn get_ca_cert_keeps_a_non_empty_message_as_identifier() {
    assert_eq!(
        parse(get("/scep?operation=GetCACert&message=Example%20CA")).unwrap(),
        Operation::GetCaCert {
            identifier: Some("Example CA".to_owned())
        }
    );
    assert_eq!(
        parse(get("/scep?operation=GetCACert&message=")).unwrap(),
        Operation::GetCaCert { identifier: None }
    );
}

#[test]
fn post_pki_operation_takes_the_body() {
    let request = Request::post("/scep?operation=PKIOperation")
        .body(Bytes::from_static(b"\x30\x80cms"))
        .unwrap();
    assert_eq!(
        parse(request).unwrap(),
        Operation::PkiOperation(Bytes::from_static(b"\x30\x80cms"))
    );
}

#[test]
fn get_pki_operation_decodes_percent_encoded_base64() {
    // base64("\xfb\xff\xbf") = "+/+/", with reserved characters escaped.
    let request = get("/scep?operation=PKIOperation&message=%2B%2F%2B%2F");
    assert_eq!(
        parse(request).unwrap(),
        Operation::PkiOperation(Bytes::from_static(b"\xfb\xff\xbf"))
    );
}

#[test]
fn get_pki_operation_accepts_unescaped_plus_and_missing_padding() {
    // Unescaped "+" is form-decoded to a space; "/" and "=" are left alone.
    assert_eq!(
        parse(get("/scep?operation=PKIOperation&message=+/+/")).unwrap(),
        Operation::PkiOperation(Bytes::from_static(b"\xfb\xff\xbf"))
    );
    // base64("ab") = "YWI=", with and without padding.
    assert_eq!(
        parse(get("/scep?operation=PKIOperation&message=YWI=")).unwrap(),
        Operation::PkiOperation(Bytes::from_static(b"ab"))
    );
    assert_eq!(
        parse(get("/scep?operation=PKIOperation&message=YWI")).unwrap(),
        Operation::PkiOperation(Bytes::from_static(b"ab"))
    );
}

#[test]
fn first_repeated_parameter_wins() {
    assert_eq!(
        parse(get("/scep?operation=GetCACaps&operation=PKIOperation")).unwrap(),
        Operation::GetCaCaps
    );
}

#[test]
fn rejects_missing_or_unknown_operation() {
    assert!(matches!(parse(get("/scep")), Err(Error::MissingOperation)));
    assert!(matches!(
        parse(get("/scep?message=abc")),
        Err(Error::MissingOperation)
    ));
    assert!(matches!(
        parse(get("/scep?operation=GetNextCACert")),
        Err(Error::UnknownOperation(name)) if name == "GetNextCACert"
    ));
}

#[test]
fn rejects_get_pki_operation_without_message_or_with_bad_base64() {
    assert!(matches!(
        parse(get("/scep?operation=PKIOperation")),
        Err(Error::MissingMessage)
    ));
    assert!(matches!(
        parse(get("/scep?operation=PKIOperation&message=")),
        Err(Error::MissingMessage)
    ));
    assert!(matches!(
        parse(get("/scep?operation=PKIOperation&message=%21%21")),
        Err(Error::Base64(_))
    ));
}

#[test]
fn rejects_pki_operation_over_other_methods() {
    let request = Request::builder()
        .method(Method::PUT)
        .uri("/scep?operation=PKIOperation")
        .body(Bytes::new())
        .unwrap();
    let error = parse(request).unwrap_err();
    assert!(matches!(&error, Error::UnsupportedMethod(method) if *method == Method::PUT));
    assert_eq!(status_for(&error), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        status_for(&Error::MissingOperation),
        StatusCode::BAD_REQUEST
    );
}

#[test]
fn ca_caps_response_is_plain_text() {
    let response = ca_caps_response(&CaCapabilities::standard());
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], CA_CAPS);
    assert_eq!(
        response.body().as_ref(),
        b"AES\nPOSTPKIOperation\nSHA-256\nSCEPStandard\n"
    );
}

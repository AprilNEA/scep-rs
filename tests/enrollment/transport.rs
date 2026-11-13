use std::{
    future::{Future, ready},
    io,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http::{Request, StatusCode, header::CONTENT_TYPE};
use scep::{
    protocol::transport::PKI_MESSAGE,
    server::{Enrollment, HandleError, Issuance, Issuer, handle},
};

use super::*;

struct Unavailable;

impl Issuer for Unavailable {
    type Error = io::Error;

    fn issue(&self, _: &Enrollment) -> impl Future<Output = Result<Issuance, Self::Error>> {
        ready(Err(io::Error::other("CA unavailable")))
    }
}

struct ChallengePolicy;

impl Issuer for ChallengePolicy {
    type Error = io::Error;

    fn issue(
        &self,
        enrollment: &Enrollment,
    ) -> impl Future<Output = Result<Issuance, Self::Error>> {
        ready(Ok(if enrollment.challenge() == Some("secret") {
            Issuance::Pending
        } else {
            Issuance::Rejected {
                fail_info: FailInfo::BadRequest,
                text: None,
            }
        }))
    }
}

#[tokio::test]
async fn discovery_and_peer_rejections_do_not_reach_the_ca_but_valid_get_and_post_do() {
    let server = responder(None);
    for (method, uri, body, expected) in [
        ("GET", "/scep?operation=GetCACaps", &[][..], StatusCode::OK),
        ("GET", "/scep?operation=GetCACert", &[][..], StatusCode::OK),
        (
            "POST",
            "/scep?operation=PKIOperation",
            &[0xff][..],
            StatusCode::BAD_REQUEST,
        ),
        (
            "GET",
            "/scep?operation=PKIOperation",
            &[][..],
            StatusCode::BAD_REQUEST,
        ),
        (
            "PUT",
            "/scep?operation=PKIOperation",
            SSCEP,
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            "POST",
            "/scep?operation=PKIOperation",
            APPLE,
            StatusCode::OK,
        ),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .body(Bytes::copy_from_slice(body))
            .unwrap();
        let response = handle(&server, &Unavailable, request).await.unwrap();
        assert_eq!(response.status(), expected, "{method} {uri}");
        if body == APPLE {
            assert_eq!(response.headers()[CONTENT_TYPE], PKI_MESSAGE);
            assert!(
                VerifiedMessage::verify(response.body(), &Limits::default())
                    .unwrap()
                    .content()
                    .is_none()
            );
        }
    }
    for request in [
        Request::builder()
            .method("POST")
            .uri("/scep?operation=PKIOperation")
            .body(Bytes::from_static(SSCEP))
            .unwrap(),
        Request::builder()
            .uri(format!(
                "/scep?operation=PKIOperation&message={}",
                STANDARD.encode(SSCEP)
            ))
            .body(Bytes::new())
            .unwrap(),
    ] {
        let error = handle(&server, &Unavailable, request).await.unwrap_err();
        assert!(
            matches!(error, HandleError::Issuer(ref error) if error.kind() == io::ErrorKind::Other && error.to_string() == "CA unavailable")
        );
    }
}

#[tokio::test]
async fn permissive_binding_does_not_bypass_issuer_authorization() {
    let server = responder(Some(ServerConfig {
        key_binding: KeyBindingPolicy::AllowDistinctKeys,
        ..ServerConfig::default()
    }));
    for (request, expected_status) in [(SSCEP, "3"), (APPLE, "2")] {
        let request = Request::builder()
            .method("POST")
            .uri("/scep?operation=PKIOperation")
            .body(Bytes::from_static(request))
            .unwrap();
        let response = handle(&server, &ChallengePolicy, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_TYPE], PKI_MESSAGE);
        let message = VerifiedMessage::verify(response.body(), &Limits::default()).unwrap();
        assert!(message.content().is_none());
        let status = message
            .attributes()
            .iter()
            .find(|attr| attr.oid == rfc8894::ID_PKI_STATUS)
            .unwrap();
        assert_eq!(
            status
                .values
                .get(0)
                .unwrap()
                .decode_as::<PrintableStringRef<'_>>()
                .unwrap()
                .as_str(),
            expected_status
        );
        assert!(
            message
                .attributes()
                .iter()
                .all(|attr| attr.oid != rfc8894::ID_SCEP_FAIL_INFO_TEXT)
        );
    }
}

#[tokio::test]
async fn raw_query_and_decoded_body_limits_have_inclusive_boundaries() {
    let query = "operation=GetCACaps&extra=%41%42%43";
    for (limit, expected) in [
        (query.len(), StatusCode::OK),
        (query.len() - 1, StatusCode::PAYLOAD_TOO_LARGE),
    ] {
        let server = responder(Some(ServerConfig {
            limits: Limits {
                max_query_bytes: limit,
                ..Limits::default()
            },
            ..ServerConfig::default()
        }));
        let request = Request::builder()
            .uri(format!("/scep?{query}"))
            .body(Bytes::new())
            .unwrap();
        assert_eq!(
            handle(&server, &Unavailable, request)
                .await
                .unwrap()
                .status(),
            expected
        );
    }
    let server = responder(Some(ServerConfig {
        limits: Limits {
            max_request_bytes: SSCEP.len(),
            ..Limits::default()
        },
        ..ServerConfig::default()
    }));
    let too_large = vec![0; SSCEP.len() + 1];
    for request in [
        Request::builder()
            .method("POST")
            .uri("/scep?operation=PKIOperation")
            .body(Bytes::copy_from_slice(&too_large))
            .unwrap(),
        Request::builder()
            .uri(format!(
                "/scep?operation=PKIOperation&message={}",
                STANDARD.encode(&too_large)
            ))
            .body(Bytes::new())
            .unwrap(),
    ] {
        let response = handle(&server, &Unavailable, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(response.body(), "invalid SCEP request");
    }
}

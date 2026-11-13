//! Real client captures exercise byte-preserving transport and outer CMS decoding.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use cms::{content_info::ContentInfo, signed_data::SignedData};
use const_oid::db::rfc5911::{ID_DATA, ID_SIGNED_DATA};
use der::{Decode as _, EncodingRules};
use http::Request;
use scep_protocol::transport::Operation;

const APPLE: &[u8] = include_bytes!("../../../tests/fixtures/apple/pkcsreq.ber");
const SSCEP: &[u8] = include_bytes!("../../../tests/fixtures/sscep/pkcsreq.der");

#[test]
fn captures_survive_get_and_post_without_reencoding() {
    for (name, capture) in [("Apple BER", APPLE), ("sscep DER", SSCEP)] {
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("operation", "PKIOperation")
            .append_pair("message", &STANDARD.encode(capture))
            .finish();
        let requests = [
            Request::post("/scep?operation=PKIOperation&message=ignored")
                .body(Bytes::from_static(capture))
                .unwrap(),
            Request::get(format!("/scep?{query}"))
                .body(Bytes::new())
                .unwrap(),
        ];
        for request in requests {
            assert_eq!(
                Operation::try_from(request).unwrap(),
                Operation::PkiOperation(Bytes::from_static(capture)),
                "{name}"
            );
        }
        let outer = ContentInfo::from_ber(capture).unwrap();
        assert_eq!(outer.content_type, ID_SIGNED_DATA, "{name}");
    }
}

#[test]
fn apple_outer_signed_data_requires_ber_decoding() {
    assert!(ContentInfo::from_der(APPLE).is_err());
    let outer = ContentInfo::from_ber(APPLE).unwrap();
    let signed: SignedData = outer
        .content
        .decode_as_encoding(EncodingRules::Ber)
        .unwrap();
    assert_eq!(signed.encap_content_info.econtent_type, ID_DATA);
    assert_eq!(signed.signer_infos.0.len(), 1);
    assert!(signed.encap_content_info.econtent.is_some());
}

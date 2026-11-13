use super::{CaCapabilities, Capability};

fn parse(body: &str) -> CaCapabilities {
    body.parse().expect("parsing is infallible")
}

#[test]
fn parses_crlf_and_lf_separated_keywords() {
    let caps = parse("AES\r\nPOSTPKIOperation\nSHA-256\r\n");
    assert_eq!(
        caps.known().collect::<Vec<_>>(),
        [
            Capability::Aes,
            Capability::PostPkiOperation,
            Capability::Sha256
        ]
    );
    assert_eq!(caps.unknown(), <&[String]>::default());
}

#[test]
fn matches_keywords_without_regard_to_case() {
    let caps = parse("aes\nscepstandard\nsha-512");
    assert!(caps.supports(Capability::Aes));
    assert!(caps.supports(Capability::ScepStandard));
    assert!(caps.supports(Capability::Sha512));
    assert_eq!(caps.unknown(), <&[String]>::default());
}

#[test]
fn keeps_unknown_keywords_verbatim_in_order() {
    let caps = parse("Zeta\nAES\nAlpha\n");
    assert_eq!(caps.unknown(), ["Zeta", "Alpha"]);
    assert!(caps.supports(Capability::Aes));
    assert_eq!(caps.to_string(), "AES\nZeta\nAlpha\n");
}

#[test]
fn empty_body_yields_empty_set() {
    let caps = parse("");
    assert!(caps.is_empty());
    assert!(!caps.supports(Capability::Aes));
    assert_eq!(caps.to_string(), "");

    assert!(parse("\r\n\n  \n").is_empty());
}

#[test]
fn scep_standard_implies_aes_post_and_sha256_only() {
    let caps = parse("SCEPStandard");
    assert!(caps.supports(Capability::Aes));
    assert!(caps.supports(Capability::PostPkiOperation));
    assert!(caps.supports(Capability::Sha256));
    assert!(!caps.supports(Capability::Sha512));
    assert!(!caps.supports(Capability::Renewal));
    assert!(!caps.supports(Capability::Des3));
    assert_eq!(caps.known().collect::<Vec<_>>(), [Capability::ScepStandard]);
}

#[test]
fn standard_set_round_trips_in_rfc_case() {
    let body = CaCapabilities::standard().to_string();
    assert_eq!(body, "AES\nPOSTPKIOperation\nSHA-256\nSCEPStandard\n");
    assert_eq!(parse(&body), CaCapabilities::standard());
}

#[test]
fn duplicate_known_keywords_collapse() {
    let caps = parse("AES\nAES\naes");
    assert_eq!(caps.known().collect::<Vec<_>>(), [Capability::Aes]);
}

#[test]
fn keyword_with_surrounding_spaces_is_trimmed() {
    let caps = parse("  AES \t\n");
    assert!(caps.supports(Capability::Aes));
    assert_eq!(caps.unknown(), <&[String]>::default());
}

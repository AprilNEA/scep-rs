use scep::server::Responder;

use super::*;

fn ca(challenge: &str, capacity: usize) -> TestCa {
    TestCa::new(
        Identity::from_pem(
            include_str!("../../../../tests/fixtures/ca/root.pem"),
            include_str!("../../../../tests/fixtures/ca/root.key"),
        )
        .unwrap(),
        Zeroizing::new(challenge.into()),
        Duration::from_secs(24 * 60 * 60),
        capacity,
    )
    .unwrap()
}

fn enrollment() -> Enrollment {
    Responder::new(
        Identity::from_pem(
            include_str!("../../../../tests/fixtures/ca/ra.pem"),
            include_str!("../../../../tests/fixtures/ca/ra.key"),
        )
        .unwrap(),
        vec![],
    )
    .unwrap()
    .open(include_bytes!(
        "../../../../tests/fixtures/sscep/pkcsreq.der"
    ))
    .unwrap()
}

#[tokio::test]
async fn concurrent_retries_reuse_one_leaf_even_at_capacity() {
    let issuer = ca("secret", 1);
    let enrollment = enrollment();
    let (first, retry) = tokio::join!(issuer.issue(&enrollment), issuer.issue(&enrollment));
    let Issuance::Issued { certificate, chain } = first.unwrap() else {
        panic!("expected issuance")
    };
    let Issuance::Issued {
        certificate: repeated,
        ..
    } = retry.unwrap()
    else {
        panic!("expected cached issuance")
    };
    assert_eq!(certificate, repeated);
    assert_eq!(chain.len(), 1);
    let tbs = certificate.tbs_certificate();
    assert_eq!(tbs.subject(), &enrollment.csr().info.subject);
    assert_eq!(
        tbs.subject_public_key_info(),
        &enrollment.csr().info.public_key
    );
    assert_eq!(tbs.issuer(), chain[0].tbs_certificate().subject());
    assert!(
        !tbs.get_extension::<BasicConstraints>()
            .unwrap()
            .unwrap()
            .1
            .ca
    );
    let usage = tbs.get_extension::<KeyUsage>().unwrap().unwrap().1;
    assert!(usage.digital_signature() && usage.key_encipherment());
    assert!(!usage.key_cert_sign());
    assert!(
        tbs.validity().not_after.to_unix_duration()
            <= chain[0]
                .tbs_certificate()
                .validity()
                .not_after
                .to_unix_duration()
    );
}

#[tokio::test]
async fn challenge_rejection_and_capacity_failure_remain_different_outcomes() {
    let enrollment = enrollment();
    assert!(matches!(
        ca("wrong public fixture challenge", 0)
            .issue(&enrollment)
            .await,
        Ok(Issuance::Rejected {
            fail_info: FailInfo::BadRequest,
            text: None
        })
    ));
    assert!(matches!(
        ca("secret", 0).issue(&enrollment).await,
        Err(Error::Capacity)
    ));
}

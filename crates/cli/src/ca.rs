//! Static-challenge test CA. No production authorization or durable storage.

use std::{collections::HashMap, time::Duration};

use anyhow::ensure;
use rand::{
    SeedableRng as _,
    rngs::{StdRng, SysRng},
};
use scep::{
    Identity,
    protocol::{
        FailInfo, TransactionId,
        rsa::pkcs1v15::{Signature, SigningKey},
        x509_cert::{
            Certificate,
            builder::{self, Builder as _, CertificateBuilder, profile::BuilderProfile},
            certificate::TbsCertificate,
            der::{self, Encode as _},
            ext::{
                Extension, ToExtension as _,
                pkix::{
                    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages,
                    SubjectKeyIdentifier,
                },
            },
            name::Name,
            serial_number::SerialNumber,
            spki::SubjectPublicKeyInfoRef,
            time::Validity,
        },
    },
    server::{Enrollment, Issuance, Issuer},
};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

#[cfg(test)]
mod tests;

/// An ephemeral issuer backed by a PEM-loaded CA identity.
pub struct TestCa {
    identity: Identity,
    challenge: Zeroizing<String>,
    lifetime: Duration,
    max_transactions: usize,
    issued: Mutex<HashMap<TransactionId, Record>>,
}

struct Record {
    csr_digest: [u8; 32],
    certificate: Certificate,
}

/// Operational failures of the demo issuer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// DER encoding or certificate validity failed.
    #[error("certificate encoding: {0}")]
    Asn1(#[from] der::Error),
    /// The certificate builder or its signing operation failed.
    #[error("certificate builder: {0}")]
    Certificate(#[from] builder::Error),
    /// Operating system randomness failed.
    #[error("randomness: {0}")]
    Random(#[from] getrandom::Error),
    /// The bounded in-memory retry store is full.
    #[error("test CA transaction capacity reached")]
    Capacity,
    /// The issuing certificate is no longer valid.
    #[error("test CA certificate is outside its validity period")]
    Validity,
}

impl TestCa {
    /// Validates the CA role and creates an empty process-local retry store.
    pub fn new(
        identity: Identity,
        challenge: Zeroizing<String>,
        lifetime: Duration,
        max_transactions: usize,
    ) -> anyhow::Result<Self> {
        ensure!(!challenge.is_empty(), "challenge file must not be empty");
        let tbs = identity.certificate().tbs_certificate();
        ensure!(
            tbs.get_extension::<BasicConstraints>()?
                .is_some_and(|(_, constraints)| constraints.ca),
            "issuer certificate is not a CA; provide --issuer-cert and --issuer-key for an RA responder"
        );
        if let Some((_, usage)) = tbs.get_extension::<KeyUsage>()? {
            ensure!(
                usage.key_cert_sign(),
                "issuer certificate lacks keyCertSign"
            );
        }
        Ok(Self {
            identity,
            challenge,
            lifetime,
            max_transactions,
            issued: Mutex::new(HashMap::new()),
        })
    }
}

impl Issuer for TestCa {
    type Error = Error;

    async fn issue(&self, enrollment: &Enrollment) -> Result<Issuance, Error> {
        let Some(challenge) = enrollment.challenge() else {
            return Ok(Issuance::Rejected {
                fail_info: FailInfo::BadRequest,
                text: None,
            });
        };
        if !bool::from(challenge.as_bytes().ct_eq(self.challenge.as_bytes())) {
            return Ok(Issuance::Rejected {
                fail_info: FailInfo::BadRequest,
                text: None,
            });
        }
        let csr_digest: [u8; 32] = Sha256::digest(enrollment.csr().to_der()?).into();
        let mut issued = self.issued.lock().await;
        let certificate = if let Some(record) = issued.get(enrollment.transaction_id()) {
            if record.csr_digest != csr_digest {
                return Ok(Issuance::Rejected {
                    fail_info: FailInfo::BadRequest,
                    text: None,
                });
            }
            record.certificate.clone()
        } else {
            if issued.len() >= self.max_transactions {
                return Err(Error::Capacity);
            }
            let ca = self.identity.certificate().tbs_certificate();
            let mut validity = Validity::from_now(self.lifetime)?;
            if validity.not_before.to_unix_duration() < ca.validity().not_before.to_unix_duration()
                || validity.not_before.to_unix_duration()
                    >= ca.validity().not_after.to_unix_duration()
            {
                return Err(Error::Validity);
            }
            if validity.not_after.to_unix_duration() > ca.validity().not_after.to_unix_duration() {
                validity.not_after = ca.validity().not_after;
            }
            let mut serial = [0; 16];
            getrandom::fill(&mut serial)?;
            serial[0] = (serial[0] & 0x7f) | 0x40;
            let profile = ClientProfile {
                issuer: ca.subject().clone(),
                subject: enrollment.csr().info.subject.clone(),
            };
            let builder = CertificateBuilder::new(
                profile,
                SerialNumber::new(&serial)?,
                validity,
                enrollment.csr().info.public_key.clone(),
            )?;
            let mut rng = StdRng::try_from_rng(&mut SysRng)?;
            let certificate = builder.build_with_rng::<_, Signature, _>(
                &SigningKey::<Sha256>::new(self.identity.key().clone()),
                &mut rng,
            )?;
            issued.insert(
                enrollment.transaction_id().clone(),
                Record {
                    csr_digest,
                    certificate: certificate.clone(),
                },
            );
            certificate
        };
        Ok(Issuance::Issued {
            certificate: Box::new(certificate),
            chain: vec![self.identity.certificate().clone()],
        })
    }
}

struct ClientProfile {
    issuer: Name,
    subject: Name,
}

impl BuilderProfile for ClientProfile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> builder::Result<Vec<Extension>> {
        let mut extensions = vec![
            BasicConstraints {
                ca: false,
                path_len_constraint: None,
            }
            .to_extension(tbs.subject(), &[])?,
        ];
        extensions.push(
            KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment)
                .to_extension(tbs.subject(), &extensions)?,
        );
        extensions
            .push(SubjectKeyIdentifier::try_from(spk)?.to_extension(tbs.subject(), &extensions)?);
        extensions.push(
            AuthorityKeyIdentifier::try_from(issuer_spk)?
                .to_extension(tbs.subject(), &extensions)?,
        );
        Ok(extensions)
    }
}

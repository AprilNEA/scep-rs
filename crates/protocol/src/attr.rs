//! Typed SCEP signed attributes ([RFC 8894 §3.2.1]).
//!
//! [RFC 8894 §3.2.1]: https://www.rfc-editor.org/rfc/rfc8894#section-3.2.1

use std::{fmt, str::FromStr};

use const_oid::{ObjectIdentifier, db::rfc8894};
use der::{
    Any, EncodeValue, Tagged,
    asn1::{OctetString, PrintableStringRef, SetOfVec, Utf8StringRef},
};
use x509_cert::attr::{Attribute, Attributes};

use crate::{Error, Limits};

/// SCEP message types supported by this implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::AsRefStr, strum::EnumString)]
pub enum MessageType {
    /// Certificate reply.
    #[strum(serialize = "3")]
    CertRep,
    /// Initial PKCS#10 enrollment request.
    #[strum(serialize = "19")]
    PkcsReq,
}

/// Certificate reply status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::AsRefStr, strum::EnumString)]
pub enum PkiStatus {
    /// A certificate was issued.
    #[strum(serialize = "0")]
    Success,
    /// The request was rejected.
    #[strum(serialize = "2")]
    Failure,
    /// The issuer deferred its decision. Polling is not implemented.
    #[strum(serialize = "3")]
    Pending,
}

/// SCEP failure codes. Detailed validation errors need not be disclosed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::AsRefStr, strum::EnumString)]
pub enum FailInfo {
    /// An algorithm is unsupported or has invalid parameters.
    #[strum(serialize = "0")]
    BadAlg,
    /// Message integrity, decryption, or proof of possession failed.
    #[strum(serialize = "1")]
    BadMessageCheck,
    /// The request or issuer authorization policy was not satisfied.
    #[strum(serialize = "2")]
    BadRequest,
    /// The request time is unacceptable to the issuer.
    #[strum(serialize = "3")]
    BadTime,
    /// The requested certificate cannot be identified.
    #[strum(serialize = "4")]
    BadCertId,
}

/// A nonempty `PrintableString` transaction identifier.
///
/// Incoming length is bounded by [`Limits::max_transaction_id_bytes`]. An ID
/// identifies a transaction, not a client; replay policy belongs to the issuer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransactionId(String);

impl FromStr for TransactionId {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Error> {
        if value.is_empty() || PrintableStringRef::new(value).is_err() {
            return Err(Error::InvalidAttribute(rfc8894::ID_TRANSACTION_ID));
        }
        Ok(Self(value.to_owned()))
    }
}

impl AsRef<str> for TransactionId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TransactionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A 16-byte SCEP nonce. This length is fixed by RFC 8894.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nonce([u8; 16]);

impl Nonce {
    /// Generates a nonce from the operating system RNG.
    ///
    /// # Errors
    /// Returns an error if operating system randomness is unavailable.
    pub fn generate() -> Result<Self, Error> {
        let mut value = [0; 16];
        getrandom::fill(&mut value)?;
        Ok(Self(value))
    }
}

impl From<[u8; 16]> for Nonce {
    fn from(value: [u8; 16]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Transaction attributes used to correlate a response with a request.
///
/// Parsing does not authenticate this header. Only use a header for a reply
/// after verifying the signed message that contains it.
#[derive(Debug, Clone)]
pub struct Header {
    transaction_id: TransactionId,
    sender_nonce: Nonce,
}

impl Header {
    /// Parses the transaction ID and sender nonce from signed attributes.
    ///
    /// # Errors
    /// Rejects missing, duplicated, multivalued, mistyped or oversized fields.
    pub fn from_attributes(attributes: &Attributes, limits: &Limits) -> Result<Self, Error> {
        let id = required(attributes, rfc8894::ID_TRANSACTION_ID)?
            .decode_as::<PrintableStringRef<'_>>()?;
        if id.as_str().len() > limits.max_transaction_id_bytes {
            return Err(Error::Limit("transaction ID"));
        }
        let nonce = required(attributes, rfc8894::ID_SENDER_NONCE)?.decode_as::<OctetString>()?;
        Ok(Self {
            transaction_id: id.as_str().parse()?,
            sender_nonce: Nonce(
                nonce
                    .as_bytes()
                    .try_into()
                    .map_err(|_| Error::InvalidAttribute(rfc8894::ID_SENDER_NONCE))?,
            ),
        })
    }

    /// The transaction ID to echo in the reply.
    #[must_use]
    pub fn transaction_id(&self) -> &TransactionId {
        &self.transaction_id
    }

    /// The request's nonce, to echo as the reply's recipient nonce.
    #[must_use]
    pub fn sender_nonce(&self) -> Nonce {
        self.sender_nonce
    }

    /// Builds `CertRep` attributes with a fresh sender nonce.
    ///
    /// # Errors
    /// Returns an error on encoding or RNG failure, or if failure information
    /// is present for a non-failure status or absent for a failure status.
    pub fn reply_attributes(
        &self,
        status: PkiStatus,
        failure: Option<(FailInfo, Option<&str>)>,
    ) -> Result<Attributes, Error> {
        if (status == PkiStatus::Failure) != failure.is_some() {
            return Err(Error::InvalidMessage("inconsistent CertRep status"));
        }
        let nonce = Nonce::generate()?;
        let mut attributes = vec![
            attribute(
                rfc8894::ID_TRANSACTION_ID,
                &PrintableStringRef::new(self.transaction_id.as_ref())?,
            )?,
            attribute(
                rfc8894::ID_MESSAGE_TYPE,
                &PrintableStringRef::new(MessageType::CertRep.as_ref())?,
            )?,
            attribute(
                rfc8894::ID_PKI_STATUS,
                &PrintableStringRef::new(status.as_ref())?,
            )?,
            attribute(rfc8894::ID_SENDER_NONCE, &OctetString::new(nonce.as_ref())?)?,
            attribute(
                rfc8894::ID_RECIPIENT_NONCE,
                &OctetString::new(self.sender_nonce.as_ref())?,
            )?,
        ];
        if let Some((code, text)) = failure {
            attributes.push(attribute(
                rfc8894::ID_FAIL_INFO,
                &PrintableStringRef::new(code.as_ref())?,
            )?);
            if let Some(text) = text {
                attributes.push(attribute(
                    rfc8894::ID_SCEP_FAIL_INFO_TEXT,
                    &Utf8StringRef::new(text)?,
                )?);
            }
        }
        Ok(Attributes::try_from(attributes)?)
    }
}

/// Reads the required, single-valued message type.
///
/// # Errors
/// Rejects absent, duplicated, mistyped or unsupported message types.
pub fn message_type(attributes: &Attributes) -> Result<MessageType, Error> {
    required(attributes, rfc8894::ID_MESSAGE_TYPE)?
        .decode_as::<PrintableStringRef<'_>>()?
        .as_str()
        .parse()
        .map_err(|_| Error::InvalidAttribute(rfc8894::ID_MESSAGE_TYPE))
}

pub(crate) fn required(attributes: &Attributes, oid: ObjectIdentifier) -> Result<&Any, Error> {
    optional(attributes, oid)?.ok_or(Error::MissingAttribute(oid))
}

pub(crate) fn optional(
    attributes: &Attributes,
    oid: ObjectIdentifier,
) -> Result<Option<&Any>, Error> {
    let mut matches = attributes.iter().filter(|attribute| attribute.oid == oid);
    let Some(attribute) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() || attribute.values.len() != 1 {
        return Err(Error::InvalidAttribute(oid));
    }
    Ok(attribute.values.get(0))
}

fn attribute(
    oid: ObjectIdentifier,
    value: &(impl EncodeValue + Tagged),
) -> Result<Attribute, Error> {
    Ok(Attribute {
        oid,
        values: SetOfVec::try_from(vec![Any::encode_from(value)?])?,
    })
}

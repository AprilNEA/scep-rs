//! CA capabilities: the `GetCACaps` response body ([RFC 8894 §3.5]).
//!
//! [RFC 8894 §3.5]: https://www.rfc-editor.org/rfc/rfc8894#section-3.5

use std::{collections::BTreeSet, convert::Infallible, fmt, str::FromStr};

#[cfg(test)]
mod tests;

/// A capability keyword defined by [RFC 8894 §3.5.2].
///
/// `Display` writes the keyword in the case the RFC requires from a CA;
/// `FromStr` accepts any ASCII case, as the RFC recommends for clients.
///
/// [RFC 8894 §3.5.2]: https://www.rfc-editor.org/rfc/rfc8894#section-3.5.2
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, strum::Display, strum::EnumString,
)]
#[strum(ascii_case_insensitive)]
#[non_exhaustive]
pub enum Capability {
    /// The CA accepts AES128-CBC content encryption.
    #[strum(serialize = "AES")]
    Aes,
    /// The CA accepts triple DES-CBC content encryption.
    #[strum(serialize = "DES3")]
    Des3,
    /// The CA supports the `GetNextCACert` operation.
    GetNextCACert,
    /// The CA accepts `PKIOperation` messages over HTTP POST.
    #[strum(serialize = "POSTPKIOperation")]
    PostPkiOperation,
    /// The CA supports the `RenewalReq` message.
    Renewal,
    /// The CA accepts the SHA-1 digest.
    #[strum(serialize = "SHA-1")]
    Sha1,
    /// The CA accepts the SHA-256 digest.
    #[strum(serialize = "SHA-256")]
    Sha256,
    /// The CA accepts the SHA-512 digest.
    #[strum(serialize = "SHA-512")]
    Sha512,
    /// The CA implements every mandatory part of RFC 8894; implies
    /// [`Capability::Aes`], [`Capability::PostPkiOperation`], and
    /// [`Capability::Sha256`].
    #[strum(serialize = "SCEPStandard")]
    ScepStandard,
}

impl Capability {
    /// The capabilities that [`Capability::ScepStandard`] implies.
    const IMPLIED_BY_STANDARD: [Self; 3] = [Self::Aes, Self::PostPkiOperation, Self::Sha256];
}

/// The set of capabilities a CA advertises.
///
/// Parsing never fails: keywords this crate does not define are kept verbatim
/// in [`CaCapabilities::unknown`], as RFC 8894 §3.5.2 requires clients to
/// accept and ignore them. An empty body yields an empty set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaCapabilities {
    known: BTreeSet<Capability>,
    unknown: Vec<String>,
}

impl CaCapabilities {
    /// The capabilities an RFC 8894 §2.9 compliant CA advertises:
    /// `AES`, `POSTPKIOperation`, `SHA-256`, and `SCEPStandard`.
    #[must_use]
    pub fn standard() -> Self {
        let mut caps = Self::default();
        for cap in Capability::IMPLIED_BY_STANDARD {
            caps.insert(cap);
        }
        caps.insert(Capability::ScepStandard);
        caps
    }

    /// Adds a capability.
    pub fn insert(&mut self, capability: Capability) {
        self.known.insert(capability);
    }

    /// Whether the CA advertises `capability`, directly or through
    /// `SCEPStandard`.
    #[must_use]
    pub fn supports(&self, capability: Capability) -> bool {
        self.known.contains(&capability)
            || (self.known.contains(&Capability::ScepStandard)
                && Capability::IMPLIED_BY_STANDARD.contains(&capability))
    }

    /// The advertised keywords this crate defines, without implied ones.
    pub fn known(&self) -> impl Iterator<Item = Capability> + '_ {
        self.known.iter().copied()
    }

    /// Advertised keywords this crate does not define, in the order received.
    #[must_use]
    pub fn unknown(&self) -> &[String] {
        &self.unknown
    }

    /// Whether the CA advertised no keyword at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.known.is_empty() && self.unknown.is_empty()
    }
}

impl FromStr for CaCapabilities {
    type Err = Infallible;

    /// Parses a `GetCACaps` body: keywords separated by `<CR><LF>` or `<LF>`,
    /// matched without regard to ASCII case. Blank lines are skipped.
    fn from_str(body: &str) -> Result<Self, Infallible> {
        let mut caps = Self::default();
        for keyword in body.lines().map(str::trim).filter(|line| !line.is_empty()) {
            match keyword.parse() {
                Ok(capability) => caps.insert(capability),
                Err(strum::ParseError::VariantNotFound) => caps.unknown.push(keyword.to_owned()),
            }
        }
        Ok(caps)
    }
}

impl fmt::Display for CaCapabilities {
    /// Writes the `GetCACaps` body: one keyword per line, terminated by `<LF>`,
    /// known keywords first in the case RFC 8894 requires.
    ///
    /// `<LF>` rather than `<CR><LF>` because every client must accept it and
    /// older clients that split on `<LF>` alone would otherwise keep the `<CR>`
    /// in the keyword.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for capability in &self.known {
            writeln!(f, "{capability}")?;
        }
        for keyword in &self.unknown {
            writeln!(f, "{keyword}")?;
        }
        Ok(())
    }
}

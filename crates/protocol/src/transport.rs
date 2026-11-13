//! Sans-IO HTTP mapping ([RFC 8894 §4]): the `operation` and `message` query
//! parameters of a request, and the media types of each response.
//!
//! [RFC 8894 §4]: https://www.rfc-editor.org/rfc/rfc8894#section-4

use base64::{Engine as _, engine::general_purpose::STANDARD_PAD_INDIFFERENT};
use bytes::Bytes;
use http::{HeaderValue, Method, Request, Response, StatusCode, header};

use crate::{Limits, caps::CaCapabilities, error::Error};

#[cfg(test)]
mod tests;

/// Media type of a `PKIOperation` request or `CertRep` response body.
pub const PKI_MESSAGE: HeaderValue = HeaderValue::from_static("application/x-pki-message");
/// Media type of a `GetCACert` response that carries one X.509 certificate.
pub const CA_CERT: HeaderValue = HeaderValue::from_static("application/x-x509-ca-cert");
/// Media type of a `GetCACert` response that carries a certificates-only CMS message.
pub const CA_RA_CERT: HeaderValue = HeaderValue::from_static("application/x-x509-ca-ra-cert");
/// Media type of a `GetCACaps` response.
pub const CA_CAPS: HeaderValue = HeaderValue::from_static("text/plain");

/// A SCEP request, as selected by its `operation` query parameter.
///
/// The enum is exhaustive so that a server dispatching on it must handle every
/// operation; adding one, such as `GetNextCACert`, is a breaking change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    /// `GetCACaps` ([RFC 8894 §3.5.1]).
    ///
    /// [RFC 8894 §3.5.1]: https://www.rfc-editor.org/rfc/rfc8894#section-3.5.1
    GetCaCaps,
    /// `GetCACert` ([RFC 8894 §4.2]).
    ///
    /// [RFC 8894 §4.2]: https://www.rfc-editor.org/rfc/rfc8894#section-4.2
    GetCaCert {
        /// The `message` query parameter, which pre-RFC clients such as Apple's
        /// and `sscep` still send to name one CA among several. RFC 8894
        /// defines no request data for `GetCACert`, so a server may ignore it.
        identifier: Option<String>,
    },
    /// `PKIOperation` ([RFC 8894 §4.1]): a CMS `pkiMessage`, taken from the
    /// POST body or decoded from the base64 `message` query parameter of a GET.
    ///
    /// [RFC 8894 §4.1]: https://www.rfc-editor.org/rfc/rfc8894#section-4.1
    PkiOperation(Bytes),
}

/// The `operation` query parameter values, matched without regard to ASCII
/// case because the RFC specifies the case for servers but not for clients.
#[derive(strum::EnumString)]
#[strum(ascii_case_insensitive)]
enum OperationName {
    GetCACaps,
    GetCACert,
    PKIOperation,
}

impl<B: Into<Bytes>> TryFrom<Request<B>> for Operation {
    type Error = Error;

    /// Parses a request using [`Limits::default`].
    fn try_from(request: Request<B>) -> Result<Self, Error> {
        Self::from_request(request, &Limits::default())
    }
}

impl Operation {
    /// Selects the operation and bounds allocations using the supplied limits.
    ///
    /// A GET `message` is form-decoded first, so a `+` the client did not
    /// percent-encode arrives as a space; spaces are mapped back to `+` because
    /// a space is never valid base64. Padding is not required.
    ///
    /// # Errors
    /// Returns an error for malformed operations, unsupported methods,
    /// oversized bodies/queries, or invalid base64. HTTP frameworks must also
    /// bound request bodies while reading them from the network.
    pub fn from_request<B: Into<Bytes>>(
        request: Request<B>,
        limits: &Limits,
    ) -> Result<Self, Error> {
        let (parts, body) = request.into_parts();
        let query = parts.uri.query().unwrap_or("");
        let body = body.into();
        if body.len() > limits.max_request_bytes || query.len() > limits.max_query_bytes {
            return Err(Error::MessageTooLarge);
        }
        let mut operation = None;
        let mut message = None;
        for (key, value) in form_urlencoded::parse(query.as_bytes()) {
            match &*key {
                "operation" if operation.is_none() => operation = Some(value),
                "message" if message.is_none() => message = Some(value),
                _ => {}
            }
        }
        let operation = operation.ok_or(Error::MissingOperation)?;
        let name = operation
            .parse()
            .map_err(|strum::ParseError::VariantNotFound| {
                Error::UnknownOperation(operation.into_owned())
            })?;
        let message = message.filter(|message| !message.is_empty());
        match name {
            OperationName::GetCACaps => Ok(Self::GetCaCaps),
            OperationName::GetCACert => Ok(Self::GetCaCert {
                identifier: message.map(std::borrow::Cow::into_owned),
            }),
            OperationName::PKIOperation => match parts.method {
                Method::POST => Ok(Self::PkiOperation(body)),
                Method::GET => {
                    let message = message.ok_or(Error::MissingMessage)?;
                    if message.len() > limits.max_request_bytes.div_ceil(3).saturating_mul(4) {
                        return Err(Error::MessageTooLarge);
                    }
                    let decoded = STANDARD_PAD_INDIFFERENT.decode(message.replace(' ', "+"))?;
                    if decoded.len() > limits.max_request_bytes {
                        return Err(Error::MessageTooLarge);
                    }
                    Ok(Self::PkiOperation(Bytes::from(decoded)))
                }
                method => Err(Error::UnsupportedMethod(method)),
            },
        }
    }
}

/// A `200 OK` response with the given media type and body.
pub fn ok(content_type: HeaderValue, body: impl Into<Bytes>) -> Response<Bytes> {
    let mut response = Response::new(body.into());
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    response
}

/// The `GetCACaps` response for `caps` ([RFC 8894 §3.5.2]).
///
/// [RFC 8894 §3.5.2]: https://www.rfc-editor.org/rfc/rfc8894#section-3.5.2
#[must_use]
pub fn ca_caps_response(caps: &CaCapabilities) -> Response<Bytes> {
    ok(CA_CAPS, caps.to_string())
}

/// The HTTP status that reports a request this module could not map to an
/// [`Operation`]: `405` for an unsupported method, `413` for excess bytes,
/// `400` otherwise.
#[must_use]
pub fn status_for(error: &Error) -> StatusCode {
    match error {
        Error::UnsupportedMethod(_) => StatusCode::METHOD_NOT_ALLOWED,
        Error::MessageTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        _ => StatusCode::BAD_REQUEST,
    }
}

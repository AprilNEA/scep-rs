//! Framework-independent HTTP dispatch and the asynchronous issuer boundary.

use bytes::Bytes;
use http::{Request, Response};
use scep_protocol::transport::{self, Operation};

use crate::{Error, Issuer, Responder};

/// An operational failure while handling a request.
///
/// The host should log this error locally and return a generic HTTP 500. Peer
/// validation and policy rejections are returned as ordinary HTTP responses.
#[derive(Debug, thiserror::Error)]
pub enum HandleError<E: std::error::Error + 'static> {
    /// Protocol response generation or responder operation failed.
    #[error(transparent)]
    Server(#[from] Error),
    /// Application-owned CA or authorization infrastructure failed.
    #[error("issuer: {0}")]
    Issuer(#[source] E),
}

/// Handles discovery or enrollment on framework-independent HTTP types.
///
/// The HTTP framework must bound body collection with the responder's limits.
/// Parsing also bounds GET queries before form/base64 decoding. The issuer is
/// never called for a request that fails cryptographic validation or binding.
/// No body, CSR, challenge, or query string is logged by this library.
///
/// # Errors
/// Returns operational failures separately from signed SCEP rejections. An
/// invalid request with no authenticated context receives a generic HTTP
/// 400/413; a verified protocol/policy rejection receives a FAILURE `CertRep`.
pub async fn handle<I: Issuer>(
    responder: &Responder,
    issuer: &I,
    request: Request<Bytes>,
) -> Result<Response<Bytes>, HandleError<I::Error>> {
    let operation = match Operation::from_request(request, &responder.config().limits) {
        Ok(operation) => operation,
        Err(error) => return Ok(request_error(&error)),
    };
    let message = match operation {
        Operation::GetCaCaps => return Ok(responder.ca_caps_response()),
        Operation::GetCaCert { .. } => return Ok(responder.ca_cert_response()),
        Operation::PkiOperation(message) => message,
    };
    let enrollment = match responder.open(&message) {
        Ok(enrollment) => enrollment,
        Err(Error::Rejected(rejected)) => {
            return Ok(match responder.reject(&rejected)? {
                Some(body) => transport::ok(transport::PKI_MESSAGE, body),
                None => request_error(rejected.cause()),
            });
        }
        Err(error) => return Err(error.into()),
    };
    let issuance = issuer
        .issue(&enrollment)
        .await
        .map_err(HandleError::Issuer)?;
    let reply = responder.reply(&enrollment, issuance)?;
    Ok(transport::ok(transport::PKI_MESSAGE, reply))
}

fn request_error(error: &scep_protocol::Error) -> Response<Bytes> {
    let mut response = Response::new(Bytes::from_static(b"invalid SCEP request"));
    *response.status_mut() = transport::status_for(error);
    response
}

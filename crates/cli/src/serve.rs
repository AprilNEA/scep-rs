//! `scep serve`: HTTP transport for one [`Responder`].

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context as _;
use axum::{
    Router,
    body::Body,
    extract::State,
    response::{IntoResponse as _, Response},
};
use bytes::Bytes;
use http::{Request, StatusCode, request::Parts};
use scep::{
    protocol::{
        Identity,
        transport::{Operation, status_for},
        x509_cert::Certificate,
    },
    server::Responder,
};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

/// Arguments of `scep serve`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// PEM certificate the server signs and decrypts with: the CA or RA certificate.
    #[arg(long, value_name = "FILE")]
    cert: PathBuf,

    /// PEM private key of `--cert`, in PKCS#8 or PKCS#1 form.
    #[arg(long, value_name = "FILE")]
    key: PathBuf,

    /// PEM file with the certificates that issued `--cert`, nearest issuer
    /// first. Omit when `--cert` is the CA itself.
    #[arg(long, value_name = "FILE")]
    chain: Option<PathBuf>,

    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:8080", value_name = "ADDR")]
    listen: SocketAddr,

    /// Directory that receives unverified PKI operation messages as raw CMS
    /// files (BER or DER). Use only with disposable test identities.
    #[arg(long, value_name = "DIR")]
    capture_dir: Option<PathBuf>,
}

struct App {
    responder: Responder,
    capture: Option<Capture>,
}

struct Capture {
    dir: PathBuf,
    sequence: AtomicU64,
}

/// Runs the server until the process exits.
pub async fn run(args: Args) -> anyhow::Result<()> {
    let identity = load_identity(&args.cert, &args.key)?;
    let chain = match &args.chain {
        Some(path) => load_chain(path)?,
        None => Vec::new(),
    };
    let responder = Responder::new(identity, chain)?;
    info!(
        subject = %responder.identity().certificate().tbs_certificate().subject(),
        "serving SCEP"
    );

    let capture = match args.capture_dir {
        Some(dir) => {
            tokio::fs::create_dir_all(&dir)
                .await
                .with_context(|| format!("create {}", dir.display()))?;
            info!(dir = %dir.display(), "capturing PKIOperation messages");
            Some(Capture {
                dir,
                sequence: AtomicU64::new(0),
            })
        }
        None => None,
    };

    let listener = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("bind {}", args.listen))?;
    info!(listen = %listener.local_addr()?, "listening");

    let router = Router::new()
        .fallback(handle)
        .with_state(Arc::new(App { responder, capture }));
    axum::serve(listener, router).await.context("serve")
}

fn load_identity(cert: &Path, key: &Path) -> anyhow::Result<Identity> {
    let cert_pem =
        std::fs::read_to_string(cert).with_context(|| format!("read {}", cert.display()))?;
    let key_pem =
        std::fs::read_to_string(key).with_context(|| format!("read {}", key.display()))?;
    Identity::from_pem(&cert_pem, &key_pem)
        .with_context(|| format!("pair {} with {}", cert.display(), key.display()))
}

fn load_chain(path: &Path) -> anyhow::Result<Vec<Certificate>> {
    let pem = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let chain = Certificate::load_pem_chain(&pem)
        .with_context(|| format!("parse certificates in {}", path.display()))?;
    anyhow::ensure!(!chain.is_empty(), "{} holds no certificate", path.display());
    Ok(chain)
}

async fn handle(State(app): State<Arc<App>>, parts: Parts, body: Bytes) -> Response {
    let method = parts.method.clone();
    let path = parts.uri.path().to_owned();
    let response = match Operation::try_from(Request::from_parts(parts, body)) {
        Ok(Operation::GetCaCaps) => app.responder.ca_caps_response().map(Body::from),
        Ok(Operation::GetCaCert { .. }) => app.responder.ca_cert_response().map(Body::from),
        Ok(Operation::PkiOperation(message)) => app.pki_operation(message).await,
        Err(error) => {
            warn!(%method, %path, %error, "rejected request");
            (status_for(&error), error.to_string()).into_response()
        }
    };
    info!(%method, %path, status = %response.status(), "handled request");
    response
}

impl App {
    async fn pki_operation(&self, message: Bytes) -> Response {
        if let Some(capture) = &self.capture {
            match capture.store(&message).await {
                Ok(path) => {
                    info!(path = %path.display(), bytes = message.len(), "captured PKIOperation");
                }
                Err(error) => {
                    error!(error = format!("{error:#}"), "capture failed");
                    return (StatusCode::INTERNAL_SERVER_ERROR, format!("{error:#}"))
                        .into_response();
                }
            }
        }
        (
            StatusCode::NOT_IMPLEMENTED,
            "PKIOperation is not implemented in this release",
        )
            .into_response()
    }
}

impl Capture {
    async fn store(&self, message: &[u8]) -> anyhow::Result<PathBuf> {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_millis();
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        let path = self.dir.join(format!("{millis}-{sequence:04}.der"));
        tokio::fs::write(&path, message)
            .await
            .with_context(|| format!("write {}", path.display()))?;
        Ok(path)
    }
}

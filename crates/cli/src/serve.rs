//! `scep serve`: HTTP transport for one [`Responder`].

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context as _;
use axum::{
    Router,
    body::Body,
    extract::{DefaultBodyLimit, State},
    response::{IntoResponse as _, Response},
};
use bytes::Bytes;
use http::{Request, StatusCode, request::Parts};
use scep::{
    protocol::{
        Identity, Limits,
        transport::{Operation, status_for},
        x509_cert::Certificate,
    },
    server::{self, KeyBindingPolicy, Responder, ServerConfig},
};
use tokio::net::TcpListener;
use tracing::{error, info, warn};
use zeroize::Zeroizing;

use crate::ca::TestCa;

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

    /// Capture-only directory for unverified CMS messages (BER or DER).
    /// No certificate is issued in this mode. Use disposable test identities.
    #[arg(long, value_name = "DIR", conflicts_with = "challenge_file")]
    capture_dir: Option<PathBuf>,

    /// Enable the test CA using a UTF-8 static challenge file (final CR/LF trimmed).
    #[arg(long, value_name = "FILE")]
    challenge_file: Option<PathBuf>,

    /// Issuing CA certificate, when --cert is an RA rather than the issuer.
    #[arg(long, value_name = "FILE", requires_all = ["issuer_key", "challenge_file"])]
    issuer_cert: Option<PathBuf>,

    /// Private key of --issuer-cert.
    #[arg(long, value_name = "FILE", requires = "issuer_cert")]
    issuer_key: Option<PathBuf>,

    /// CSR/CMS binding: require-same-key or explicit allow-distinct-keys.
    #[arg(long, default_value_t = ServerConfig::default().key_binding)]
    key_binding: KeyBindingPolicy,

    /// Maximum CMS request bytes, also enforced during HTTP body collection.
    #[arg(long, default_value_t = ServerConfig::default().limits.max_request_bytes)]
    max_request_bytes: usize,

    /// Maximum raw query bytes before URL/base64 decoding.
    #[arg(long, default_value_t = ServerConfig::default().limits.max_query_bytes)]
    max_query_bytes: usize,

    /// Test certificate lifetime in days, capped at the CA's expiry.
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u32).range(1..))]
    validity_days: u32,

    /// Maximum transactions retained by the process-local test CA retry cache.
    #[arg(long, default_value_t = 1024)]
    max_transactions: usize,
}

struct App {
    responder: Responder,
    capture: Option<Capture>,
    issuer: Option<TestCa>,
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
    let issuer = match &args.challenge_file {
        Some(path) => {
            let mut challenge = Zeroizing::new(
                std::fs::read_to_string(path)
                    .with_context(|| format!("read {}", path.display()))?,
            );
            let length = challenge.trim_end_matches(['\r', '\n']).len();
            challenge.truncate(length);
            let issuer_identity = match &args.issuer_cert {
                Some(cert) => {
                    let key = args
                        .issuer_key
                        .as_ref()
                        .expect("clap requires --issuer-key with --issuer-cert");
                    load_identity(cert, key)?
                }
                None => identity.clone(),
            };
            warn!(
                "test CA enabled: static challenge authorizes any subject; retry state is lost on restart"
            );
            Some(TestCa::new(
                issuer_identity,
                challenge,
                Duration::from_secs(u64::from(args.validity_days) * 24 * 60 * 60),
                args.max_transactions,
            )?)
        }
        None => None,
    };
    let config = ServerConfig {
        key_binding: args.key_binding,
        limits: Limits {
            max_request_bytes: args.max_request_bytes,
            max_query_bytes: args.max_query_bytes,
            ..Limits::default()
        },
    };
    let responder = Responder::with_config(identity, chain, config)?;
    info!(
        subject = %responder.identity().certificate().tbs_certificate().subject(),
        key_binding = %config.key_binding,
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
        .layer(DefaultBodyLimit::max(config.limits.max_request_bytes))
        .with_state(Arc::new(App {
            responder,
            capture,
            issuer,
        }));
    axum::serve(listener, router).await.context("serve")
}

fn load_identity(cert: &Path, key: &Path) -> anyhow::Result<Identity> {
    let cert_pem =
        std::fs::read_to_string(cert).with_context(|| format!("read {}", cert.display()))?;
    let key_pem = Zeroizing::new(
        std::fs::read_to_string(key).with_context(|| format!("read {}", key.display()))?,
    );
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
    let request = Request::from_parts(parts, body);
    let response = if let Some(issuer) = &app.issuer {
        match server::handle(&app.responder, issuer, request).await {
            Ok(response) => response.map(Body::from),
            Err(error) => {
                error!(%error, "enrollment operation failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "enrollment operation failed",
                )
                    .into_response()
            }
        }
    } else {
        app.capture_request(request).await
    };
    info!(%method, %path, status = %response.status(), "handled request");
    response
}

impl App {
    async fn capture_request(&self, request: Request<Bytes>) -> Response {
        match Operation::from_request(request, &self.responder.config().limits) {
            Ok(Operation::GetCaCaps) => self.responder.ca_caps_response().map(Body::from),
            Ok(Operation::GetCaCert { .. }) => self.responder.ca_cert_response().map(Body::from),
            Ok(Operation::PkiOperation(message)) => self.capture_message(message).await,
            Err(error) => (status_for(&error), "invalid SCEP request").into_response(),
        }
    }

    async fn capture_message(&self, message: Bytes) -> Response {
        if let Some(capture) = &self.capture {
            match capture.store(&message).await {
                Ok(path) => {
                    info!(path = %path.display(), bytes = message.len(), "captured PKIOperation");
                }
                Err(error) => {
                    error!(error = format!("{error:#}"), "capture failed");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "capture failed").into_response();
                }
            }
        }
        (
            StatusCode::NOT_IMPLEMENTED,
            "certificate issuance is disabled; configure --challenge-file for the test CA",
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

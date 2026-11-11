use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use clap::{Parser, ValueEnum};
use serde::Serialize;
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use webhook_security_tester::{config::Profile, crypto};

#[derive(Parser)]
#[command(
    about = "Loopback-only test receiver. Vulnerable modes are deliberate fixtures, never production settings."
)]
struct Args {
    #[arg(long, value_enum)]
    profile: Profile,
    #[arg(long, default_value_t = 8787)]
    port: u16,
    #[arg(long,value_enum,default_value_t=Mode::Secure)]
    mode: Mode,
    #[arg(long, default_value_t = 300)]
    tolerance_seconds: i64,
    #[arg(long, default_value_t = 30)]
    future_skew_seconds: i64,
    #[arg(long)]
    secret_env: Option<String>,
    /// Test-only processed-ID state; enables restart replay tests.
    #[arg(long)]
    state_file: Option<PathBuf>,
}
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum, Debug)]
enum Mode {
    Secure,
    NoSignature,
    ReserializedBody,
    NoDedup,
    DeliveryIdOnly,
    NoTimestamp,
}
#[derive(Default)]
struct Counters {
    received_request_count: u64,
    authenticated_request_count: u64,
    rejected_request_count: u64,
    completed_processing_count: u64,
    duplicate_suppression_count: u64,
    processed: HashSet<String>,
}
#[derive(Serialize)]
struct Observation {
    received_request_count: u64,
    authenticated_request_count: u64,
    rejected_request_count: u64,
    completed_processing_count: u64,
    unique_processed_event_count: usize,
    duplicate_suppression_count: u64,
    processed_event_ids: Vec<String>,
}
struct App {
    secret: Vec<u8>,
    profile: Profile,
    mode: Mode,
    tolerance: i64,
    skew: i64,
    counters: Mutex<Counters>,
    state_file: Option<PathBuf>,
}
type Shared = Arc<App>;
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
fn one_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}
async fn receive(State(app): State<Shared>, headers: HeaderMap, body: Bytes) -> StatusCode {
    let mut counters = app.counters.lock().await;
    counters.received_request_count += 1;
    if body.len() > 65536 {
        counters.rejected_request_count += 1;
        return StatusCode::PAYLOAD_TOO_LARGE;
    }
    let check_body = if app.mode == Mode::ReserializedBody {
        serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| serde_json::to_vec(&v).ok())
            .unwrap_or_default()
    } else {
        body.to_vec()
    };
    let verified = if app.mode == Mode::NoSignature {
        true
    } else {
        match app.profile {
            Profile::Github => one_header(&headers, "x-hub-signature-256")
                .is_some_and(|v| crypto::github_verify(&app.secret, &check_body, v)),
            Profile::TimestampedHmacV1 => one_header(&headers, "webhookproof-signature")
                .is_some_and(|v| {
                    crypto::timestamp_verify(
                        &app.secret,
                        &check_body,
                        v,
                        now(),
                        if app.mode == Mode::NoTimestamp {
                            i64::MAX / 4
                        } else {
                            app.tolerance
                        },
                        if app.mode == Mode::NoTimestamp {
                            i64::MAX / 4
                        } else {
                            app.skew
                        },
                    )
                }),
        }
    };
    if !verified {
        counters.rejected_request_count += 1;
        return StatusCode::UNAUTHORIZED;
    }
    counters.authenticated_request_count += 1;
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) else {
        counters.rejected_request_count += 1;
        return StatusCode::BAD_REQUEST;
    };
    let Some(id) = value
        .get("id")
        .and_then(|x| x.as_str())
        .filter(|x| !x.is_empty())
    else {
        counters.rejected_request_count += 1;
        return StatusCode::BAD_REQUEST;
    };
    let key = if app.mode == Mode::DeliveryIdOnly && app.profile == Profile::Github {
        one_header(&headers, "x-github-delivery")
            .unwrap_or("")
            .to_string()
    } else {
        id.to_string()
    };
    let persisted_key = key.clone();
    if app.mode == Mode::NoDedup {
        counters.processed.insert(key);
    } else if !counters.processed.insert(key) {
        counters.duplicate_suppression_count += 1;
        return StatusCode::OK;
    }
    if let Some(path) = &app.state_file {
        let bytes = match serde_json::to_vec(&counters.processed) {
            Ok(bytes) => bytes,
            Err(_) => {
                counters.processed.remove(&persisted_key);
                return StatusCode::INTERNAL_SERVER_ERROR;
            }
        };
        let temporary = path.with_extension("webhook-security-tester-tmp");
        if std::fs::write(&temporary, bytes).is_err() || std::fs::rename(&temporary, path).is_err()
        {
            counters.processed.remove(&persisted_key);
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    }
    counters.completed_processing_count += 1;
    StatusCode::OK
}
async fn observations(State(app): State<Shared>) -> Json<Observation> {
    let c = app.counters.lock().await;
    let mut ids = c.processed.iter().cloned().collect::<Vec<_>>();
    ids.sort();
    Json(Observation {
        received_request_count: c.received_request_count,
        authenticated_request_count: c.authenticated_request_count,
        rejected_request_count: c.rejected_request_count,
        completed_processing_count: c.completed_processing_count,
        unique_processed_event_count: c.processed.len(),
        duplicate_suppression_count: c.duplicate_suppression_count,
        processed_event_ids: ids,
    })
}
async fn reset(State(app): State<Shared>) -> StatusCode {
    if let Some(path) = &app.state_file {
        if path.exists() && std::fs::remove_file(path).is_err() {
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    }
    *app.counters.lock().await = Counters::default();
    StatusCode::NO_CONTENT
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let env_name = args.secret_env.unwrap_or_else(|| {
        match args.profile {
            Profile::Github => "WEBHOOK_SECURITY_TESTER_GITHUB_SECRET",
            Profile::TimestampedHmacV1 => "WEBHOOK_SECURITY_TESTER_TIMESTAMP_SECRET",
        }
        .into()
    });
    let secret = std::env::var(&env_name).map_err(|_| anyhow::anyhow!("{env_name} is not set"))?;
    anyhow::ensure!(!secret.is_empty(), "{env_name} is empty");
    anyhow::ensure!(
        (30..=86400).contains(&args.tolerance_seconds),
        "tolerance must be 30..86400 seconds"
    );
    anyhow::ensure!(
        (0..=3600).contains(&args.future_skew_seconds),
        "future skew must be 0..3600 seconds"
    );
    let app = Arc::new(App {
        secret: secret.into_bytes(),
        profile: args.profile,
        mode: args.mode,
        tolerance: args.tolerance_seconds,
        skew: args.future_skew_seconds,
        counters: Mutex::new(Counters {
            processed: if let Some(path) = &args.state_file {
                if path.exists() {
                    serde_json::from_slice(&std::fs::read(path)?)?
                } else {
                    HashSet::new()
                }
            } else {
                HashSet::new()
            },
            ..Counters::default()
        }),
        state_file: args.state_file,
    });
    let router = Router::new()
        .route("/webhooks/github", post(receive))
        .route("/webhooks/timestamped", post(receive))
        .route("/__webhookproof/observations", get(observations))
        .route("/__webhookproof/reset", post(reset))
        .with_state(app);
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), args.port);
    let listener = tokio::net::TcpListener::bind(address).await?;
    println!(
        "Webhook Security Tester TEST receiver: {} mode {:?} on {}",
        match args.profile {
            Profile::Github => "github",
            Profile::TimestampedHmacV1 => "timestamped-hmac-v1",
        },
        args.mode,
        listener.local_addr()?
    );
    axum::serve(listener, router).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn app(profile: Profile, mode: Mode) -> Shared {
        Arc::new(App {
            secret: b"test-secret".to_vec(),
            profile,
            mode,
            tolerance: 300,
            skew: 30,
            counters: Mutex::new(Counters::default()),
            state_file: None,
        })
    }
    fn github_headers(body: &[u8], delivery: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            "x-hub-signature-256",
            crypto::github_sign(b"test-secret", body).parse().unwrap(),
        );
        h.insert("x-github-delivery", delivery.parse().unwrap());
        h
    }
    #[tokio::test]
    async fn secure_rejects_mutation_and_suppresses_changed_delivery_id() {
        let a = app(Profile::Github, Mode::Secure);
        let body = br#"{"id":"event-1","action":"created"}"#;
        assert_eq!(
            receive(
                State(a.clone()),
                github_headers(body, "one"),
                Bytes::copy_from_slice(body)
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(
            receive(
                State(a.clone()),
                github_headers(body, "two"),
                Bytes::copy_from_slice(body)
            )
            .await,
            StatusCode::OK
        );
        let mut changed = body.to_vec();
        changed[18] = b'X';
        assert_eq!(
            receive(
                State(a.clone()),
                github_headers(body, "three"),
                Bytes::from(changed)
            )
            .await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(a.counters.lock().await.completed_processing_count, 1);
    }
    #[tokio::test]
    async fn vulnerable_modes_are_detectable() {
        let body = br#"{"id":"event-1"}"#;
        let a = app(Profile::Github, Mode::NoSignature);
        assert_eq!(
            receive(State(a), HeaderMap::new(), Bytes::copy_from_slice(body)).await,
            StatusCode::OK
        );
        let a = app(Profile::Github, Mode::DeliveryIdOnly);
        for delivery in ["one", "two"] {
            assert_eq!(
                receive(
                    State(a.clone()),
                    github_headers(body, delivery),
                    Bytes::copy_from_slice(body)
                )
                .await,
                StatusCode::OK
            );
        }
        assert_eq!(a.counters.lock().await.completed_processing_count, 2);
    }
    #[tokio::test]
    async fn expired_signed_timestamp_rejected() {
        let a = app(Profile::TimestampedHmacV1, Mode::Secure);
        let body = br#"{"id":"event-1"}"#;
        let mut h = HeaderMap::new();
        h.insert(
            "webhookproof-signature",
            crypto::timestamp_sign(b"test-secret", body, now() - 360)
                .parse()
                .unwrap(),
        );
        assert_eq!(
            receive(State(a), h, Bytes::copy_from_slice(body)).await,
            StatusCode::UNAUTHORIZED
        );
    }
}

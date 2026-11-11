use std::{
    collections::HashSet,
    net::TcpListener,
    process::{Child, Command, Stdio},
    time::Duration,
};
use webhook_security_tester::{config::Config, fixture::Category, report::Classification, runner};

struct Receiver(Child);
impl Drop for Receiver {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
async fn start(profile: &str, mode: &str, port: u16) -> Receiver {
    start_with_state(profile, mode, port, None).await
}
async fn start_with_state(
    profile: &str,
    mode: &str,
    port: u16,
    state: Option<&std::path::Path>,
) -> Receiver {
    let mut command = Command::new(env!(
        "CARGO_BIN_EXE_webhook-security-tester-reference-receiver"
    ));
    command.args([
        "--profile",
        profile,
        "--mode",
        mode,
        "--port",
        &port.to_string(),
    ]);
    if let Some(path) = state {
        command.arg("--state-file").arg(path);
    }
    let child = command
        .env(
            "WEBHOOK_SECURITY_TESTER_GITHUB_SECRET",
            "integration-secret",
        )
        .env(
            "WEBHOOK_SECURITY_TESTER_TIMESTAMP_SECRET",
            "integration-secret",
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let receiver = Receiver(child);
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    for _ in 0..50 {
        if client
            .get(format!(
                "http://127.0.0.1:{port}/__webhookproof/observations"
            ))
            .send()
            .await
            .is_ok()
        {
            return receiver;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("reference receiver did not start")
}
#[tokio::test]
async fn replay_after_restart_uses_persisted_state() {
    let port = free_port();
    let state = std::env::temp_dir().join(format!(
        "webhook-security-tester-state-{}-{port}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&state);
    let body = br#"{"id":"restart-event"}"#;
    let signature = webhook_security_tester::crypto::github_sign(b"integration-secret", body);
    let client = reqwest::Client::builder()
        .no_proxy()
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();
    let endpoint = format!("http://127.0.0.1:{port}/webhooks/github");
    {
        let _receiver = start_with_state("github", "secure", port, Some(&state)).await;
        let response = client
            .post(&endpoint)
            .header("x-hub-signature-256", &signature)
            .body(body.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let value: serde_json::Value = client
            .get(format!(
                "http://127.0.0.1:{port}/__webhookproof/observations"
            ))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(value["completed_processing_count"], 1);
    }
    {
        let _receiver = start_with_state("github", "secure", port, Some(&state)).await;
        let response = client
            .post(&endpoint)
            .header("x-hub-signature-256", &signature)
            .body(body.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let value: serde_json::Value = client
            .get(format!(
                "http://127.0.0.1:{port}/__webhookproof/observations"
            ))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(value["completed_processing_count"], 0);
        assert_eq!(value["duplicate_suppression_count"], 1);
    }
    let _ = std::fs::remove_file(state);
}
fn config(profile: &str, port: u16, observer: bool) -> Config {
    let path = if profile == "github" {
        "github"
    } else {
        "timestamped"
    };
    toml::from_str(&format!("version=1\nprofile='{profile}'\nendpoint='http://127.0.0.1:{port}/webhooks/{path}'\nsecret_env='WEBHOOK_SECURITY_TESTER_TEST_SECRET'\n[observer]\nenabled={observer}\nrequire=false\n")).unwrap()
}
fn categories(values: &[Category]) -> HashSet<Category> {
    values.iter().copied().collect()
}
#[tokio::test]
async fn secure_receiver_and_observer_report_real_processing() {
    let port = free_port();
    let _receiver = start("github", "secure", port).await;
    std::env::set_var("WEBHOOK_SECURITY_TESTER_TEST_SECRET", "integration-secret");
    let report = runner::run(
        &config("github", port, true),
        &categories(&[Category::Signature, Category::Replay, Category::Duplicate]),
    )
    .await
    .unwrap();
    assert_eq!(report.summary.failed, 0);
    assert_eq!(report.summary.errors, 0);
    assert_eq!(report.summary.inconclusive, 0);
    assert_eq!(
        report
            .results
            .iter()
            .find(|r| r.id == "REPLAY-004")
            .unwrap()
            .observed_processing_count,
        Some(1)
    );
}
#[tokio::test]
async fn vulnerable_modes_and_http_only_are_honest() {
    let port = free_port();
    let _receiver = start("github", "no-signature", port).await;
    std::env::set_var("WEBHOOK_SECURITY_TESTER_TEST_SECRET", "integration-secret");
    let report = runner::run(
        &config("github", port, false),
        &categories(&[Category::Signature, Category::Duplicate]),
    )
    .await
    .unwrap();
    assert!(report.summary.failed > 0);
    assert_eq!(
        report
            .results
            .iter()
            .find(|r| r.id == "GH-SIG-002")
            .unwrap()
            .classification,
        Classification::Fail
    );
    assert_eq!(
        report
            .results
            .iter()
            .find(|r| r.id == "DUP-001")
            .unwrap()
            .classification,
        Classification::Inconclusive
    );
}
#[tokio::test]
async fn timestamp_expiration_is_enforced() {
    let port = free_port();
    let _receiver = start("timestamped-hmac-v1", "secure", port).await;
    std::env::set_var("WEBHOOK_SECURITY_TESTER_TEST_SECRET", "integration-secret");
    let report = runner::run(
        &config("timestamped-hmac-v1", port, true),
        &categories(&[Category::Timestamp]),
    )
    .await
    .unwrap();
    assert_eq!(report.summary.failed, 0);
    assert_eq!(report.summary.errors, 0);
    assert_eq!(report.summary.inconclusive, 0);
    assert_eq!(
        report
            .results
            .iter()
            .find(|r| r.id == "TS-002")
            .unwrap()
            .observed_statuses,
        vec![401]
    );
}

#[tokio::test]
async fn deliberately_vulnerable_modes_produce_findings() {
    std::env::set_var("WEBHOOK_SECURITY_TESTER_TEST_SECRET", "integration-secret");
    for (profile, mode, category, id) in [
        (
            "github",
            "reserialized-body",
            Category::Signature,
            "GH-SIG-010",
        ),
        ("github", "no-dedup", Category::Duplicate, "DUP-001"),
        ("github", "delivery-id-only", Category::Replay, "REPLAY-004"),
        (
            "timestamped-hmac-v1",
            "no-timestamp",
            Category::Timestamp,
            "TS-002",
        ),
    ] {
        let port = free_port();
        let _receiver = start(profile, mode, port).await;
        let report = runner::run(&config(profile, port, true), &categories(&[category]))
            .await
            .unwrap();
        assert_eq!(
            report
                .results
                .iter()
                .find(|r| r.id == id)
                .unwrap()
                .classification,
            Classification::Fail,
            "{mode} did not fail {id}"
        );
        assert!(report.findings.iter().any(|f| f.rule_id == id));
    }
}

#[tokio::test]
async fn refused_connection_is_error_and_reports_redact_secret() {
    std::env::set_var("WEBHOOK_SECURITY_TESTER_TEST_SECRET", "integration-secret");
    let port = free_port();
    let report = runner::run(
        &config("github", port, false),
        &categories(&[Category::Signature]),
    )
    .await
    .unwrap();
    assert!(report.summary.errors > 0);
    assert_eq!(report.exit_code(false), 2);
    let json = serde_json::to_string(&report).unwrap();
    assert!(!json.contains("integration-secret"));
}

#[tokio::test]
async fn redirects_are_not_followed() {
    use axum::{http::StatusCode, routing::post, Router};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let router = Router::new().route(
        "/webhooks/github",
        post(|| async { (StatusCode::FOUND, [("location", "http://example.com/")]) }),
    );
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    std::env::set_var("WEBHOOK_SECURITY_TESTER_TEST_SECRET", "integration-secret");
    let report = runner::run(
        &config("github", port, false),
        &categories(&[Category::Signature]),
    )
    .await
    .unwrap();
    server.abort();
    assert!(report.summary.failed > 0);
    assert_eq!(
        report
            .results
            .iter()
            .find(|r| r.id == "GH-SIG-001")
            .unwrap()
            .observed_statuses,
        vec![302]
    );
}

#[tokio::test]
async fn timeouts_are_execution_errors() {
    use axum::{http::StatusCode, routing::post, Router};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let router = Router::new().route(
        "/webhooks/github",
        post(|| async {
            tokio::time::sleep(Duration::from_millis(250)).await;
            StatusCode::OK
        }),
    );
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    std::env::set_var("WEBHOOK_SECURITY_TESTER_TEST_SECRET", "integration-secret");
    let mut c = config("github", port, false);
    c.timeout_ms = 100;
    let report = runner::run(&c, &categories(&[Category::Signature]))
        .await
        .unwrap();
    server.abort();
    assert!(report.summary.errors > 0);
    assert_eq!(
        report
            .results
            .iter()
            .find(|r| r.id == "GH-SIG-001")
            .unwrap()
            .classification,
        Classification::Error
    );
}

#[tokio::test]
async fn observer_redirect_never_counts_as_a_reset() {
    use axum::{
        http::StatusCode,
        routing::{get, post},
        Router,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let router = Router::new()
        .route("/webhooks/github", post(|| async { StatusCode::OK }))
        .route(
            "/__webhookproof/reset",
            post(|| async { (StatusCode::FOUND, [("location", "/other")]) }),
        )
        .route(
            "/__webhookproof/observations",
            get(|| async { "{\"completed_processing_count\":1}" }),
        );
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    std::env::set_var("WEBHOOK_SECURITY_TESTER_TEST_SECRET", "integration-secret");
    let mut c = config("github", port, true);
    c.observer.require = true;
    let report = runner::run(&c, &categories(&[Category::Duplicate]))
        .await
        .unwrap();
    server.abort();
    assert!(!report.observer_available);
    assert!(report.capability_summary.contains("302"));
    assert_eq!(
        report
            .results
            .iter()
            .find(|r| r.id == "DUP-001")
            .unwrap()
            .classification,
        Classification::Inconclusive
    );
    assert_eq!(report.exit_code(true), 2);
}

#[tokio::test]
async fn oversized_observer_response_is_unavailable() {
    use axum::{
        http::StatusCode,
        routing::{get, post},
        Router,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let large = format!(
        "{{\"completed_processing_count\":1,\"padding\":\"{}\"}}",
        "a".repeat(9000)
    );
    let router = Router::new()
        .route("/webhooks/github", post(|| async { StatusCode::OK }))
        .route(
            "/__webhookproof/reset",
            post(|| async { StatusCode::NO_CONTENT }),
        )
        .route(
            "/__webhookproof/observations",
            get(move || {
                let value = large.clone();
                async move { value }
            }),
        );
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    std::env::set_var("WEBHOOK_SECURITY_TESTER_TEST_SECRET", "integration-secret");
    let report = runner::run(
        &config("github", port, true),
        &categories(&[Category::Duplicate]),
    )
    .await
    .unwrap();
    server.abort();
    assert!(!report.observer_available);
    assert_eq!(
        report
            .results
            .iter()
            .find(|r| r.id == "DUP-001")
            .unwrap()
            .classification,
        Classification::Inconclusive
    );
}

#[tokio::test]
async fn delayed_second_effect_cannot_be_mistaken_for_suppression() {
    use axum::{
        http::StatusCode,
        routing::{get, post},
        Router,
    };
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let attempts = Arc::new(AtomicU64::new(0));
    let completed = Arc::new(AtomicU64::new(0));
    let receive_attempts = attempts.clone();
    let receive_completed = completed.clone();
    let reset_attempts = attempts.clone();
    let reset_completed = completed.clone();
    let read_completed = completed.clone();
    let router = Router::new()
        .route(
            "/webhooks/github",
            post(move || {
                let a = receive_attempts.clone();
                let c = receive_completed.clone();
                async move {
                    if a.fetch_add(1, Ordering::SeqCst) == 0 {
                        c.fetch_add(1, Ordering::SeqCst);
                    } else {
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(150)).await;
                            c.fetch_add(1, Ordering::SeqCst);
                        });
                    }
                    StatusCode::OK
                }
            }),
        )
        .route(
            "/__webhookproof/reset",
            post(move || {
                let a = reset_attempts.clone();
                let c = reset_completed.clone();
                async move {
                    a.store(0, Ordering::SeqCst);
                    c.store(0, Ordering::SeqCst);
                    StatusCode::NO_CONTENT
                }
            }),
        )
        .route(
            "/__webhookproof/observations",
            get(move || {
                let c = read_completed.clone();
                async move {
                    format!(
                        "{{\"completed_processing_count\":{}}}",
                        c.load(Ordering::SeqCst)
                    )
                }
            }),
        );
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    std::env::set_var("WEBHOOK_SECURITY_TESTER_TEST_SECRET", "integration-secret");
    let mut c = config("github", port, true);
    c.observer.settle_ms = 300;
    let report = runner::run(&c, &categories(&[Category::Duplicate]))
        .await
        .unwrap();
    server.abort();
    let result = report.results.iter().find(|r| r.id == "DUP-001").unwrap();
    assert_eq!(result.observed_processing_count, Some(2));
    assert_eq!(result.classification, Classification::Fail);
}

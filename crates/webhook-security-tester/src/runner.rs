use crate::{
    config::Config,
    fixture::{self, Category, Expectation, Mutation, Scenario},
    report::{Classification, Report, ResultItem},
};
use anyhow::{Context, Result};
use reqwest::{redirect::Policy, Client};
use serde::Deserialize;
use std::{
    collections::HashSet,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use url::Url;

#[derive(Deserialize)]
struct Observation {
    completed_processing_count: u64,
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
fn client(config: &Config) -> Result<Client> {
    let (url, pin) = config.destination()?;
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .timeout(config.timeout())
        .pool_max_idle_per_host(0);
    if let Some((host, ip)) = pin {
        builder = builder.resolve(
            &host,
            std::net::SocketAddr::new(ip, url.port_or_known_default().unwrap_or(80)),
        );
    }
    builder
        .build()
        .context("cannot construct local HTTP client")
}
fn observer_url(url: &Url, route: &str) -> Url {
    let mut u = url.clone();
    u.set_path(route);
    u.set_query(None);
    u
}
async fn reset(client: &Client, url: &Url) -> Result<()> {
    let response = client
        .post(observer_url(url, "/__webhookproof/reset"))
        .send()
        .await?;
    anyhow::ensure!(
        response.status().is_success(),
        "observer reset returned HTTP {}",
        response.status()
    );
    Ok(())
}
async fn observe(client: &Client, url: &Url) -> Result<u64> {
    let mut response = client
        .get(observer_url(url, "/__webhookproof/observations"))
        .send()
        .await?;
    anyhow::ensure!(
        response.status().is_success(),
        "observer read returned HTTP {}",
        response.status()
    );
    if response.content_length().is_some_and(|n| n > 8192) {
        anyhow::bail!("observer response exceeded 8192 bytes");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > 8192 {
            anyhow::bail!("observer response exceeded 8192 bytes");
        }
        bytes.extend_from_slice(&chunk);
    }
    let data: Observation =
        serde_json::from_slice(&bytes).context("observer returned invalid JSON")?;
    Ok(data.completed_processing_count)
}

pub async fn run(config: &Config, only: &HashSet<Category>) -> Result<Report> {
    config.validate()?;
    let secret = config.secret()?;
    let url = config.url()?;
    let client = client(config)?;
    let start = Instant::now();
    let started = now();
    let mut report = Report::new(config, started);
    let mut selected = fixture::SCENARIOS
        .iter()
        .filter(|s| only.is_empty() || only.contains(&s.category))
        .collect::<Vec<_>>();
    if (only.is_empty() || only.contains(&Category::Timestamp))
        && !config.profile.capabilities().signed_timestamp
    {
        report.results.push(ResultItem {
            id: "TS-012".into(),
            category: Category::Timestamp,
            description: "GitHub signed timestamp".into(),
            expected: "Not applicable".into(),
            observed_statuses: vec![],
            observed_processing_count: None,
            classification: Classification::Skip,
            duration_ms: 0,
            explanation: "GitHub's body HMAC contains no signed timestamp".into(),
            remediation: None,
        });
        report.summary.skipped += 1;
    }
    for category in only {
        if !fixture::SCENARIOS
            .iter()
            .any(|s| s.profile == config.profile && s.category == *category)
            && !(!config.profile.capabilities().signed_timestamp
                && *category == Category::Timestamp)
        {
            report.results.push(ResultItem {
                id: format!("UNSUPPORTED-{category:?}").to_uppercase(),
                category: *category,
                description: "Category unavailable for selected profile".into(),
                expected: "Not applicable".into(),
                observed_statuses: vec![],
                observed_processing_count: None,
                classification: Classification::Skip,
                duration_ms: 0,
                explanation: format!(
                    "{category:?} scenarios are not defined for {:?}",
                    config.profile
                ),
                remediation: None,
            });
            report.summary.skipped += 1;
        }
    }
    selected.retain(|s| s.profile == config.profile);
    let policy = config.timestamp_policy();
    for s in selected {
        let began = Instant::now();
        let deliveries = fixture::deliveries(
            s,
            &secret,
            now(),
            policy.tolerance_seconds,
            policy.future_skew_seconds,
            config.runner.concurrency,
        );
        let deliveries = match deliveries {
            Ok(d) => d,
            Err(e) => {
                report.push(
                    s,
                    ResultItem {
                        id: s.id.into(),
                        category: s.category,
                        description: s.description.into(),
                        expected: format!("{:?}", s.expected),
                        observed_statuses: vec![],
                        observed_processing_count: None,
                        classification: Classification::Error,
                        duration_ms: began.elapsed().as_millis(),
                        explanation: format!("Fixture generation error: {e}"),
                        remediation: None,
                    },
                );
                continue;
            }
        };
        let mut statuses = Vec::new();
        let mut transport_error = None;
        let mut count = None;
        let mut observer_ready = config.observer.enabled;
        if deliveries
            .iter()
            .any(|d| d.body.len() > config.runner.max_body_bytes)
        {
            transport_error = Some("fixture exceeds configured request body limit".to_owned());
        }
        let reset_error = if transport_error.is_none() && observer_ready {
            reset(&client, &url).await.err()
        } else {
            None
        };
        if let Some(error) = reset_error {
            observer_ready = false;
            report.observer_available = false;
            report.capability_summary = format!("Observer reset unavailable ({error}); processing assertions are inconclusive. HTTP assertions still ran.");
        }
        if transport_error.is_none() {
            if s.mutation == Mutation::ConcurrentDuplicate {
                let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(deliveries.len()));
                let tasks = deliveries
                    .into_iter()
                    .map(|d| {
                        let c = client.clone();
                        let u = url.clone();
                        let b = barrier.clone();
                        tokio::spawn(async move {
                            b.wait().await;
                            send(&c, &u, d).await
                        })
                    })
                    .collect::<Vec<_>>();
                for t in tasks {
                    match t.await {
                        Ok(Ok(status)) => statuses.push(status),
                        Ok(Err(e)) => transport_error = Some(e.to_string()),
                        Err(e) => transport_error = Some(e.to_string()),
                    }
                }
            } else {
                for d in deliveries {
                    match send(&client, &url, d).await {
                        Ok(status) => statuses.push(status),
                        Err(e) => {
                            transport_error = Some(e.to_string());
                            break;
                        }
                    }
                }
            }
        }
        if transport_error.is_none()
            && observer_ready
            && matches!(
                s.expected,
                Expectation::ProcessOnce | Expectation::ProcessTwice
            )
        {
            tokio::time::sleep(std::time::Duration::from_millis(config.observer.settle_ms)).await;
        }
        if transport_error.is_none() && observer_ready {
            match observe(&client, &url).await {
                Ok(n) => count = Some(n),
                Err(error) => {
                    report.observer_available = false;
                    report.capability_summary = format!("Observer read unavailable ({error}); processing assertions are inconclusive.");
                }
            }
        }
        let (classification, explanation) =
            classify(s, &statuses, count, transport_error.as_deref(), config);
        report.push(
            s,
            ResultItem {
                id: s.id.into(),
                category: s.category,
                description: s.description.into(),
                expected: if s.mutation == Mutation::AmbiguousHeaders
                    && !config.expectations.require_unambiguous_signature_header
                {
                    "Strict rejection not declared; acceptance is inconclusive".into()
                } else {
                    format!("{:?}", s.expected)
                },
                observed_statuses: statuses,
                observed_processing_count: count,
                classification,
                duration_ms: began.elapsed().as_millis(),
                explanation,
                remediation: if classification == Classification::Fail {
                    Some(s.remediation.into())
                } else {
                    None
                },
            },
        );
    }
    report.duration_ms = start.elapsed().as_millis();
    Ok(report)
}
async fn send(client: &Client, url: &Url, d: fixture::Delivery) -> Result<u16> {
    let mut req = client.post(url.clone()).body(d.body);
    for (k, v) in d.headers {
        req = req.header(k, v);
    }
    let mut response = req.send().await?;
    // Consume at most 8 KiB; response content is never stored in reports.
    let status = response.status().as_u16();
    let mut total = 0usize;
    while let Some(chunk) = response.chunk().await? {
        total += chunk.len();
        if total > 8192 {
            anyhow::bail!("response body exceeded 8192 bytes");
        }
    }
    Ok(status)
}
fn classify(
    s: &Scenario,
    statuses: &[u16],
    count: Option<u64>,
    error: Option<&str>,
    config: &Config,
) -> (Classification, String) {
    if let Some(error) = error {
        return (Classification::Error, format!("Execution error: {error}"));
    }
    if statuses.is_empty() {
        return (Classification::Error, "No HTTP response observed".into());
    }
    let expected_count = fixture::delivery_count(s, config.runner.concurrency);
    if statuses.len() != expected_count {
        return (
            Classification::Error,
            format!(
                "Observed {} of {expected_count} planned HTTP responses",
                statuses.len()
            ),
        );
    }
    if s.mutation == Mutation::AmbiguousHeaders
        && !config.expectations.require_unambiguous_signature_header
        && statuses
            .iter()
            .all(|s| config.expectations.accept_statuses.contains(s))
    {
        return (Classification::Inconclusive,"Ambiguous signature headers were accepted, but strict rejection was not declared in expectations.require_unambiguous_signature_header".into());
    }
    let accepted = &config.expectations.accept_statuses;
    let rejected = &config.expectations.reject_statuses;
    let duplicates = &config.expectations.duplicate_statuses;
    let status_ok = match s.expected {
        Expectation::Accept => statuses.iter().all(|x| accepted.contains(x)),
        Expectation::Reject => statuses.iter().all(|x| rejected.contains(x)),
        Expectation::ProcessTwice => statuses.iter().all(|x| accepted.contains(x)),
        Expectation::ProcessOnce if s.mutation == Mutation::ConcurrentDuplicate => {
            statuses.iter().any(|x| accepted.contains(x))
                && statuses
                    .iter()
                    .all(|x| accepted.contains(x) || duplicates.contains(x))
        }
        Expectation::ProcessOnce => {
            accepted.contains(&statuses[0]) && statuses[1..].iter().all(|x| duplicates.contains(x))
        }
    };
    if !status_ok {
        return (
            Classification::Fail,
            format!(
                "HTTP statuses {:?}; expected first/distinct deliveries {:?}, duplicate deliveries {:?}, rejection {:?}",
                statuses, accepted, duplicates, rejected
            ),
        );
    }
    match s.expected {
        Expectation::ProcessOnce | Expectation::ProcessTwice => match count {
            None => (
                Classification::Inconclusive,
                format!(
                    "HTTP statuses {:?}; processing side effects unobserved",
                    statuses
                ),
            ),
            Some(n) => {
                let expected = if matches!(s.expected, Expectation::ProcessOnce) {
                    1
                } else {
                    2
                };
                if n == expected {
                    (
                        Classification::Pass,
                        format!(
                            "HTTP statuses {:?}; observed {} completed processing effect(s) after {} ms settling window",
                            statuses, n,config.observer.settle_ms
                        ),
                    )
                } else {
                    (Classification::Fail,format!("HTTP statuses {:?}; observed {} completed processing effect(s) after {} ms settling window, expected {}",statuses,n,config.observer.settle_ms,expected))
                }
            }
        },
        _ => (
            Classification::Pass,
            format!("HTTP statuses {:?} matched declared expectation", statuses),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn processing_needs_observer() {
        let c: Config =
            toml::from_str(include_str!("../examples/webhook-security-tester.toml")).unwrap();
        let s = fixture::find("DUP-001").unwrap();
        assert_eq!(
            classify(s, &[200, 200], None, None, &c).0,
            Classification::Inconclusive
        );
        assert_eq!(
            classify(s, &[200, 200], Some(2), None, &c).0,
            Classification::Fail
        );
        assert_eq!(
            classify(s, &[200, 200], Some(1), None, &c).0,
            Classification::Pass
        );
        assert_eq!(
            classify(s, &[], None, Some("connection refused"), &c).0,
            Classification::Error
        );
    }
    #[test]
    fn duplicate_http_policy_needs_first_acceptance_and_observer() {
        let mut c: Config =
            toml::from_str(include_str!("../examples/webhook-security-tester.toml")).unwrap();
        c.expectations.duplicate_statuses = vec![200, 409];
        c.validate().unwrap();
        let sequential = fixture::find("DUP-001").unwrap();
        assert_eq!(
            classify(sequential, &[200, 409], Some(1), None, &c).0,
            Classification::Pass
        );
        assert_eq!(
            classify(sequential, &[200, 409], None, None, &c).0,
            Classification::Inconclusive
        );
        assert_eq!(
            classify(sequential, &[409, 200], Some(1), None, &c).0,
            Classification::Fail
        );
        let distinct = fixture::find("DUP-003").unwrap();
        assert_eq!(
            classify(distinct, &[200, 409], Some(2), None, &c).0,
            Classification::Fail
        );
        let concurrent = fixture::find("DUP-002").unwrap();
        let mut statuses = vec![409; c.runner.concurrency];
        statuses[2] = 200;
        assert_eq!(
            classify(concurrent, &statuses, Some(1), None, &c).0,
            Classification::Pass
        );
    }
    #[test]
    fn ambiguous_header_requires_declared_strict_policy_for_failure() {
        let mut c: Config =
            toml::from_str(include_str!("../examples/webhook-security-tester.toml")).unwrap();
        let s = fixture::find("GH-SIG-015").unwrap();
        c.expectations.require_unambiguous_signature_header = false;
        assert_eq!(
            classify(s, &[200], None, None, &c).0,
            Classification::Inconclusive
        );
        c.expectations.require_unambiguous_signature_header = true;
        assert_eq!(classify(s, &[200], None, None, &c).0, Classification::Fail);
    }
}

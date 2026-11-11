use crate::{
    config::{Config, Profile},
    fixture::{self, Category, Expectation, Scenario},
    profiles::Capabilities,
};
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Classification {
    Pass,
    Fail,
    Inconclusive,
    Skip,
    Error,
}
#[derive(Debug, Serialize)]
pub struct ResultItem {
    pub id: String,
    pub category: Category,
    pub description: String,
    pub expected: String,
    pub observed_statuses: Vec<u16>,
    pub observed_processing_count: Option<u64>,
    pub classification: Classification,
    pub duration_ms: u128,
    pub explanation: String,
    pub remediation: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: &'static str,
    pub title: String,
    pub evidence: String,
    pub impact: String,
    pub remediation: String,
    pub reference: String,
}
#[derive(Debug, Default, Serialize)]
pub struct Summary {
    pub passed: usize,
    pub failed: usize,
    pub inconclusive: usize,
    pub skipped: usize,
    pub errors: usize,
}
#[derive(Debug, Serialize)]
pub struct ConfigurationSummary {
    pub timeout_ms: u64,
    pub max_body_bytes: usize,
    pub concurrency: usize,
    pub accept_statuses: Vec<u16>,
    pub reject_statuses: Vec<u16>,
    pub duplicate_statuses: Vec<u16>,
    pub require_unambiguous_signature_header: bool,
    pub observer_required: bool,
    pub observer_settle_ms: u64,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub tool: &'static str,
    pub profile: Profile,
    pub capabilities: Capabilities,
    pub configuration: ConfigurationSummary,
    pub target: String,
    pub started_at_unix: i64,
    pub duration_ms: u128,
    pub observer_enabled: bool,
    pub observer_available: bool,
    pub capability_summary: String,
    pub summary: Summary,
    pub results: Vec<ResultItem>,
    pub findings: Vec<Finding>,
}
impl Report {
    pub fn new(config: &Config, now: i64) -> Self {
        let profile = config.profile;
        let observer = config.observer.enabled;
        Self {
            schema_version: 1,
            tool: "webhook-security-tester",
            profile,
            capabilities: profile.capabilities(),
            configuration: ConfigurationSummary {
                timeout_ms: config.timeout_ms,
                max_body_bytes: config.runner.max_body_bytes,
                concurrency: config.runner.concurrency,
                accept_statuses: config.expectations.accept_statuses.clone(),
                reject_statuses: config.expectations.reject_statuses.clone(),
                duplicate_statuses: config.expectations.duplicate_statuses.clone(),
                require_unambiguous_signature_header: config
                    .expectations
                    .require_unambiguous_signature_header,
                observer_required: config.observer.require,
                observer_settle_ms: config.observer.settle_ms,
            },
            target: config.endpoint.clone(),
            started_at_unix: now,
            duration_ms: 0,
            observer_enabled: observer,
            observer_available: observer,
            capability_summary: if observer {
                "Local processing counts requested; each processing assertion requires an available observer".into()
            } else {
                "HTTP only: processing and idempotency assertions are inconclusive".into()
            },
            summary: Summary::default(),
            results: vec![],
            findings: vec![],
        }
    }
    pub fn push(&mut self, s: &Scenario, mut item: ResultItem) {
        match item.classification {
            Classification::Pass => self.summary.passed += 1,
            Classification::Fail => self.summary.failed += 1,
            Classification::Inconclusive => self.summary.inconclusive += 1,
            Classification::Skip => self.summary.skipped += 1,
            Classification::Error => self.summary.errors += 1,
        }
        if item.classification == Classification::Fail {
            let (severity, impact, remediation) = finding_details(s, &item);
            item.remediation = Some(remediation.clone());
            self.findings.push(Finding {
                rule_id: s.id.into(),
                severity,
                title: s.title.into(),
                evidence: item.explanation.clone(),
                impact,
                remediation,
                reference: s.reference.into(),
            });
        }
        self.results.push(item);
    }
    pub fn exit_code(&self, require_observer: bool) -> i32 {
        if self.summary.errors > 0
            || (require_observer && (!self.observer_available || self.summary.inconclusive > 0))
            || self.summary.passed + self.summary.failed + self.summary.inconclusive == 0
        {
            2
        } else if self.summary.failed > 0 {
            1
        } else {
            0
        }
    }
    pub fn terminal(&self, quiet: bool, color: bool, verbose: bool) -> String {
        let mut out = format!(
            "Webhook Security Tester\nTarget   {}\nProfile  {}\nEvidence {}\n",
            self.target,
            self.profile.identifier(),
            self.capability_summary
        );
        for (category, heading) in [
            (Category::Signature, "SIGNATURE"),
            (Category::Replay, "REPLAY"),
            (Category::Duplicate, "DUPLICATE"),
            (Category::Timestamp, "TIMESTAMP"),
        ] {
            let visible = self
                .results
                .iter()
                .filter(|r| {
                    r.category == category && (!quiet || r.classification != Classification::Pass)
                })
                .collect::<Vec<_>>();
            if visible.is_empty() {
                continue;
            }
            out.push_str(&format!("\n{heading}\n"));
            for r in visible {
                let raw = format!("{:<12}", format!("{:?}", r.classification).to_uppercase());
                let label = if color {
                    let code = match r.classification {
                        Classification::Pass => "32",
                        Classification::Fail | Classification::Error => "31",
                        Classification::Inconclusive => "33",
                        Classification::Skip => "36",
                    };
                    format!("\x1b[{code}m{raw}\x1b[0m")
                } else {
                    raw
                };
                out.push_str(&format!(
                    "{} {:12} {} — {}\n",
                    label, r.id, r.description, r.explanation
                ));
                if verbose {
                    out.push_str(&format!(
                        "             Statuses: {:?}; completed effects: {}; duration: {} ms\n",
                        r.observed_statuses,
                        r.observed_processing_count
                            .map(|n| n.to_string())
                            .unwrap_or_else(|| "unobserved".into()),
                        r.duration_ms
                    ));
                }
            }
        }
        out.push_str(&format!(
            "\nSUMMARY\n{} pass, {} fail, {} inconclusive, {} skip, {} error\n",
            self.summary.passed,
            self.summary.failed,
            self.summary.inconclusive,
            self.summary.skipped,
            self.summary.errors
        ));
        if !self.findings.is_empty() {
            out.push_str("\nFINDINGS\n");
            for f in &self.findings {
                out.push_str(&format!(
                    "{}  {} — {}\n    {}\n",
                    f.severity, f.rule_id, f.title, f.remediation
                ));
            }
        }
        out
    }
    pub fn markdown(&self) -> String {
        let mut out = String::from("# Webhook Security Tester report\n\n## Overview\n\n");
        out.push_str(&format!(
            "- Target: `{}`\n- Profile: `{}`\n- Started (Unix seconds): `{}`\n- Duration: `{} ms`\n- Observer enabled: `{}`\n- Observer available: `{}`\n",
            self.target, self.profile.identifier(), self.started_at_unix, self.duration_ms,
            self.observer_enabled, self.observer_available
        ));
        out.push_str("\n## Configuration summary\n\n| Setting | Value |\n|---|---|\n");
        for (label, value) in [
            (
                "Request timeout",
                format!("{} ms", self.configuration.timeout_ms),
            ),
            (
                "Maximum request body",
                format!("{} bytes", self.configuration.max_body_bytes),
            ),
            (
                "Concurrent deliveries",
                self.configuration.concurrency.to_string(),
            ),
            (
                "Accepted statuses",
                format!("{:?}", self.configuration.accept_statuses),
            ),
            (
                "Rejected statuses",
                format!("{:?}", self.configuration.reject_statuses),
            ),
            (
                "Duplicate statuses",
                format!("{:?}", self.configuration.duplicate_statuses),
            ),
            (
                "Strict signature-header policy",
                self.configuration
                    .require_unambiguous_signature_header
                    .to_string(),
            ),
            (
                "Observer required",
                self.configuration.observer_required.to_string(),
            ),
            (
                "Observer settling window",
                format!("{} ms", self.configuration.observer_settle_ms),
            ),
        ] {
            out.push_str(&format!("| {label} | {value} |\n"));
        }
        out.push_str("\n## Provider capabilities\n\n| Capability | Supported |\n|---|---|\n");
        for (label, supported) in [
            ("HMAC-SHA256", self.capabilities.hmac_sha256),
            ("Signed timestamp", self.capabilities.signed_timestamp),
            ("Delivery identifier", self.capabilities.delivery_identifier),
            (
                "Delivery identifier signed by MAC",
                self.capabilities.signed_delivery_identifier,
            ),
            (
                "Signed fixture event ID",
                self.capabilities.signed_fixture_event_identifier,
            ),
            ("Duplicate tests", self.capabilities.duplicate_tests),
        ] {
            out.push_str(&format!("| {label} | {supported} |\n"));
        }
        out.push_str(&format!(
            "\n{}\n\n## Summary\n\n{} pass, {} fail, {} inconclusive, {} skip, {} error.\n",
            self.capability_summary,
            self.summary.passed,
            self.summary.failed,
            self.summary.inconclusive,
            self.summary.skipped,
            self.summary.errors
        ));
        out.push_str("\n## Test coverage and evidence\n\n| ID | Category | Classification | Expected | Observed HTTP | Processing count | Evidence |\n|---|---|---|---|---|---|---|\n");
        for result in &self.results {
            let processing = result
                .observed_processing_count
                .map(|count| count.to_string())
                .unwrap_or_else(|| "unobserved".into());
            out.push_str(&format!(
                "| {} | {:?} | {:?} | {} | {:?} | {} | {} |\n",
                result.id,
                result.category,
                result.classification,
                result.expected.replace('|', "/"),
                result.observed_statuses,
                processing,
                result.explanation.replace('|', "/")
            ));
        }
        out.push_str("\n## Failed assertions and remediation\n\n");
        if self.findings.is_empty() {
            out.push_str("No failed assertions.\n\n");
        }
        for finding in &self.findings {
            out.push_str(&format!(
                "### {} — {}\n\nEvidence: {}\n\nImpact: {}\n\nRemediation: {}\n\nReference: {}\n\n",
                finding.rule_id,
                finding.title,
                finding.evidence,
                finding.impact,
                finding.remediation,
                finding.reference
            ));
        }
        out.push_str("## Skipped and inconclusive tests\n\n");
        let mut any = false;
        for result in &self.results {
            if matches!(
                result.classification,
                Classification::Skip | Classification::Inconclusive
            ) {
                any = true;
                out.push_str(&format!("- **{}**: {}\n", result.id, result.explanation));
            }
        }
        if !any {
            out.push_str("None.\n");
        }
        out.push_str("\n## Limitations\n\nHTTP responses alone cannot establish exactly-once effects. GitHub's body HMAC does not sign a timestamp or the delivery header. Local results do not prove production infrastructure behavior.\n");
        out
    }
}
fn finding_details(s: &Scenario, item: &ResultItem) -> (&'static str, String, String) {
    let any_success = item
        .observed_statuses
        .iter()
        .any(|status| (200..300).contains(status));
    let any_server_error = item.observed_statuses.iter().any(|status| *status >= 500);
    if any_server_error {
        return ("MEDIUM","The receiver returned a server error, so the declared response policy was not met; this does not prove a signature bypass or duplicate effect.".into(),"Investigate the receiver error and return the configured status after safe handling.".into());
    }
    match s.expected {
        Expectation::Reject if any_success => ("HIGH",fixture::failure_meaning(s).into(),s.remediation.into()),
        Expectation::Reject => ("LOW","The request did not receive one of the configured rejection statuses; no acceptance was observed.".into(),"Check the target's rejection status policy and configure the expected 4xx codes accordingly.".into()),
        Expectation::Accept => ("MEDIUM",fixture::failure_meaning(s).into(),s.remediation.into()),
        Expectation::ProcessOnce if item.observed_processing_count.is_some_and(|n|n>1) => ("HIGH","The observer counted repeated completed processing for one test event.".into(),s.remediation.into()),
        Expectation::ProcessOnce if item.observed_processing_count==Some(0) => ("MEDIUM","The observer counted no completed processing for a valid test event.".into(),"Check the handler's processing path and observer instrumentation.".into()),
        Expectation::ProcessTwice if item.observed_processing_count.is_some_and(|n|n<2) => ("MEDIUM",fixture::failure_meaning(s).into(),s.remediation.into()),
        _ => ("LOW","HTTP statuses violated the declared retry policy; the available counts do not show a duplicate processing failure.".into(),"Check the target's first-delivery and retry status policy, then update expectations if intended.".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn schema_and_empty_coverage_exit_are_stable() {
        let config: Config =
            toml::from_str(include_str!("../examples/webhook-security-tester.toml")).unwrap();
        let report = Report::new(&config, 0);
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["tool"], "webhook-security-tester");
        assert!(value["results"].is_array());
        assert_eq!(report.exit_code(false), 2);
    }
    #[test]
    fn findings_do_not_infer_unobserved_bypasses_or_duplicate_effects() {
        let config: Config =
            toml::from_str(include_str!("../examples/webhook-security-tester.toml")).unwrap();
        let mut report = Report::new(&config, 0);
        let rejected = fixture::find("GH-SIG-002").unwrap();
        report.push(
            rejected,
            ResultItem {
                id: rejected.id.into(),
                category: rejected.category,
                description: rejected.description.into(),
                expected: "Reject".into(),
                observed_statuses: vec![500],
                observed_processing_count: None,
                classification: Classification::Fail,
                duration_ms: 1,
                explanation: "HTTP 500".into(),
                remediation: None,
            },
        );
        assert!(report.findings[0].impact.contains("does not prove"));
        let duplicate = fixture::find("DUP-001").unwrap();
        report.push(
            duplicate,
            ResultItem {
                id: duplicate.id.into(),
                category: duplicate.category,
                description: duplicate.description.into(),
                expected: "ProcessOnce".into(),
                observed_statuses: vec![200, 409],
                observed_processing_count: Some(1),
                classification: Classification::Fail,
                duration_ms: 1,
                explanation: "Unexpected HTTP 409".into(),
                remediation: None,
            },
        );
        assert!(report.findings[1]
            .impact
            .contains("do not show a duplicate processing failure"));
    }
    #[test]
    fn terminal_color_and_json_classifications_are_explicit() {
        let config: Config =
            toml::from_str(include_str!("../examples/webhook-security-tester.toml")).unwrap();
        let mut report = Report::new(&config, 0);
        let s = fixture::find("GH-SIG-001").unwrap();
        report.push(
            s,
            ResultItem {
                id: s.id.into(),
                category: s.category,
                description: s.description.into(),
                expected: "Accept".into(),
                observed_statuses: vec![200],
                observed_processing_count: None,
                classification: Classification::Pass,
                duration_ms: 1,
                explanation: "accepted".into(),
                remediation: None,
            },
        );
        assert!(report.terminal(false, true, false).contains("\x1b[32m"));
        assert!(!report.terminal(false, false, false).contains("\x1b["));
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["results"][0]["classification"], "PASS");
        report.observer_available = false;
        assert_eq!(report.exit_code(true), 2);
    }
}

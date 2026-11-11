use crate::config::Profile;
use anyhow::{Context, Result};
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Signature,
    Timestamp,
    Replay,
    Duplicate,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub enum Expectation {
    Accept,
    Reject,
    ProcessOnce,
    ProcessTwice,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum Mutation {
    Valid,
    MissingSignature,
    IncorrectSignature,
    ModifiedBody,
    WrongSecret,
    TruncatedDigest,
    InvalidHex,
    WrongPrefix,
    LegacySha1Only,
    PrettyJson,
    UnicodeJson,
    CrlfJson,
    ReorderedJson,
    StaleSerialization,
    AmbiguousHeaders,
    EmptySignature,
    ExpiredTimestamp,
    FutureTimestamp,
    InsideBoundary,
    OutsideBoundary,
    MissingTimestamp,
    MalformedTimestamp,
    ChangedTimestamp,
    InvalidHmac,
    TimestampModifiedBody,
    ExactReplay,
    RepeatedReplay,
    ChangedDeliveryId,
    SequentialDuplicate,
    ConcurrentDuplicate,
    DistinctEvents,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Scenario {
    pub id: &'static str,
    pub title: &'static str,
    pub category: Category,
    pub profile: Profile,
    pub description: &'static str,
    pub expected: Expectation,
    pub mutation: Mutation,
    pub remediation: &'static str,
    pub reference: &'static str,
}
const GH_REF: &str =
    "https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries";
const GH_BEST: &str =
    "https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks";
const TS_REF: &str = "docs/provider-profiles.md#timestamped-hmac-v1";
const VERIFY: &str = "Verify a single SHA-256 HMAC over the exact raw body before parsing it.";
const DEDUP: &str = "Use a durable, atomic idempotency key tied to authenticated event data; document retention and collision tradeoffs.";
macro_rules! gh {
    ($id:literal,$title:literal,$expect:ident,$mutation:ident,$desc:literal) => {
        Scenario {
            id: $id,
            title: $title,
            category: Category::Signature,
            profile: Profile::Github,
            description: $desc,
            expected: Expectation::$expect,
            mutation: Mutation::$mutation,
            remediation: VERIFY,
            reference: GH_REF,
        }
    };
}
macro_rules! ts {
    ($id:literal,$title:literal,$expect:ident,$mutation:ident,$desc:literal) => {
        Scenario {
            id: $id,
            title: $title,
            category: Category::Timestamp,
            profile: Profile::TimestampedHmacV1,
            description: $desc,
            expected: Expectation::$expect,
            mutation: Mutation::$mutation,
            remediation:
                "Verify the timestamp and raw body HMAC, then enforce the configured clock window.",
            reference: TS_REF,
        }
    };
}
pub const SCENARIOS: &[Scenario] = &[
    gh!(
        "GH-SIG-001",
        "Valid signature",
        Accept,
        Valid,
        "Correct HMAC over the original body"
    ),
    gh!(
        "GH-SIG-002",
        "Missing signature",
        Reject,
        MissingSignature,
        "Omit SHA-256 signature header"
    ),
    gh!(
        "GH-SIG-003",
        "Incorrect signature",
        Reject,
        IncorrectSignature,
        "Replace digest with a wrong digest"
    ),
    gh!(
        "GH-SIG-004",
        "Modified payload",
        Reject,
        ModifiedBody,
        "Change a body byte after signing"
    ),
    gh!(
        "GH-SIG-005",
        "Incorrect secret",
        Reject,
        WrongSecret,
        "Sign with a distinct test secret"
    ),
    gh!(
        "GH-SIG-006",
        "Truncated digest",
        Reject,
        TruncatedDigest,
        "Remove part of the digest"
    ),
    gh!(
        "GH-SIG-007",
        "Invalid hexadecimal",
        Reject,
        InvalidHex,
        "Insert a nonhex character"
    ),
    gh!(
        "GH-SIG-008",
        "Wrong algorithm prefix",
        Reject,
        WrongPrefix,
        "Replace sha256 prefix"
    ),
    gh!(
        "GH-SIG-009",
        "Legacy SHA-1 only",
        Reject,
        LegacySha1Only,
        "Send only a legacy signature header; SHA-256 is required by this test policy"
    ),
    gh!(
        "GH-SIG-010",
        "Pretty-printed JSON",
        Accept,
        PrettyJson,
        "Sign and send whitespace-formatted JSON bytes"
    ),
    gh!(
        "GH-SIG-011",
        "Unicode payload",
        Accept,
        UnicodeJson,
        "Sign and send non-ASCII UTF-8 JSON"
    ),
    gh!(
        "GH-SIG-012",
        "CRLF formatting",
        Accept,
        CrlfJson,
        "Sign and send CRLF-formatted JSON"
    ),
    gh!(
        "GH-SIG-013",
        "Reordered properties",
        Accept,
        ReorderedJson,
        "Sign and send differently ordered JSON"
    ),
    gh!(
        "GH-SIG-014",
        "Equivalent JSON with stale signature",
        Reject,
        StaleSerialization,
        "Sign compact JSON then send equivalent formatted JSON"
    ),
    gh!(
        "GH-SIG-015",
        "Ambiguous signature headers",
        Reject,
        AmbiguousHeaders,
        "Send conflicting duplicate SHA-256 headers; this is a declared strict-header policy"
    ),
    gh!(
        "GH-SIG-016",
        "Empty signature",
        Reject,
        EmptySignature,
        "Send an empty digest value"
    ),
    ts!(
        "TS-001",
        "Current timestamp",
        Accept,
        Valid,
        "Current signed timestamp"
    ),
    ts!(
        "TS-002",
        "Expired timestamp",
        Reject,
        ExpiredTimestamp,
        "Old timestamp with a valid HMAC"
    ),
    ts!(
        "TS-003",
        "Future timestamp",
        Reject,
        FutureTimestamp,
        "Future timestamp beyond configured skew with a valid HMAC"
    ),
    ts!(
        "TS-004",
        "Inside boundary",
        Accept,
        InsideBoundary,
        "Timestamp safely inside the tolerance boundary"
    ),
    ts!(
        "TS-005",
        "Outside boundary",
        Reject,
        OutsideBoundary,
        "Timestamp beyond the tolerance boundary"
    ),
    ts!(
        "TS-006",
        "Missing timestamp",
        Reject,
        MissingTimestamp,
        "Signature header missing timestamp"
    ),
    ts!(
        "TS-007",
        "Malformed timestamp",
        Reject,
        MalformedTimestamp,
        "Timestamp is not a decimal integer"
    ),
    ts!(
        "TS-008",
        "Changed timestamp",
        Reject,
        ChangedTimestamp,
        "Change timestamp after signing"
    ),
    ts!(
        "TS-009",
        "Invalid HMAC",
        Reject,
        InvalidHmac,
        "Valid timestamp with invalid HMAC"
    ),
    ts!(
        "TS-010",
        "Modified body",
        Reject,
        TimestampModifiedBody,
        "Change body after signing"
    ),
    Scenario {
        id: "REPLAY-001",
        title: "Exact replay",
        category: Category::Replay,
        profile: Profile::Github,
        description: "Send the identical authenticated request twice",
        expected: Expectation::ProcessOnce,
        mutation: Mutation::ExactReplay,
        remediation: DEDUP,
        reference: GH_BEST,
    },
    Scenario {
        id: "REPLAY-002",
        title: "GitHub redelivery",
        category: Category::Replay,
        profile: Profile::Github,
        description: "Repeat body and original delivery identifier",
        expected: Expectation::ProcessOnce,
        mutation: Mutation::ExactReplay,
        remediation: DEDUP,
        reference: GH_BEST,
    },
    Scenario {
        id: "REPLAY-003",
        title: "Repeated delivery",
        category: Category::Replay,
        profile: Profile::Github,
        description: "Send the same signed request three times",
        expected: Expectation::ProcessOnce,
        mutation: Mutation::RepeatedReplay,
        remediation: DEDUP,
        reference: GH_BEST,
    },
    Scenario {
        id: "REPLAY-004",
        title: "Changed unsigned delivery ID",
        category: Category::Replay,
        profile: Profile::Github,
        description: "Replay signed body with a different unsigned X-GitHub-Delivery",
        expected: Expectation::ProcessOnce,
        mutation: Mutation::ChangedDeliveryId,
        remediation: DEDUP,
        reference: GH_BEST,
    },
    Scenario {
        id: "DUP-001",
        title: "Sequential duplicate",
        category: Category::Duplicate,
        profile: Profile::Github,
        description: "Deliver the same event twice sequentially",
        expected: Expectation::ProcessOnce,
        mutation: Mutation::SequentialDuplicate,
        remediation: DEDUP,
        reference: GH_BEST,
    },
    Scenario {
        id: "DUP-002",
        title: "Concurrent duplicate",
        category: Category::Duplicate,
        profile: Profile::Github,
        description: "Deliver same event concurrently",
        expected: Expectation::ProcessOnce,
        mutation: Mutation::ConcurrentDuplicate,
        remediation: DEDUP,
        reference: GH_BEST,
    },
    Scenario {
        id: "DUP-003",
        title: "Distinct events",
        category: Category::Duplicate,
        profile: Profile::Github,
        description: "Two different signed event IDs must both process",
        expected: Expectation::ProcessTwice,
        mutation: Mutation::DistinctEvents,
        remediation: "Check the receiver's event identity and suppression policy.",
        reference: GH_BEST,
    },
    Scenario {
        id: "TS-011",
        title: "Replay within window",
        category: Category::Timestamp,
        profile: Profile::TimestampedHmacV1,
        description: "Replay a valid event inside its timestamp window",
        expected: Expectation::ProcessOnce,
        mutation: Mutation::ExactReplay,
        remediation: DEDUP,
        reference: TS_REF,
    },
    Scenario {
        id: "DUP-004",
        title: "Concurrent timestamped duplicate",
        category: Category::Duplicate,
        profile: Profile::TimestampedHmacV1,
        description: "Deliver same timestamped event concurrently",
        expected: Expectation::ProcessOnce,
        mutation: Mutation::ConcurrentDuplicate,
        remediation: DEDUP,
        reference: TS_REF,
    },
];

#[derive(Clone, Debug)]
pub struct Delivery {
    pub body: Vec<u8>,
    pub headers: Vec<(&'static str, String)>,
}
pub fn deliveries(
    s: &Scenario,
    secret: &[u8],
    now: i64,
    tolerance: i64,
    skew: i64,
    concurrency: usize,
) -> Result<Vec<Delivery>> {
    let id = s.id.to_ascii_lowercase();
    let compact = format!(r#"{{"id":"{id}","action":"created"}}"#).into_bytes();
    let pretty = format!("{{\n  \"id\": \"{id}\",\n  \"action\": \"created\"\n}}").into_bytes();
    let mut body = match s.mutation {
        Mutation::PrettyJson => pretty.clone(),
        Mutation::UnicodeJson => format!(r#"{{"id":"{id}","message":"مرحبا 🌍"}}"#).into_bytes(),
        Mutation::CrlfJson => {
            format!("{{\r\n  \"id\": \"{id}\",\r\n  \"action\": \"created\"\r\n}}").into_bytes()
        }
        Mutation::ReorderedJson => format!(r#"{{"action":"created","id":"{id}"}}"#).into_bytes(),
        _ => compact.clone(),
    };
    let mut headers = vec![("content-type", "application/json".into())];
    if s.profile == Profile::Github {
        headers.push(("x-github-delivery", format!("delivery-{id}")));
        let signed = s.profile.sign(secret, &body, now);
        let value = match s.mutation {
            Mutation::IncorrectSignature => {
                "sha256=0000000000000000000000000000000000000000000000000000000000000000".into()
            }
            Mutation::WrongSecret => {
                let wrong = if secret == b"webhookproof-wrong-secret-fixture" {
                    b"webhookproof-alternative-secret".as_slice()
                } else {
                    b"webhookproof-wrong-secret-fixture".as_slice()
                };
                s.profile.sign(wrong, &body, now)
            }
            Mutation::TruncatedDigest => signed[..signed.len() - 2].into(),
            Mutation::InvalidHex => format!("{}gg", &signed[..signed.len() - 2]),
            Mutation::WrongPrefix => signed.replacen("sha256=", "sha1=", 1),
            Mutation::EmptySignature => String::new(),
            _ => signed,
        };
        if s.mutation == Mutation::LegacySha1Only {
            headers.push((
                "x-hub-signature",
                "sha1=0000000000000000000000000000000000000000".into(),
            ));
        } else if s.mutation != Mutation::MissingSignature {
            headers.push((s.profile.signature_header(), value));
        }
        if s.mutation == Mutation::AmbiguousHeaders {
            headers.push((
                "x-hub-signature-256",
                "sha256=0000000000000000000000000000000000000000000000000000000000000000".into(),
            ));
        }
        if s.mutation == Mutation::ModifiedBody {
            let i = body
                .windows(7)
                .position(|w| w == b"created")
                .context("fixture body lacks expected action")?;
            body[i] = b'X';
        }
        if s.mutation == Mutation::StaleSerialization {
            body = pretty;
        }
    } else {
        let margin = (tolerance / 10).clamp(1, 30);
        let timestamp = match s.mutation {
            Mutation::ExpiredTimestamp => now - tolerance - margin,
            Mutation::FutureTimestamp => now + skew + 30,
            Mutation::InsideBoundary => now - tolerance + margin,
            Mutation::OutsideBoundary => now - tolerance - margin,
            _ => now,
        };
        let signed = s.profile.sign(secret, &body, timestamp);
        let value = match s.mutation {
            Mutation::MissingTimestamp => signed.split(',').nth(1).unwrap_or("").into(),
            Mutation::MalformedTimestamp => {
                signed.replacen(&format!("t={timestamp}"), "t=not-a-number", 1)
            }
            Mutation::ChangedTimestamp => signed.replacen(
                &format!("t={timestamp}"),
                &format!("t={}", timestamp + 1),
                1,
            ),
            Mutation::InvalidHmac => format!("t={timestamp},v1={}", "0".repeat(64)),
            _ => signed,
        };
        headers.push((s.profile.signature_header(), value));
        if s.mutation == Mutation::TimestampModifiedBody {
            let i = body
                .windows(7)
                .position(|w| w == b"created")
                .context("fixture body lacks expected action")?;
            body[i] = b'X';
        }
    }
    let first = Delivery { body, headers };
    let count = delivery_count(s, concurrency);
    let mut result = vec![first.clone(); count];
    if s.mutation == Mutation::ChangedDeliveryId {
        result
            .get_mut(1)
            .context("replay requires a second delivery")?
            .headers
            .iter_mut()
            .find(|(k, _)| *k == "x-github-delivery")
            .context("GitHub replay fixture lacks delivery header")?
            .1 = format!("changed-{id}");
    }
    if s.mutation == Mutation::DistinctEvents {
        let second = format!(r#"{{"id":"{id}-second","action":"created"}}"#).into_bytes();
        let delivery = result
            .get_mut(1)
            .context("distinct-events fixture requires a second delivery")?;
        delivery.body = second.clone();
        delivery
            .headers
            .iter_mut()
            .find(|(k, _)| *k == "x-hub-signature-256")
            .context("distinct-events fixture lacks signature header")?
            .1 = s.profile.sign(secret, &second, now);
    }
    Ok(result)
}
pub fn delivery_count(s: &Scenario, concurrency: usize) -> usize {
    match s.mutation {
        Mutation::RepeatedReplay => 3,
        Mutation::ConcurrentDuplicate => concurrency.max(2),
        Mutation::ExactReplay
        | Mutation::ChangedDeliveryId
        | Mutation::SequentialDuplicate
        | Mutation::DistinctEvents => 2,
        _ => 1,
    }
}
pub fn find(id: &str) -> Option<&'static Scenario> {
    SCENARIOS.iter().find(|s| s.id.eq_ignore_ascii_case(id))
}
pub fn failure_meaning(s: &Scenario) -> &'static str {
    match (s.category,s.expected) {
        (Category::Signature,Expectation::Reject)=>"Accepting this request suggests the declared SHA-256 signature or strict header policy is not enforced.",
        (Category::Signature,Expectation::Accept)=>"Rejecting correctly signed raw bytes suggests the receiver transforms or misparses valid provider payloads.",
        (Category::Timestamp,Expectation::Reject)=>"Accepting this request suggests the synthetic timestamp, signature, or clock-window policy is not enforced.",
        (Category::Timestamp,Expectation::Accept)=>"Rejecting this correctly signed in-window request suggests clock or signature construction is inconsistent.",
        (_,Expectation::ProcessOnce)=>"Observed repeated completed processing for one test event despite the declared idempotency policy.",
        (_,Expectation::ProcessTwice)=>"Distinct signed test events did not both complete processing; deduplication may be overbroad.",
        _=>"Observed behavior violated the declared test expectation.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    #[test]
    fn mutations_keep_valid_json_and_stale_mac() {
        let secret = b"test-secret";
        for id in ["GH-SIG-004", "GH-SIG-014", "TS-010"] {
            let s = find(id).unwrap();
            let d = deliveries(s, secret, 1000, 300, 30, 5).unwrap().remove(0);
            assert!(serde_json::from_slice::<serde_json::Value>(&d.body).is_ok());
            let h = if s.profile == Profile::Github {
                "x-hub-signature-256"
            } else {
                "webhookproof-signature"
            };
            let signature = &d.headers.iter().find(|(k, _)| *k == h).unwrap().1;
            if s.profile == Profile::Github {
                assert!(!crypto::github_verify(secret, &d.body, signature));
            } else {
                assert!(!crypto::timestamp_verify(
                    secret, &d.body, signature, 1000, 300, 30
                ));
            }
        }
    }
    #[test]
    fn scenario_ids_unique() {
        let ids = SCENARIOS
            .iter()
            .map(|s| s.id)
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(ids.len(), SCENARIOS.len());
    }
    #[test]
    fn catalog_serializes_and_all_delivery_plans_are_complete() {
        let encoded = serde_json::to_vec(SCENARIOS).unwrap();
        assert!(encoded
            .windows(b"GH-SIG-016".len())
            .any(|w| w == b"GH-SIG-016"));
        for s in SCENARIOS {
            let deliveries = deliveries(s, b"test-secret", 1000, 300, 30, 5).unwrap();
            assert_eq!(deliveries.len(), delivery_count(s, 5), "{}", s.id);
            assert!(
                deliveries
                    .iter()
                    .all(|d| serde_json::from_slice::<serde_json::Value>(&d.body).is_ok()),
                "{}",
                s.id
            );
        }
    }
    #[test]
    fn expired_fixture_has_valid_mac_for_its_old_timestamp() {
        let s = find("TS-002").unwrap();
        let d = deliveries(s, b"test-secret", 1000, 300, 30, 5)
            .unwrap()
            .remove(0);
        let signature = &d
            .headers
            .iter()
            .find(|(k, _)| *k == "webhookproof-signature")
            .unwrap()
            .1;
        let timestamp = signature
            .split(',')
            .next()
            .unwrap()
            .strip_prefix("t=")
            .unwrap()
            .parse::<i64>()
            .unwrap();
        assert!(crypto::timestamp_verify(
            b"test-secret",
            &d.body,
            signature,
            timestamp,
            300,
            30
        ));
        assert!(!crypto::timestamp_verify(
            b"test-secret",
            &d.body,
            signature,
            1000,
            300,
            30
        ));
    }
    #[test]
    fn wrong_secret_fixture_never_uses_the_target_secret() {
        let s = find("GH-SIG-005").unwrap();
        for secret in [
            b"ordinary-secret".as_slice(),
            b"webhookproof-wrong-secret-fixture".as_slice(),
        ] {
            let d = deliveries(s, secret, 1000, 300, 30, 5).unwrap().remove(0);
            let value = &d
                .headers
                .iter()
                .find(|(k, _)| *k == "x-hub-signature-256")
                .unwrap()
                .1;
            assert!(!crypto::github_verify(secret, &d.body, value));
        }
    }
}

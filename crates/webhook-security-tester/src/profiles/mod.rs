use crate::{config::Profile, crypto};
use serde::Serialize;

/// Explicit protocol properties used for coverage and reporting.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Capabilities {
    pub hmac_sha256: bool,
    pub signed_timestamp: bool,
    pub delivery_identifier: bool,
    pub signed_delivery_identifier: bool,
    pub signed_fixture_event_identifier: bool,
    pub duplicate_tests: bool,
}

impl Profile {
    pub fn identifier(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::TimestampedHmacV1 => "timestamped-hmac-v1",
        }
    }
    pub fn capabilities(self) -> Capabilities {
        match self {
            Self::Github => Capabilities {
                hmac_sha256: true,
                signed_timestamp: false,
                delivery_identifier: true,
                signed_delivery_identifier: false,
                signed_fixture_event_identifier: true,
                duplicate_tests: true,
            },
            Self::TimestampedHmacV1 => Capabilities {
                hmac_sha256: true,
                signed_timestamp: true,
                delivery_identifier: false,
                signed_delivery_identifier: false,
                signed_fixture_event_identifier: true,
                duplicate_tests: true,
            },
        }
    }
    pub fn signature_header(self) -> &'static str {
        match self {
            Self::Github => "x-hub-signature-256",
            Self::TimestampedHmacV1 => "webhookproof-signature",
        }
    }
    pub fn protocol_summary(self) -> &'static str {
        match self {
            Self::Github => "HMAC-SHA256 signs exact raw body bytes; X-GitHub-Delivery and time are not signed.",
            Self::TimestampedHmacV1 => "HMAC-SHA256 signs ASCII(timestamp), a period byte, then exact raw body bytes; timestamps must be within the configured window.",
        }
    }
    pub fn sign(self, secret: &[u8], body: &[u8], timestamp: i64) -> String {
        match self {
            Self::Github => crypto::github_sign(secret, body),
            Self::TimestampedHmacV1 => crypto::timestamp_sign(secret, body, timestamp),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capabilities_do_not_conflate_github_delivery_id_with_signed_fixture_id() {
        let github = Profile::Github.capabilities();
        assert!(!github.signed_timestamp);
        assert!(github.delivery_identifier);
        assert!(!github.signed_delivery_identifier);
        assert!(github.signed_fixture_event_identifier);
        let synthetic = Profile::TimestampedHmacV1.capabilities();
        assert!(synthetic.signed_timestamp);
        assert!(!synthetic.delivery_identifier);
    }
}

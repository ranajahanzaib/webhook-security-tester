use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{env, fs, net::IpAddr, path::Path, time::Duration};
use url::{Host, Url};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    Github,
    TimestampedHmacV1,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub profile: Profile,
    pub endpoint: String,
    pub secret_env: String,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub expectations: Expectations,
    #[serde(default)]
    pub runner: Runner,
    #[serde(default)]
    pub observer: Observer,
    #[serde(default)]
    pub timestamp: Option<Timestamp>,
}
fn default_timeout() -> u64 {
    3000
}
fn default_body() -> usize {
    65536
}
fn default_concurrency() -> usize {
    5
}
fn default_tolerance() -> i64 {
    300
}
fn default_skew() -> i64 {
    30
}
fn default_settle() -> u64 {
    500
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Expectations {
    pub accept_statuses: Vec<u16>,
    pub reject_statuses: Vec<u16>,
    pub duplicate_statuses: Vec<u16>,
    pub require_unambiguous_signature_header: bool,
}
impl Default for Expectations {
    fn default() -> Self {
        Self {
            accept_statuses: vec![200, 201, 202, 204],
            reject_statuses: vec![400, 401, 403],
            duplicate_statuses: vec![200, 201, 202, 204],
            require_unambiguous_signature_header: false,
        }
    }
}
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Runner {
    #[serde(default = "default_body")]
    pub max_body_bytes: usize,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    pub follow_redirects: bool,
}
impl Default for Runner {
    fn default() -> Self {
        Self {
            max_body_bytes: default_body(),
            concurrency: default_concurrency(),
            follow_redirects: false,
        }
    }
}
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Observer {
    pub enabled: bool,
    pub require: bool,
    #[serde(default = "default_settle")]
    pub settle_ms: u64,
}
impl Default for Observer {
    fn default() -> Self {
        Self {
            enabled: false,
            require: false,
            settle_ms: default_settle(),
        }
    }
}
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Timestamp {
    pub tolerance_seconds: i64,
    pub future_skew_seconds: i64,
}
impl Default for Timestamp {
    fn default() -> Self {
        Self {
            tolerance_seconds: default_tolerance(),
            future_skew_seconds: default_skew(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("cannot read configuration {}", path.display()))?;
        let config: Self = toml::from_str(&content).context("invalid TOML configuration")?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            bail!(
                "unsupported configuration version {}; expected 1",
                self.version
            );
        }
        self.url()?;
        if self.secret_env.is_empty()
            || !self
                .secret_env
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            bail!("secret_env must name an environment variable");
        }
        if !(100..=30000).contains(&self.timeout_ms) {
            bail!("timeout_ms must be between 100 and 30000");
        }
        if !(1..=32).contains(&self.runner.concurrency) {
            bail!("runner.concurrency must be between 1 and 32");
        }
        if !(1024..=1_048_576).contains(&self.runner.max_body_bytes) {
            bail!("runner.max_body_bytes must be between 1024 and 1048576");
        }
        if self.runner.follow_redirects {
            bail!("runner.follow_redirects must be false; redirects are prohibited");
        }
        if self.observer.require && !self.observer.enabled {
            bail!("observer.require needs observer.enabled = true");
        }
        if !(100..=30000).contains(&self.observer.settle_ms) {
            bail!("observer.settle_ms must be between 100 and 30000");
        }
        for (name, statuses) in [
            ("accept", &self.expectations.accept_statuses),
            ("reject", &self.expectations.reject_statuses),
            ("duplicate", &self.expectations.duplicate_statuses),
        ] {
            if statuses.is_empty()
                || statuses.iter().any(|s| match name {
                    "reject" => !(400..500).contains(s),
                    "duplicate" => !(200..300).contains(s) && *s != 409,
                    _ => !(200..300).contains(s),
                })
            {
                bail!(
                    "expectations.{name}_statuses contains an unsupported code (accept: 2xx; reject: 4xx; duplicate: 2xx or 409)"
                );
            }
        }
        if !self.profile.capabilities().signed_timestamp && self.timestamp.is_some() {
            bail!("[timestamp] is unsupported for GitHub: its body HMAC contains no timestamp");
        }
        if self.profile != Profile::Github && self.expectations.require_unambiguous_signature_header
        {
            bail!("expectations.require_unambiguous_signature_header is only supported by the GitHub profile");
        }
        if let Some(t) = &self.timestamp {
            if !(30..=86400).contains(&t.tolerance_seconds)
                || !(0..=3600).contains(&t.future_skew_seconds)
            {
                bail!("timestamp tolerance must be 30..86400 and future skew 0..3600 seconds");
            }
        }
        Ok(())
    }
    pub fn url(&self) -> Result<Url> {
        let url = Url::parse(&self.endpoint).context("endpoint must be an absolute URL")?;
        if url.scheme() != "http"
            || url.username() != ""
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            bail!("endpoint must be a plain HTTP loopback URL without credentials, query, or fragment");
        }
        match url.host() {
            Some(Host::Ipv4(ip)) if ip.is_loopback() => {}
            Some(Host::Ipv6(ip)) if ip.is_loopback() => {}
            Some(Host::Domain("localhost")) => {}
            _ => bail!("endpoint must use 127.0.0.1, [::1], or localhost"),
        }
        if url.port_or_known_default().is_none() {
            bail!("endpoint has no valid port");
        }
        Ok(url)
    }
    pub fn secret(&self) -> Result<Vec<u8>> {
        let secret = env::var(&self.secret_env).with_context(|| {
            format!(
                "{} is not set; set it to the local receiver's signing secret",
                self.secret_env
            )
        })?;
        if secret.is_empty() {
            bail!(
                "{} is empty; set a nonempty signing secret",
                self.secret_env
            );
        }
        Ok(secret.into_bytes())
    }
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
    pub fn timestamp_policy(&self) -> Timestamp {
        self.timestamp
            .as_ref()
            .map(|x| Timestamp {
                tolerance_seconds: x.tolerance_seconds,
                future_skew_seconds: x.future_skew_seconds,
            })
            .unwrap_or_default()
    }
    pub fn destination(&self) -> Result<(Url, Option<(String, IpAddr)>)> {
        let url = self.url()?;
        let pin = if url.host_str() == Some("localhost") {
            Some((
                "localhost".into(),
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            ))
        } else {
            None
        };
        Ok((url, pin))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Config {
        toml::from_str(include_str!("../examples/webhook-security-tester.toml")).unwrap()
    }
    #[test]
    fn rejects_remote_and_redirects() {
        let mut c = sample();
        c.endpoint = "http://example.com/webhook".into();
        assert!(c.validate().is_err());
        c.endpoint = "http://127.0.0.1:8787/webhook".into();
        c.runner.follow_redirects = true;
        assert!(c.validate().is_err());
    }
    #[test]
    fn validates_profile_specific_settings() {
        let mut c = sample();
        c.timestamp = Some(Timestamp::default());
        assert!(c.validate().is_err());
        c.timestamp = None;
        c.version = 2;
        assert!(c.validate().is_err());
        let mut t: Config = toml::from_str(include_str!("../examples/timestamped.toml")).unwrap();
        t.expectations.require_unambiguous_signature_header = true;
        assert!(t.validate().is_err());
    }
    #[test]
    fn unknown_profile_and_invalid_status_policy_are_rejected() {
        let raw = include_str!("../examples/webhook-security-tester.toml")
            .replace("profile = \"github\"", "profile = \"stripe\"");
        assert!(toml::from_str::<Config>(&raw).is_err());
        let mut c = sample();
        c.expectations.duplicate_statuses = vec![200, 500];
        assert!(c.validate().is_err());
        c.expectations.duplicate_statuses = vec![200, 409];
        c.observer.settle_ms = 0;
        assert!(c.validate().is_err());
    }
}

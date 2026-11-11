# Webhook Security Tester

**Prove your webhook handler behaves securely before production.**

Webhook Security Tester sends controlled, signed and intentionally malformed HTTP deliveries to a webhook consumer you run on loopback. It checks responses and, when a local observer is available, counts completed processing effects. The target application can be written in any language.

## What it tests

- GitHub's raw-body `X-Hub-Signature-256` protocol: valid bytes, absent and malformed headers, wrong secrets, body changes, and valid formatting variations.
- A clearly synthetic `timestamped-hmac-v1` protocol: signed timestamps, expiration, future skew, malformed timestamps, and in-window replay. It is **not** Stripe compatibility.
- Exact replay, changed GitHub delivery ID, sequential and concurrent duplicates, and distinct events.
- HTTP-only results remain **INCONCLUSIVE** for processing effects. Enable the observer on a controlled local instance to verify counts.

The bundled Axum receiver provides secure and deliberately vulnerable test modes. It is a fixture, not production middleware.

## Install and quickstart

Rust stable is required. No account, Docker, database, or provider token is needed.

```sh
git clone https://github.com/ranajahanzaib/webhook-security-tester.git
cd webhook-security-tester
cargo install --path crates/webhook-security-tester
export WEBHOOK_SECURITY_TESTER_GITHUB_SECRET='local-test-secret'
webhook-security-tester init
```

In another terminal, with the same environment variable:

```sh
webhook-security-tester-reference-receiver --profile github --port 8787 --mode secure
```

Then run:

```sh
webhook-security-tester test -c webhook-security-tester.toml --json report.json --markdown report.md
```

`init` creates the example config without overwriting an existing file. The default example enables the reference receiver's test-only observer. For another local consumer, set `[observer] enabled = false`; duplicate processing assertions then report INCONCLUSIVE.

Example configuration:

```toml
version = 1
profile = "github"
endpoint = "http://127.0.0.1:8787/webhooks/github"
secret_env = "WEBHOOK_SECURITY_TESTER_GITHUB_SECRET"
timeout_ms = 3000

[observer]
enabled = true
require = true
settle_ms = 500
```

The full examples are [`webhook-security-tester.toml`](crates/webhook-security-tester/examples/webhook-security-tester.toml) and [`timestamped.toml`](crates/webhook-security-tester/examples/timestamped.toml). Secrets are loaded from the environment and never written to reports.

Selected lines from a secure local GitHub run:

```text
SIGNATURE
PASS         GH-SIG-001   Correct HMAC over the original body — HTTP statuses [200] matched declared expectation
REPLAY
PASS         REPLAY-004   Replay signed body with a different unsigned X-GitHub-Delivery — HTTP statuses [200, 200]; observed 1 completed processing effect(s) after 500 ms settling window
TIMESTAMP
SKIP         TS-012       GitHub signed timestamp — GitHub's body HMAC contains no signed timestamp
SUMMARY
23 pass, 0 fail, 0 inconclusive, 1 skip, 0 error
```

Use `--only signature`, `--only replay`, `--only duplicate`, or `--only timestamp`; repeat `--only` for multiple categories. `--quiet` suppresses PASS lines while retaining findings and unsupported-test explanations. `fixtures list --profile github` lists scenarios; `explain GH-SIG-004` describes a finding offline.

`duplicate_statuses` may include `409` when a local consumer acknowledges a repeat with Conflict. The first delivery still must match `accept_statuses`, and processing safety still needs observer evidence. GitHub's ambiguous-header test treats acceptance as INCONCLUSIVE unless `expectations.require_unambiguous_signature_header = true` declares a strict rejection policy; the generated reference-receiver config sets it to true.

To see a real failure, restart the receiver with `--mode no-signature` and rerun the test. The receiver also has `reserialized-body`, `no-dedup`, `delivery-id-only`, and `no-timestamp` modes.

To try persisted replay suppression, start the receiver with `--state-file /tmp/webhook-security-tester-processed.json`. The receiver stores processed test IDs in that local file and suppresses the same event after restart.

For the timestamp profile, set `WEBHOOK_SECURITY_TESTER_TIMESTAMP_SECRET`, start the receiver with `--profile timestamped-hmac-v1 --port 8788`, and run `test -c crates/webhook-security-tester/examples/timestamped.toml`.

## CI and exit codes

`0`: required tests passed; `1`: an assertion failed; `2`: configuration or execution error, no applicable tests, or required observer evidence unavailable. INCONCLUSIVE results are never counted as passes. Set `observer.require = true` to make missing processing evidence non-successful. See [CI integration](docs/ci-integration.md).

## Security limits

Webhook Security Tester permits only HTTP loopback targets. It disables proxy inheritance and redirects, pins `localhost` to `127.0.0.1`, limits request and response bodies, and has finite timeouts. It tests systems you control. GitHub's body HMAC has no signed timestamp and does not cover `X-GitHub-Delivery`; neither authenticity nor an HTTP 200 alone proves replay safety. The reference receiver uses a synthetic signed fixture `id` as its idempotency key. That is a controlled test contract, not a universal GitHub event identity rule. Passing local tests does not prove production behavior or total webhook security. See [limitations](docs/limitations.md) and [threat model](docs/threat-model.md).

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release
```

Architecture, profile rules, and the complete test catalog are in [`docs/`](docs/). Contributions are welcome under [CONTRIBUTING.md](CONTRIBUTING.md). MIT license: [LICENSE](LICENSE).

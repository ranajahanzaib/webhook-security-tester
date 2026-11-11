# Limitations

- HTTP responses cannot establish exactly-once processing. Duplicate assertions are INCONCLUSIVE without a functioning observer.
- Observer counts are a snapshot after the configured settling window; effects occurring later are outside the observed interval. Run against an isolated local test instance and increase `observer.settle_ms` if processing is asynchronous.
- GitHub's body signature does not bind a timestamp or the `X-GitHub-Delivery` header. Authentic signed requests may be replayed. A changed delivery header may bypass header-only deduplication.
- The reference receiver uses a signed fixture `id` for test identity. A real GitHub consumer must choose an event-appropriate identity strategy. Content hashes can suppress legitimate identical events; unsigned IDs can be changed. Retention windows and false positives are application decisions.
- Signed timestamps bound replay only to a time window. Inside-window duplicates still need idempotency protection.
- The duplicate scenarios replay an event after a successful first delivery. A failed attempt followed by a retry may legitimately complete processing once; that separate business-flow behavior is not established by these scenarios.
- The reference receiver uses in-memory state by default. Its test-only `--state-file` option persists processed IDs; an integration test verifies restart suppression. The general CLI does not restart arbitrary consumers or test long retention windows.
- Local results do not cover production routing, middleware, infrastructure, or provider delivery behavior. Passing does not guarantee total application security.
- `timestamped-hmac-v1` is synthetic and does not claim Stripe compatibility.

# Provider profiles

| Property              | GitHub                                     | timestamped-hmac-v1                                  |
| --------------------- | ------------------------------------------ | ---------------------------------------------------- |
| Signature             | `X-Hub-Signature-256: sha256=<hex>`        | `WebhookSecurityTester-Signature: t=<unix>,v1=<hex>` |
| Signed bytes          | Exact raw body                             | ASCII timestamp, period byte, exact raw body         |
| MAC                   | HMAC-SHA256                                | HMAC-SHA256                                          |
| Signed timestamp      | No                                         | Yes                                                  |
| Delivery identifier   | `X-GitHub-Delivery`, unsigned by body HMAC | Synthetic signed JSON `id` in fixture                |
| Duplicate observation | Optional local observer                    | Optional local observer                              |

The serialized capability model also distinguishes a provider delivery ID from the signed `id` in Webhook Security Tester's controlled fixture body. For GitHub, only the latter is authenticated by the body HMAC. It is a test contract rather than a claim that every GitHub webhook payload has an `id` field.

GitHub's standard body HMAC has no timestamp. The runner marks `TS-012` SKIP, not PASS. A requested GitHub redelivery reuses the original delivery ID, but changing that unsigned header does not invalidate the body signature. Signature authenticity, idempotency, and replay resistance are separate properties. References: [validation](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries), [best practices](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks).

`timestamped-hmac-v1` is a Webhook Security Tester test protocol, not a provider adapter or Stripe compatibility claim. The default acceptance window is 300 seconds old and 30 seconds in the future. The receiver verifies both the MAC and the window. Clocks should be synchronized for live tests. Unit tests inject explicit timestamps and clock values for deterministic boundary checks. The suite uses a bounded 1–30-second margin for live boundary scenarios to avoid network scheduling false failures. Configure `[timestamp] tolerance_seconds` and `future_skew_seconds` only for this profile, and use the same policy on the receiver.

Each profile has its own signed bytes, header parser, clock rules, event identity semantics, redelivery behavior, and capabilities. Profiles that use the same MAC algorithm can still differ in all of these properties.

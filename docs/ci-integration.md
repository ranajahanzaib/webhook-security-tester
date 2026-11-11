# CI integration

The repository workflow runs formatting, Clippy, unit tests, a release build, starts the secure local receiver, and runs the GitHub conformance suite. It uploads a sanitized JSON report. The receiver process is stopped by a shell trap.

For another repository, start a local test instance of your own consumer, set its test signing secret and `WEBHOOK_SECURITY_TESTER_GITHUB_SECRET` to the same value, and run:

```sh
webhook-security-tester test -c webhook-security-tester.toml --json webhook-security-tester-report.json --quiet
```

Set `observer.enabled = false` if your consumer does not expose the local observer contract. Set `observer.require = true` when CI must reject unavailable processing evidence. Exit codes: 0 for no failed required assertions or errors, 1 for assertion failure, 2 for configuration/execution error, no applicable tests, or required observer evidence unavailable. Inspect `summary.inconclusive` even when exit 0 is allowed by your policy.

Never use production webhook credentials in CI fixtures. Keep diagnostic observer routes loopback-only and test-only.

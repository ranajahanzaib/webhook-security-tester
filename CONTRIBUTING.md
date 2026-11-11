# Contributing

Contributions to Webhook Security Tester are welcome. Open an issue to discuss protocol changes before implementing a new provider profile. Protocol claims need primary provider documentation and tests using exact signed bytes.

From a clean checkout, run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release
```

Integration tests bind dynamically allocated loopback ports and do not contact external services. Do not use live provider credentials or public targets in tests. Add a regression test when fixing a signature, classification, observer, or network restriction bug.

Keep scenarios deterministic and document their expected response, required observation, and protocol limitations in `docs/test-catalog.md`. Describe what local evidence proves and what remains inconclusive. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community expectations and [LICENSE](LICENSE) for terms.

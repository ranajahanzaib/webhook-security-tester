# Test catalog

All listed scenarios send actual HTTP requests. Accept expects a configured 2xx code; reject expects a configured 4xx code. Processing assertions require the local observer and are INCONCLUSIVE without it. A transport failure is ERROR. Every body is deterministic; a unique signed fixture `id` isolates each scenario.

| ID         | Objective and input                                  | Expected                            | Observation / limit                                                                                          |
| ---------- | ---------------------------------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| GH-SIG-001 | Correct HMAC over raw body                           | Accept                              | HTTP status                                                                                                  |
| GH-SIG-002 | Omit SHA-256 signature                               | Reject                              | HTTP status                                                                                                  |
| GH-SIG-003 | Replace digest with wrong digest                     | Reject                              | HTTP status                                                                                                  |
| GH-SIG-004 | Change one valid JSON body byte after signing        | Reject                              | HTTP status; catches raw-byte verification failure                                                           |
| GH-SIG-005 | Sign with distinct test secret                       | Reject                              | HTTP status                                                                                                  |
| GH-SIG-006 | Truncate digest                                      | Reject                              | HTTP status                                                                                                  |
| GH-SIG-007 | Invalid hex in digest                                | Reject                              | HTTP status                                                                                                  |
| GH-SIG-008 | Wrong `sha1=` prefix in SHA-256 header               | Reject                              | HTTP status                                                                                                  |
| GH-SIG-009 | Legacy SHA-1 header only                             | Reject                              | Declared SHA-256-required policy; legacy deployments may differ                                              |
| GH-SIG-010 | Correctly sign pretty JSON                           | Accept                              | HTTP status; exact formatted bytes                                                                           |
| GH-SIG-011 | Correctly sign UTF-8 Unicode JSON                    | Accept                              | HTTP status                                                                                                  |
| GH-SIG-012 | Correctly sign CRLF JSON                             | Accept                              | HTTP status                                                                                                  |
| GH-SIG-013 | Correctly sign reordered JSON properties             | Accept                              | HTTP status                                                                                                  |
| GH-SIG-014 | Sign compact JSON, send equivalent pretty JSON       | Reject                              | HTTP status; catches parse/normalize verification                                                            |
| GH-SIG-015 | Conflicting duplicated SHA-256 headers               | Reject under declared strict policy | If accepted without `require_unambiguous_signature_header = true`, classify INCONCLUSIVE; HTTP stacks differ |
| GH-SIG-016 | Empty signature value                                | Reject                              | HTTP status                                                                                                  |
| TS-001     | Current signed timestamp                             | Accept                              | HTTP status                                                                                                  |
| TS-002     | Correctly signed expired timestamp                   | Reject                              | HTTP status; signature remains valid for old timestamp                                                       |
| TS-003     | Correctly signed future timestamp beyond skew        | Reject                              | HTTP status                                                                                                  |
| TS-004     | Correctly signed timestamp inside age boundary       | Accept                              | Live scenario uses a bounded scheduling margin of 1–30 seconds                                               |
| TS-005     | Correctly signed timestamp outside age boundary      | Reject                              | Live scenario uses a bounded scheduling margin of 1–30 seconds                                               |
| TS-006     | Missing timestamp component                          | Reject                              | HTTP status                                                                                                  |
| TS-007     | Nonnumeric timestamp                                 | Reject                              | HTTP status                                                                                                  |
| TS-008     | Change timestamp after signing                       | Reject                              | HTTP status                                                                                                  |
| TS-009     | Valid timestamp, invalid HMAC                        | Reject                              | HTTP status                                                                                                  |
| TS-010     | Change valid JSON body byte after signing            | Reject                              | HTTP status                                                                                                  |
| TS-011     | Replay signed event inside time window               | Process once                        | Observer required; timestamp alone does not stop replay                                                      |
| TS-012     | Select timestamp tests under GitHub                  | SKIP                                | GitHub has no signed timestamp                                                                               |
| REPLAY-001 | Send identical signed request twice                  | Process once                        | Observer required                                                                                            |
| REPLAY-002 | Repeat signed body and original GitHub delivery ID   | Process once                        | Observer required; models redelivery                                                                         |
| REPLAY-003 | Send same request three times                        | Process once                        | Observer required                                                                                            |
| REPLAY-004 | Replay signed body with changed unsigned delivery ID | Process once                        | Observer required; demonstrates header-only dedup weakness                                                   |
| DUP-001    | Two sequential deliveries                            | Process once                        | Observer required                                                                                            |
| DUP-002    | Barrier-start concurrent deliveries                  | Process once                        | Observer required; count bounded by `runner.concurrency`                                                     |
| DUP-003    | Two distinct signed fixture IDs                      | Process twice                       | Observer required; avoids suppress-all false confidence                                                      |
| DUP-004    | Concurrent timestamped duplicates                    | Process once                        | Observer required                                                                                            |

The CLI does not restart arbitrary consumer processes or test a configured retention interval. See [limitations](limitations.md).

Restart durability is covered by an integration test: it restarts the bundled receiver with `--state-file`, replays the authenticated body, and verifies that the second process records no additional completed effect and one duplicate suppression. Retention-window replay is not currently configurable in the CLI.

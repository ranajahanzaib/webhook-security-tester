# Threat model

Webhook Security Tester targets local development and CI webhook consumers. Its inputs are a user-authored config and a secret read from an environment variable. The runner sends deterministic requests only to a loopback HTTP destination, with redirects and proxy inheritance disabled. It does not discover endpoints, contact provider APIs, use real account credentials, or run untrusted scripts. Do not place credentials in the endpoint URL path; the report includes the target URL for identification.

Covered failures include absent or malformed signature enforcement, byte-transforming verification, expired synthetic timestamps, duplicate processing, and weak reliance on GitHub's unsigned delivery header. A 4xx response is evidence of configured rejection, not a proof of the internal reason. An observer count is evidence of completed processing in the controlled test receiver, not a general proof of all business effects.

Out of scope: malicious local processes, compromised signing secrets, production load balancers, provider infrastructure, external callback side effects, full business-logic correctness, replay retention after an arbitrary period, and every possible parser ambiguity. The diagnostic routes are local test fixtures. Do not expose them in production.

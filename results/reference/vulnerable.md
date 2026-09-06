# MCPSB report — `vulnerable`

Spec 0.1 · generated 2026-09-04T13:14:41+00:00

> No aggregate score by design (SPEC §4). `UNSUP`/`OOS` are the N/A bucket — the target was not meaningfully asked, not that it failed.

## Summary by severity

| Severity | PASS | FAIL | UNSUP | OOS | INCONC | ERROR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| CRITICAL | 0 | 8 | 0 | 0 | 0 | 0 |
| HIGH | 0 | 20 | 0 | 0 | 0 | 0 |
| MEDIUM | 0 | 7 | 0 | 0 | 0 | 0 |
| LOW | 0 | 0 | 0 | 0 | 0 | 0 |
| **Total** | **0** | **35** | **0** | **0** | **0** | **0** |

## Detail

| Sub-ID | Severity | Verdict | Reason |
| --- | --- | --- | --- |
| `AUTH-001.a` | CRITICAL | FAIL | a: attack succeeded (served a result) |
| `AUTH-001.b` | CRITICAL | FAIL | b: attack succeeded (served a result) |
| `AUTH-002.b` | CRITICAL | FAIL | A's token was accepted while acting as principal B |
| `AUTH-003.b` | HIGH | FAIL | b: attack succeeded (served a result) |
| `AUTH-004.b` | HIGH | FAIL | b: attack succeeded (served a result) |
| `AUTHZ-001.b` | HIGH | FAIL | b: attack succeeded (served a result) |
| `AUTHZ-001.c` | HIGH | FAIL | c: attack succeeded (served a result) |
| `AUTHZ-001.d` | HIGH | FAIL | d: attack succeeded (served a result) |
| `AUTHZ-001.e` | HIGH | FAIL | batch: unauthorized call executed |
| `AUTHZ-002.a` | HIGH | FAIL | hidden tool disclosed by tools/list |
| `AUTHZ-002.b` | HIGH | FAIL | b: attack succeeded (served a result) |
| `AUTHZ-003.a` | HIGH | FAIL | restricted tool discoverable via list |
| `AUTHZ-003.b` | HIGH | FAIL | b: attack succeeded (served a result) |
| `AUTHZ-003.c` | HIGH | FAIL | c: attack succeeded (served a result) |
| `AUTHZ-003.d` | HIGH | FAIL | d: attack succeeded (served a result) |
| `AUTHZ-004.e` | HIGH | FAIL | batch: unauthorized call slipped past the gate |
| `TENANT-001.b` | CRITICAL | FAIL | argument re-scoped the tenant; other tenant's data returned |
| `TENANT-002.b` | CRITICAL | FAIL | a request-controlled field re-scoped the tenant |
| `SSRF-001.b` | HIGH | FAIL | intermediary forwarded the call to the internal address |
| `SSRF-002.b` | CRITICAL | FAIL | intermediary proxied a call to instance metadata |
| `SSRF-003.b` | HIGH | FAIL | IPv4-mapped encoding reached loopback |
| `SSRF-004.b` | CRITICAL | FAIL | rebinding reached loopback after a benign policy check |
| `SSRF-005.b` | HIGH | FAIL | followed a redirect to an internal destination |
| `EGRESS-001.b` | HIGH | FAIL | a confusable child of the allowlisted host was reached |
| `SCHEMA-001.a` | MEDIUM | FAIL | tool silently gained argument(s): ['injected_arg'] |
| `SCHEMA-001.b` | MEDIUM | FAIL | b: attack succeeded (served a result) |
| `SCHEMA-002.a` | MEDIUM | FAIL | tool description mutated after admission |
| `SCHEMA-002.b` | MEDIUM | FAIL | tool description mutated after admission |
| `SCHEMA-003.a` | HIGH | FAIL | a colliding tool name appears more than once |
| `SCHEMA-003.b` | HIGH | FAIL | call served by the shadowing upstream |
| `SESSION-001.f` | HIGH | FAIL | one session's state was readable from another |
| `SECRET-001.b` | CRITICAL | FAIL | secret interpolated into the response |
| `AUDIT-001.b` | MEDIUM | FAIL | action executed with no audit event |
| `AUDIT-001.e` | MEDIUM | FAIL | action executed with no audit event |
| `AUDIT-002.b` | MEDIUM | FAIL | raw sensitive argument recorded in the trace |

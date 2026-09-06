# MCPSB report — `secure`

Spec 0.1 · generated 2026-09-04T13:14:39+00:00

> No aggregate score by design (SPEC §4). `UNSUP`/`OOS` are the N/A bucket — the target was not meaningfully asked, not that it failed.

## Summary by severity

| Severity | PASS | FAIL | UNSUP | OOS | INCONC | ERROR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| CRITICAL | 8 | 0 | 0 | 0 | 0 | 0 |
| HIGH | 20 | 0 | 0 | 0 | 0 | 0 |
| MEDIUM | 7 | 0 | 0 | 0 | 0 | 0 |
| LOW | 0 | 0 | 0 | 0 | 0 | 0 |
| **Total** | **35** | **0** | **0** | **0** | **0** | **0** |

## Detail

| Sub-ID | Severity | Verdict | Reason |
| --- | --- | --- | --- |
| `AUTH-001.a` | CRITICAL | PASS | a: blocked (unauthenticated) |
| `AUTH-001.b` | CRITICAL | PASS | b: blocked (unauthenticated) |
| `AUTH-002.b` | CRITICAL | PASS | token stayed bound to its own principal |
| `AUTH-003.b` | HIGH | PASS | b: blocked (unauthenticated) |
| `AUTH-004.b` | HIGH | PASS | b: blocked (unauthenticated) |
| `AUTHZ-001.b` | HIGH | PASS | b: blocked (not authorized for tool read_doc) |
| `AUTHZ-001.c` | HIGH | PASS | c: blocked (not authorized for prompt greeting) |
| `AUTHZ-001.d` | HIGH | PASS | d: blocked (not authorized for resource notes) |
| `AUTHZ-001.e` | HIGH | PASS | batch: unauthorized call blocked |
| `AUTHZ-002.a` | HIGH | PASS | hidden tool not disclosed |
| `AUTHZ-002.b` | HIGH | PASS | b: blocked (not authorized for tool admin_ping) |
| `AUTHZ-003.a` | HIGH | PASS | restricted tool not discoverable |
| `AUTHZ-003.b` | HIGH | PASS | b: blocked (not authorized for tool Admin_Ping) |
| `AUTHZ-003.c` | HIGH | PASS | c: blocked (not authorized for prompt Admin_Prompt) |
| `AUTHZ-003.d` | HIGH | PASS | d: blocked (not authorized for resource Admin_Resource) |
| `AUTHZ-004.e` | HIGH | PASS | batch: unauthorized call gated |
| `TENANT-001.b` | CRITICAL | PASS | tenant stayed bound to the session |
| `TENANT-002.b` | CRITICAL | PASS | tenant stayed bound to the session |
| `SSRF-001.b` | HIGH | PASS | egress to the internal address was blocked |
| `SSRF-002.b` | CRITICAL | PASS | egress to instance metadata was blocked |
| `SSRF-003.b` | HIGH | PASS | alternate encoding was resolved and blocked |
| `SSRF-004.b` | CRITICAL | PASS | connect-time address was re-checked and blocked |
| `SSRF-005.b` | HIGH | PASS | redirect chain was re-checked and blocked |
| `EGRESS-001.b` | HIGH | PASS | whole-label match rejected the confusable host |
| `SCHEMA-001.a` | MEDIUM | PASS | advertised argument set stayed pinned |
| `SCHEMA-001.b` | MEDIUM | PASS | b: blocked (argument outside the admitted schema for echo) |
| `SCHEMA-002.a` | MEDIUM | PASS | description stayed pinned to what was admitted |
| `SCHEMA-002.b` | MEDIUM | PASS | description stayed pinned to what was admitted |
| `SCHEMA-003.a` | HIGH | PASS | tool names stayed unique |
| `SCHEMA-003.b` | HIGH | PASS | call served by the original upstream |
| `SESSION-001.f` | HIGH | PASS | session state stayed isolated across reconnect |
| `SECRET-001.b` | CRITICAL | PASS | probe returned without interpolating the secret |
| `AUDIT-001.b` | MEDIUM | PASS | action produced an audit event |
| `AUDIT-001.e` | MEDIUM | PASS | action produced an audit event |
| `AUDIT-002.b` | MEDIUM | PASS | trace redacted the sensitive argument |

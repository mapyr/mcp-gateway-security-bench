# MCPSB combined matrix

> One matrix, every registry sub-ID as a row and every target as a column. No cell is blank: where a target was not meaningfully asked the cell reads `UNSUP`, and where preconditions were never established it reads `INCON`. There is no aggregate score (SPEC §4). Most cells read `INCON` because that is the honest result — a live intermediary rarely lets the bench establish every precondition end-to-end.

- `secure` — mcpsb-reference/0.1.0.dev0, spec 0.1, generated 2026-09-04T13:14:39+00:00
- `vulnerable` — mcpsb-reference/0.1.0.dev0, spec 0.1, generated 2026-09-04T13:14:41+00:00

## Summary

- **2 of 2 target(s) were exercised live** (`secure`, `vulnerable`): each produced at least one non-INCONCLUSIVE verdict.
- **Verdicts were confirmed by the out-of-band observation plane** for `secure`, `vulnerable` (evidence from the sink/DNS/IMDS, not the target's own response).
- **Every target with a PASS has a verified positive control** (`secure`): a legitimate request was accepted before a blocked one was scored.

Target versions (sourced from the artifact under test):
- `secure` — mcpsb-reference/0.1.0.dev0
- `vulnerable` — mcpsb-reference/0.1.0.dev0

## Positive controls (per family)

| Family | `secure` | `vulnerable` |
| --- | :---: | :---: |
| AUDIT | PASS [^1] | FAIL [^2] |
| AUTH | PASS [^3] | PASS [^3] |
| AUTHZ | PASS [^4] | PASS [^4] |
| EGRESS | PASS [^5] | PASS [^5] |
| SCHEMA | PASS [^6] | PASS [^6] |
| SECRET | PASS [^7] | PASS [^7] |
| SESSION | PASS [^8] | PASS [^8] |
| SSRF | PASS [^5] | PASS [^5] |
| TENANT | PASS [^9] | PASS [^9] |

## Verdicts (per sub-ID)

| Sub-ID | `secure` | `vulnerable` |
| --- | :---: | :---: |
| `AUTH-001.a` | PASS [^10] | FAIL [^11] |
| `AUTH-001.b` | PASS [^12] | FAIL [^13] |
| `AUTH-002.b` | PASS [^14] | FAIL [^15] |
| `AUTH-003.b` | PASS [^12] | FAIL [^13] |
| `AUTH-004.b` | PASS [^12] | FAIL [^13] |
| `AUTHZ-001.b` | PASS [^16] | FAIL [^13] |
| `AUTHZ-001.c` | PASS [^17] | FAIL [^18] |
| `AUTHZ-001.d` | PASS [^19] | FAIL [^20] |
| `AUTHZ-001.e` | PASS [^21] | FAIL [^22] |
| `AUTHZ-002.a` | PASS [^23] | FAIL [^24] |
| `AUTHZ-002.b` | PASS [^25] | FAIL [^13] |
| `AUTHZ-003.a` | PASS [^26] | FAIL [^27] |
| `AUTHZ-003.b` | PASS [^28] | FAIL [^13] |
| `AUTHZ-003.c` | PASS [^29] | FAIL [^18] |
| `AUTHZ-003.d` | PASS [^30] | FAIL [^20] |
| `AUTHZ-004.e` | PASS [^31] | FAIL [^32] |
| `TENANT-001.b` | PASS [^33] | FAIL [^34] |
| `TENANT-002.b` | PASS [^33] | FAIL [^35] |
| `SSRF-001.b` | PASS [^36] | FAIL [^37] |
| `SSRF-002.b` | PASS [^38] | FAIL [^39] |
| `SSRF-003.b` | PASS [^40] | FAIL [^41] |
| `SSRF-004.b` | PASS [^42] | FAIL [^43] |
| `SSRF-005.b` | PASS [^44] | FAIL [^45] |
| `EGRESS-001.b` | PASS [^46] | FAIL [^47] |
| `SCHEMA-001.a` | PASS [^48] | FAIL [^49] |
| `SCHEMA-001.b` | PASS [^50] | FAIL [^13] |
| `SCHEMA-002.a` | PASS [^51] | FAIL [^52] |
| `SCHEMA-002.b` | PASS [^51] | FAIL [^52] |
| `SCHEMA-003.a` | PASS [^53] | FAIL [^54] |
| `SCHEMA-003.b` | PASS [^55] | FAIL [^56] |
| `SESSION-001.f` | PASS [^57] | FAIL [^58] |
| `SECRET-001.b` | PASS [^59] | FAIL [^60] |
| `AUDIT-001.b` | PASS [^61] | FAIL [^62] |
| `AUDIT-001.e` | PASS [^61] | FAIL [^62] |
| `AUDIT-002.b` | PASS [^63] | FAIL [^64] |

## Cell reasons

[^1]: a legitimate action produced an audit entry (the log is live)
[^2]: the audit log recorded nothing for a legitimate action
[^3]: valid credentials were accepted for an authorized tool
[^4]: an authorized principal could list and call its permitted tool
[^5]: a permitted destination was resolved through the bench DNS (observation plane is in the egress path)
[^6]: the schema-bearing tool was advertised and callable with valid input
[^7]: the render tool served a benign template without leaking the secret
[^8]: a value written in a session was readable within the same session
[^9]: a principal could read its own tenant's data
[^10]: a: blocked (unauthenticated)
[^11]: a: attack succeeded (served a result)
[^12]: b: blocked (unauthenticated)
[^13]: b: attack succeeded (served a result)
[^14]: token stayed bound to its own principal
[^15]: A's token was accepted while acting as principal B
[^16]: b: blocked (not authorized for tool read_doc)
[^17]: c: blocked (not authorized for prompt greeting)
[^18]: c: attack succeeded (served a result)
[^19]: d: blocked (not authorized for resource notes)
[^20]: d: attack succeeded (served a result)
[^21]: batch: unauthorized call blocked
[^22]: batch: unauthorized call executed
[^23]: hidden tool not disclosed
[^24]: hidden tool disclosed by tools/list
[^25]: b: blocked (not authorized for tool admin_ping)
[^26]: restricted tool not discoverable
[^27]: restricted tool discoverable via list
[^28]: b: blocked (not authorized for tool Admin_Ping)
[^29]: c: blocked (not authorized for prompt Admin_Prompt)
[^30]: d: blocked (not authorized for resource Admin_Resource)
[^31]: batch: unauthorized call gated
[^32]: batch: unauthorized call slipped past the gate
[^33]: tenant stayed bound to the session
[^34]: argument re-scoped the tenant; other tenant's data returned
[^35]: a request-controlled field re-scoped the tenant
[^36]: egress to the internal address was blocked
[^37]: intermediary forwarded the call to the internal address
[^38]: egress to instance metadata was blocked
[^39]: intermediary proxied a call to instance metadata
[^40]: alternate encoding was resolved and blocked
[^41]: IPv4-mapped encoding reached loopback
[^42]: connect-time address was re-checked and blocked
[^43]: rebinding reached loopback after a benign policy check
[^44]: redirect chain was re-checked and blocked
[^45]: followed a redirect to an internal destination
[^46]: whole-label match rejected the confusable host
[^47]: a confusable child of the allowlisted host was reached
[^48]: advertised argument set stayed pinned
[^49]: tool silently gained argument(s): ['injected_arg']
[^50]: b: blocked (argument outside the admitted schema for echo)
[^51]: description stayed pinned to what was admitted
[^52]: tool description mutated after admission
[^53]: tool names stayed unique
[^54]: a colliding tool name appears more than once
[^55]: call served by the original upstream
[^56]: call served by the shadowing upstream
[^57]: session state stayed isolated across reconnect
[^58]: one session's state was readable from another
[^59]: probe returned without interpolating the secret
[^60]: secret interpolated into the response
[^61]: action produced an audit event
[^62]: action executed with no audit event
[^63]: trace redacted the sensitive argument
[^64]: raw sensitive argument recorded in the trace

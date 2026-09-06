# MCPSB — Specification

**Version:** 0.1 (draft) · **License:** CC BY 4.0 (this document) · code is Apache-2.0

> The test tables and premises in the lower half of this file are **generated
> from [`mcpsb/registry.py`](mcpsb/registry.py)**. Do not edit anything below
> the `GENERATED FROM …` marker by hand — run `python -m mcpsb.registry --write`
> and commit the result. CI fails the build if they drift (`ci/check_spec_drift.py`).

---

## 1. What this is

MCPSB is a reproducible set of attacks that every **MCP intermediary** should
pass. An *intermediary* is any component that sits on the path between an MCP
client and an MCP server and makes a decision about the call. "Gateway" is in
the repository name for discoverability; the object under test is the
intermediary.

It is **not** a ranking, a scanner, or a scoring tool. There is deliberately no
aggregate score (§ verdicts). The output is a per-severity count with an
explicit N/A column, so the reader sees *which* invariants held and which did
not, not a single number that reduces to marketing within a week.

## 2. Scope of v0.1

The eventual model has three layers: **Gateway** (will the action pass?),
**Runtime** (what happens if the MCP server is malicious?), and **Governance**
(can you prove to an auditor two years from now what happened?).

**v0.1 tests the Gateway layer only, plus a minimal AUDIT slice.** Runtime
requires control over how each target launches its MCP servers, which differs
per target and would blow up the harness. Governance without a working Gateway
is theatre. Layers 2–3 are v0.3+ or never. This scope is a spec commitment, not
a schedule note.

Explicitly out of v0.1: canary/version routing, HA/multi-replica behavior,
runtime/sandbox, SIEM/governance, rate limiting.

## 3. The three design decisions

These three are the design; the rest is work.

### 3.1 The verdict never comes from the system under test

The bench owns an **observation plane** independent of the SUT: an HTTP sink
that records every inbound request, a DNS server under bench control (full query
log + a rebinding zone with TTL=0), a fake IMDS at `169.254.169.254`, a redirect
server, and the JSON-RPC responses delivered to the attacking client. A verdict
is derived from what the observation plane recorded, never from the SUT's own
logs, metrics, or API responses.

**Sole exception:** the `AUDIT-*` family, where the SUT's log *is* the subject of
study. Even there the action is driven and observed out-of-band first; the audit
record is then checked against that ground truth.

### 3.2 Every attack runs on every surface

A mismatch found on one surface is a hypothesis about *every* surface reading
the same map, not about that one surface. Each test therefore declares the
surfaces it must exercise, and the runner runs it on each. Surface sub-IDs use a
letter suffix (`AUTHZ-002.a`, `.b`, …). A surface the target lacks yields
`UNSUPPORTED` for that letter — never `PASS`. **A test family implemented for
only one of its declared letters is not mergeable.**

### 3.3 Every test declares its premise

A maintainer who receives a FAIL does not attack the mechanism; they attack the
premise. So every test carries a mandatory `premise`: one sentence stating the
trust-boundary assumption it makes. If a maintainer links a public document
saying "that trust boundary is deliberately open for us," the bench records
`DECLARED-OUT-OF-SCOPE` with the link and does not count it as FAIL. This is not
softness — it is the only way the result is something other than an argument
about definitions, and it forces projects to write down publicly what they do
*not* protect.

## 4. Verdict dictionary

| Verdict | Meaning |
| --- | --- |
| `PASS` | Attack blocked; out-of-band observation confirms it. |
| `FAIL` | Attack succeeded. |
| `UNSUPPORTED` | Target cannot express the policy the test setup requires (no notion of tenant, no egress policy, …). **Not** a FAIL. |
| `DECLARED-OUT-OF-SCOPE` | Maintainer has a public, linked document placing this trust boundary outside their threat model. |
| `INCONCLUSIVE` | Harness never established preconditions (target didn't start, flaky network). **Never degrades to PASS or FAIL.** |
| `ERROR` | The bench itself failed. |

`UNSUPPORTED ≠ FAIL` is load-bearing: a gateway with no concept of
multi-tenancy does not *fail* tenant isolation, it does not *offer* it, and that
is how it must be reported.

The report is per-severity counts plus an explicit N/A column. **No aggregate
indicator.**

## 5. Severity is frozen

Severity is an attribute of the *test*, set when the ID is created, and
immutable. Changing expected behavior means a new ID plus deprecation of the old
one; IDs are never renumbered. CI compares each ID's severity against the last
tag; a change requires a commit tagged `spec-change:` and an entry in
[`SPEC-CHANGELOG.md`](SPEC-CHANGELOG.md).

The severity ladder and the full test registry follow, generated from the
registry module.

<!-- GENERATED FROM mcpsb/registry.py — DO NOT EDIT BY HAND -->

## Severity registry

Severity is an attribute of the *test*, frozen at ID creation.

| Severity | Definition |
| --- | --- |
| CRITICAL | Authentication bypass, tenant-isolation bypass, arbitrary code execution, gateway takeover, or access to high-value credentials. |
| HIGH | Authorization bypass, SSRF into internal network / IMDS, invoking a tool without its required policy, or cross-session access. |
| MEDIUM | Action with no audit record, silent schema change, secret leaked to a log or trace, or a broken rate limit. |
| LOW | Metadata leak or overly detailed errors. |

## Surfaces

Each attack is executed on *every* surface it declares (§3.2).

| Letter | Surface |
| --- | --- |
| `a` | tools/list |
| `b` | tools/call |
| `c` | prompts/get |
| `d` | resources/read |
| `e` | batch / aggregating path |
| `f` | reconnect / resumption path |

## Test registry

23 active IDs.

| ID | Name | Severity | Surfaces | Source |
| --- | --- | --- | --- | --- |
| AUTH-001 | Unauthenticated tools/list | CRITICAL | `a` `b` | baseline |
| AUTH-002 | Client A's token presented as B | CRITICAL | `b` | baseline |
| AUTH-003 | Expired token | HIGH | `b` | baseline |
| AUTH-004 | Wrong audience (RFC 8707) | HIGH | `b` | Hangar 1.4.0 audience binding |
| AUTHZ-001 | No permission for the call | HIGH | `b` `c` `d` `e` | baseline |
| AUTHZ-002 | Tool hidden from list, called directly | HIGH | `a` `b` | class: mechanism present, path absent |
| AUTHZ-003 | Group/alias policy bypassed by different keying | HIGH | `a` `b` `c` `d` | Hangar #1036/#1040, F3 |
| AUTHZ-004 | Batch path bypasses per-call gate | HIGH | `e` | Hangar _GATES, batch pre-gate |
| TENANT-001 | Tenant override in tool arguments | CRITICAL | `b` | baseline |
| TENANT-002 | Tenant override in header / path / _meta | CRITICAL | `b` | Hangar SEP-2243 / Mcp-Param-* |
| SSRF-001 | Loopback + RFC1918 | HIGH | `b` | baseline |
| SSRF-002 | IMDS 169.254.169.254 | CRITICAL | `b` | baseline |
| SSRF-003 | IPv6 and IPv4-mapped (::ffff:) | HIGH | `b` | Hangar #900 |
| SSRF-004 | DNS rebinding: TOCTOU register->connect | CRITICAL | `b` | Hangar #836, GHSA UI-TARS |
| SSRF-005 | Redirect chain past the allowlist | HIGH | `b` | ToolHive-class |
| EGRESS-001 | Suffix confusion (api.example.com.evil.com) | HIGH | `b` | baseline |
| SCHEMA-001 | Silent schema expansion (new argument) | MEDIUM | `a` `b` | Hangar digest pinning |
| SCHEMA-002 | Tool description rug pull (tool poisoning) | MEDIUM | `a` `b` | advisory: open-webui |
| SCHEMA-003 | Tool shadowing / cross-upstream name collision | HIGH | `a` `b` | advisory: Docker MCP Gateway |
| SESSION-001 | State leak across sessions after reconnect | HIGH | `f` | agentgateway, Hangar #929/#802 |
| SECRET-001 | Env exfiltration via arguments / response | CRITICAL | `b` | baseline |
| AUDIT-001 | Action executed with no audit event | MEDIUM | `b` `e` | Hangar F4 |
| AUDIT-002 | Secrets / raw arguments in audit or trace | MEDIUM | `b` | Hangar F7/F8 |

## Premises

Each test declares the trust-boundary assumption it makes (§3.3). A maintainer who disputes a FAIL disputes the premise, not the mechanism; a linked public document placing the boundary out of scope yields `DECLARED-OUT-OF-SCOPE`, not `FAIL`.

### AUTH-001 — Unauthenticated tools/list

*Severity:* CRITICAL  
*Surfaces:* `a` (tools/list), `b` (tools/call)  
*Sub-IDs:* `AUTH-001.a`, `AUTH-001.b`  

**Premise.** An unauthenticated caller sits outside the trust boundary; the intermediary must not reveal tool inventory or accept calls before identity is established.

### AUTH-002 — Client A's token presented as B

*Severity:* CRITICAL  
*Surfaces:* `b` (tools/call)  
*Sub-IDs:* `AUTH-002.b`  

**Premise.** A bearer token authenticates exactly one principal; presenting principal A's token must never grant principal B's authority.

### AUTH-003 — Expired token

*Severity:* HIGH  
*Surfaces:* `b` (tools/call)  
*Sub-IDs:* `AUTH-003.b`  

**Premise.** Token validity is time-bounded; an expired credential carries no authority regardless of prior validity.

### AUTH-004 — Wrong audience (RFC 8707)

*Severity:* HIGH  
*Surfaces:* `b` (tools/call)  
*Sub-IDs:* `AUTH-004.b`  

**Premise.** A token minted for a different resource audience is not addressed to this intermediary and must be rejected even if otherwise valid.

### AUTHZ-001 — No permission for the call

*Severity:* HIGH  
*Surfaces:* `b` (tools/call), `c` (prompts/get), `d` (resources/read), `e` (batch / aggregating path)  
*Sub-IDs:* `AUTHZ-001.b`, `AUTHZ-001.c`, `AUTHZ-001.d`, `AUTHZ-001.e`  

**Premise.** Authorization is required on every value-bearing surface; authenticating a caller does not by itself authorize a specific tool, prompt, or resource.

### AUTHZ-002 — Tool hidden from list, called directly

*Severity:* HIGH  
*Surfaces:* `a` (tools/list), `b` (tools/call)  
*Sub-IDs:* `AUTHZ-002.a`, `AUTHZ-002.b`  

**Premise.** Hiding a tool from tools/list is a discovery-layer decision; the enforcement decision on tools/call must not depend on whether the caller could see the tool.

> Sequence a->b: hide on list, then invoke directly.

### AUTHZ-003 — Group/alias policy bypassed by different keying

*Severity:* HIGH  
*Surfaces:* `a` (tools/list), `b` (tools/call), `c` (prompts/get), `d` (resources/read)  
*Sub-IDs:* `AUTHZ-003.a`, `AUTHZ-003.b`, `AUTHZ-003.c`, `AUTHZ-003.d`  

**Premise.** A policy expressed over one identifier for a resource must hold under every alias or key the same resource can be addressed by.

### AUTHZ-004 — Batch path bypasses per-call gate

*Severity:* HIGH  
*Surfaces:* `e` (batch / aggregating path)  
*Sub-IDs:* `AUTHZ-004.e`  

**Premise.** An aggregating or batch surface is not a trust-exempt fast path; every constituent call must pass the same gate as a singleton.

### TENANT-001 — Tenant override in tool arguments

*Severity:* CRITICAL  
*Surfaces:* `b` (tools/call)  
*Sub-IDs:* `TENANT-001.b`  

**Premise.** The caller's tenant is bound by the authenticated session, not by data the caller supplies; tool arguments cannot re-scope authority.

### TENANT-002 — Tenant override in header / path / _meta

*Severity:* CRITICAL  
*Surfaces:* `b` (tools/call)  
*Sub-IDs:* `TENANT-002.b`  

**Premise.** Tenant identity derives from the authenticated principal; no request-controlled header, path segment, or _meta field may override it.

### SSRF-001 — Loopback + RFC1918

*Severity:* HIGH  
*Surfaces:* `b` (tools/call)  
*Sub-IDs:* `SSRF-001.b`  

**Premise.** The intermediary's network position is not delegable to a malicious server; requests it originates must honor an egress policy, not the server's chosen destination.

### SSRF-002 — IMDS 169.254.169.254

*Severity:* CRITICAL  
*Surfaces:* `b` (tools/call)  
*Sub-IDs:* `SSRF-002.b`  

**Premise.** Cloud instance metadata is reachable only from the host's network position; the intermediary must never proxy a call there on a server's behalf.

### SSRF-003 — IPv6 and IPv4-mapped (::ffff:)

*Severity:* HIGH  
*Surfaces:* `b` (tools/call)  
*Sub-IDs:* `SSRF-003.b`  

**Premise.** An egress allow/deny decision must be made on the resolved destination, not its textual form; alternate address encodings address the same host.

### SSRF-004 — DNS rebinding: TOCTOU register->connect

*Severity:* CRITICAL  
*Surfaces:* `b` (tools/call)  
*Sub-IDs:* `SSRF-004.b`  

**Premise.** The destination checked at policy time must be the destination connected to; a name that re-resolves between check and connect is the same request, not a new one.

### SSRF-005 — Redirect chain past the allowlist

*Severity:* HIGH  
*Surfaces:* `b` (tools/call)  
*Sub-IDs:* `SSRF-005.b`  

**Premise.** An egress allowlist governs the final destination reached, not only the first hop; following a redirect does not exit the policy.

### EGRESS-001 — Suffix confusion (api.example.com.evil.com)

*Severity:* HIGH  
*Surfaces:* `b` (tools/call)  
*Sub-IDs:* `EGRESS-001.b`  

**Premise.** Host allowlisting matches whole DNS labels, not string suffixes; api.example.com.evil.com is not within api.example.com.

### SCHEMA-001 — Silent schema expansion (new argument)

*Severity:* MEDIUM  
*Surfaces:* `a` (tools/list), `b` (tools/call)  
*Sub-IDs:* `SCHEMA-001.a`, `SCHEMA-001.b`  

**Premise.** A tool's input contract is what the intermediary vouched for; a server adding arguments after admission changes that contract and must be surfaced, not silently accepted.

### SCHEMA-002 — Tool description rug pull (tool poisoning)

*Severity:* MEDIUM  
*Surfaces:* `a` (tools/list), `b` (tools/call)  
*Sub-IDs:* `SCHEMA-002.a`, `SCHEMA-002.b`  

**Premise.** The tool description an agent reasons over is part of the trust surface; a server mutating it after admission is a change the intermediary must detect.

### SCHEMA-003 — Tool shadowing / cross-upstream name collision

*Severity:* HIGH  
*Surfaces:* `a` (tools/list), `b` (tools/call)  
*Sub-IDs:* `SCHEMA-003.a`, `SCHEMA-003.b`  

**Premise.** A tool name resolves to exactly one upstream; a second upstream claiming the same name must not silently shadow or override the first.

### SESSION-001 — State leak across sessions after reconnect

*Severity:* HIGH  
*Surfaces:* `f` (reconnect / resumption path)  
*Sub-IDs:* `SESSION-001.f`  

**Premise.** Session state is bound to its session; reconnection or resumption must not expose one session's state, identity, or authority to another.

### SECRET-001 — Env exfiltration via arguments / response

*Severity:* CRITICAL  
*Surfaces:* `b` (tools/call)  
*Sub-IDs:* `SECRET-001.b`  

**Premise.** The intermediary's own secrets (environment, tokens) are outside every caller's and server's trust boundary; no argument or response path may induce their disclosure.

### AUDIT-001 — Action executed with no audit event

*Severity:* MEDIUM  
*Surfaces:* `b` (tools/call), `e` (batch / aggregating path)  
*Sub-IDs:* `AUDIT-001.b`, `AUDIT-001.e`  

**Premise.** A security-relevant action and its audit record are one atomic fact; an action that executes without a corresponding event is unaccountable.

> AUDIT-* test: the SUT's log IS the subject of study, so the 'verdict never from the SUT's logs' rule (SPEC §3.1) is relaxed for this family only. The action is still driven and observed out-of-band; the audit record is then checked against it.

### AUDIT-002 — Secrets / raw arguments in audit or trace

*Severity:* MEDIUM  
*Surfaces:* `b` (tools/call)  
*Sub-IDs:* `AUDIT-002.b`  

**Premise.** The audit trail is itself a disclosure surface; recording secrets or raw sensitive arguments turns an accountability mechanism into a leak.

> AUDIT-* test: see AUDIT-001 note on the §3.1 relaxation.

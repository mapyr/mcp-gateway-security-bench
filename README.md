# MCP Gateway Security Bench (MCPSB)

**Status:** v0.1 draft · **License:** Apache-2.0 (code), CC BY 4.0 (`SPEC.md`)

A reproducible set of attacks that every **MCP intermediary** should pass — not a
ranking, not a scanner, not a score. An *intermediary* is any component that sits
between an MCP client and an MCP server and makes a decision about the call.

> We built an open, reproducible security benchmark for MCP intermediaries. It
> ships with a deliberately vulnerable and a deliberately secure reference
> implementation, so you can check the tests before you check your gateway.

## What makes the result trustworthy

Three design decisions, spelled out in [`SPEC.md`](SPEC.md):

1. **The verdict never comes from the system under test.** The bench owns an
   independent observation plane — an HTTP sink, a DNS server with a rebinding
   zone, a fake IMDS, a redirector — and reads verdicts from what *it* recorded.
   (Sole exception: the `AUDIT-*` family, where the log is the subject of study.)
2. **Every attack runs on every surface it declares** — `tools/list`,
   `tools/call`, `prompts/get`, `resources/read`, batch, reconnect. A missing
   surface is `UNSUPPORTED`, never `PASS`.
3. **Every test declares its premise** — the one trust-boundary assumption it
   makes. A maintainer can place a boundary out of scope with a public document,
   yielding `DECLARED-OUT-OF-SCOPE`, not `FAIL`.

There is **no aggregate score.** The report is per-severity counts with an
explicit N/A column.

## Repository layout

| Path | What |
| --- | --- |
| [`SPEC.md`](SPEC.md) | The invariants, IDs, severities, and premises. Generated from `mcpsb/registry.py`. |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | Who the attacker is and what is out of scope. |
| [`GOVERNANCE.md`](GOVERNANCE.md) | Neutrality, conflict-of-interest rules, spec-change process. |
| [`SECURITY.md`](SECURITY.md) / [`DISCLOSURE.md`](DISCLOSURE.md) | Responsible-disclosure policy for findings. |
| [`CLAUDE.md`](CLAUDE.md) / [`AGENTS.md`](AGENTS.md) | Non-negotiable invariants for agents working in the repo. |
| `mcpsb/` | The runner and the test registry. |
| `attacks/` | The attack tests. **Zero knowledge of any target.** |
| `controls/` | A deliberately `vulnerable/` and deliberately `secure/` reference intermediary — the differential gate. |
| `targets/` | One adapter per intermediary under test. |
| `results/` | Published runs. |

## Running

```sh
mcpsb run --target noop                 # smoke test: every test is INCONCLUSIVE
mcpsb run --target <name> --out results/ --format both
```

A target is a directory under `targets/<name>/` with an `adapter.py` exposing an
`Adapter` class. The report is per-severity counts plus a per-sub-ID detail
table — no aggregate score. `noop` is a built-in placeholder that provisions no
intermediary, so it exercises the whole pipeline and reports `INCONCLUSIVE`
everywhere.

## The registry and the spec

`SPEC.md`'s tables and premises are generated. After editing
`mcpsb/registry.py`:

```sh
python -m mcpsb.registry --write   # regenerate SPEC.md
python -m mcpsb.registry --check   # CI gate: fails on drift
```

## Targets and capability profiles

Three real intermediaries have adapters. Each declares — from its documented
model or (for Hangar) its source, held to the same "enforcement must be in code"
standard — which policies it can express. What it cannot express is
`UNSUPPORTED`, never `FAIL` (SPEC §4). The striking result is that the three
protect **different** things:

| Target | Applicable tests | `UNSUPPORTED` | Distinctive |
| --- | --- | --- | --- |
| ToolHive | 20 / 35 | 15 | OIDC + Cedar per-caller authz; no audit/secret/collision control |
| Docker MCP Gateway | 15 / 35 | 20 | shared bearer token, tool-name collision rejection, call logging, secret scanning; no per-principal identity or per-caller policy |
| MCP Hangar | 29 / 35 | 6 | OIDC + tenancy + digest pinning; egress/audit are declared (they run rather than reporting `UNSUPPORTED`), and their verdicts await a live run |

**Coverage is not a score, and there is no aggregate score by design.** "More
applicable tests" does not mean "more secure": several of the families a target
*runs* are expected to **fail** it (Hangar's egress and audit families among
them). A live PASS/FAIL requires standing the target up with its harness; until
then those runs report `INCONCLUSIVE`, honestly. The value is the comparison
itself — the same test asked of every intermediary.

## Live results

Every row here is backed by a run in this repository; no PASS/FAIL is claimed for
a target the bench did not actually exercise. Verdicts are point-in-time,
version-specific, and best-effort — a targeted benchmark, not an audit. Target
versions are sourced from the artifact under test, never asserted from memory.

**Reference controls (fully reproducible).** The deliberately-secure and
-vulnerable intermediaries run through the full bench — 35 sub-IDs each, with the
observation plane. Secure is all-PASS, vulnerable is all-FAIL, and every PASS has
a **verified positive control** (a legitimate request accepted before a blocked
one is scored). This is the executable definition of the differential gate; the
generated matrix is [`results/reference/combined-matrix.md`](results/reference/combined-matrix.md),
and its verdicts are confirmed by the out-of-band observation plane.

**ToolHive** (`thv` v0.46.0, OrbStack) — **AUTH-001 enforced live**: with OIDC
configured, an unauthenticated `tools/list`/`tools/call` is blocked (HTTP 401),
whereas with no OIDC ToolHive serves it and warns it accepts every request
unauthenticated. Clean differential. AUTH-003/004 (token expiry / audience) are
**`INCONCLUSIVE`**: their positive control requires a valid token to be accepted,
and ToolHive v0.46's detached OIDC proxy will not trust the bench's issuer without
a host-trust change the bench refuses to make — see
[`targets/toolhive/NOTES.md`](targets/toolhive/NOTES.md).

**Docker MCP Gateway** and **MCP Hangar** — **not yet reproduced here**, so every
sub-ID is `INCONCLUSIVE` (invariant #8): the `docker mcp` plugin is absent in this
environment, and Hangar's live provisioning is not yet implemented. Their adapters
and sourced capability maps are complete and unit-tested; the verdicts await a
live bring-up.

**No third-party finding is published here.** Any FAIL against a target this
project's author does not maintain goes to that maintainer privately first, and is
withheld until the disclosure window closes or the maintainer consents
(`DISCLOSURE.md`). Hangar is the author's **own** target (GOVERNANCE §1): it runs
through the same pipeline as everyone else and under the same disclosure clock —
no PASS is claimed for it here that a run has not produced.

**No aggregate score, by design.** Where a positive control could not be
established, the result is `INCONCLUSIVE`, never a guessed verdict (invariant #8),
and the reason is written down in the per-target record.

## Status (v0.1)

Complete: the spec/governance foundation, the runner, the observation plane, the
deliberately-vulnerable/secure controls with the differential gate, the full
23-ID attack corpus / 35 sub-IDs (validated FAIL-on-vulnerable / PASS-on-secure),
the malicious MCP fixtures, adapters for ToolHive, Docker MCP Gateway, and Hangar
with sourced capability maps, and the **live harness proven against ToolHive**
(AUTH-001; above). Remaining: live provisioning for Docker MCP Gateway and Hangar,
deeper live coverage, and the maintainer runs below.

## An invitation

We built an open, reproducible security benchmark for MCP intermediaries. It
ships with a deliberately vulnerable and a deliberately secure reference
implementation, so you can check the tests before you check your gateway. We
invite the maintainers of **ToolHive, Docker MCP Gateway, agentgateway,
ContextForge, and MCP Hangar** to run it and publish their results.

Not "Hangar is better" — "let's test everyone with the same test." Per
`GOVERNANCE.md` §1.4, no MCPSB result appears in Hangar's own marketing until at
least one external maintainer has published a run. Third-party findings follow
`DISCLOSURE.md` (private first, 90-day window). Reference results for the controls
themselves are in [`results/reference/`](results/reference/).

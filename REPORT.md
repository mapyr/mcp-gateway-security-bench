# MCPSB — Study Report

**Version:** v0.1 · **Generated:** 2026-09-04 · **Scope:** only results backed by
a run in this repository. No PASS/FAIL is claimed for a target the bench did not
actually exercise. Point-in-time, version-specific, best-effort — a targeted
benchmark, **not** a comprehensive audit, and **no aggregate score** by design.

> Every summary sentence below is a *function of run data*, checked by a CI gate
> (`ci/check_claims.py`): the observation-plane claim appears only when a live
> verdict actually came from the sink/DNS/IMDS, a target's version is sourced from
> the artifact under test, and a PASS is only reported where a positive control
> was verified. The report cannot be edited to say more than the run supports.

---

## 1. What the bench measures, and why the result is trustworthy

Four properties, each enforced in code rather than asserted in prose:

1. **The verdict never comes from the system under test.** An independent
   observation plane — an HTTP sink, a DNS server with a rebinding zone, a fake
   IMDS, a redirector — is the source of record. Every conclusive verdict carries
   a mandatory `evidence_source ∈ {client_response, sink, dns, imds, target_audit}`,
   and `target_audit` is admissible only for the `AUDIT-*` family; anywhere else it
   is an `ERROR`, never a pass (WS-D1).
2. **A block only counts if the target also accepts legitimate traffic.** Each
   family has a *positive control* — a legitimate request that must be accepted.
   If a target does not pass a family's positive control, every PASS in that
   family degrades automatically to `INCONCLUSIVE` (`positive_control_missing`),
   so a target that blocks *everything* is never scored as if it blocked
   *selectively* (WS-D2).
3. **Every attack is differential.** A test that is not FAIL on a deliberately
   vulnerable reference and PASS on a deliberately secure one does not exist. The
   secure control is the executable definition of "correct" (GOVERNANCE §3).
4. **Capability, not guesswork.** What a target cannot express is `UNSUPPORTED`
   (an explicit N/A), never `FAIL`. The verdict vocabulary keeps `INCONCLUSIVE`
   and `UNSUPPORTED` strictly separate from PASS/FAIL (SPEC §4).

Conflict of interest is governed openly: one target (MCP Hangar) is the author's
own. It is implemented last, runs through the same pipeline, and its results are
published on the same terms and the same disclosure clock as everyone else's
(GOVERNANCE §1, `DISCLOSURE.md`).

---

## 2. Coverage at a glance

| Target | Version (sourced from artifact) | Status in this run |
| --- | --- | --- |
| `secure` (reference) | mcpsb-reference/0.1.0.dev0 | **Fully exercised** — 35/35 sub-IDs PASS |
| `vulnerable` (reference) | mcpsb-reference/0.1.0.dev0 | **Fully exercised** — 35/35 sub-IDs FAIL |
| ToolHive (`thv`) | toolhive/v0.46.0 | **Partial** — AUTH-001 live; AUTH-003/004 `INCONCLUSIVE` |
| Docker MCP Gateway | v2.0.1 (tested band 2.0.x; plugin absent here) | **Prior PASSes superseded → `INCONCLUSIVE`**; not reproducible here |
| MCP Hangar | _(wheel 1.4.0 present; live provisioning not implemented)_ | **Not run** — all `INCONCLUSIVE` |

The reference controls are the backbone: they prove the 35 sub-IDs are
well-formed (FAIL-on-vulnerable / PASS-on-secure) and that the observation plane
confirms the verdicts. The three real intermediaries have complete, unit-tested
adapters and sourced capability maps; their live verdicts await a bring-up that
this environment could not provide (see §5).

---

## 3. Reference controls — the fully-backed result

The following is **generated** from the run data by `mcpsb matrix`; the
authoritative, gate-checked copy is
[`results/reference/combined-matrix.md`](results/reference/combined-matrix.md).
Regenerate with:

```sh
python -m mcpsb.cli run --target secure     --out results/reference --format both
python -m mcpsb.cli run --target vulnerable  --out results/reference --format both
python -m mcpsb.cli matrix results/reference/secure.json results/reference/vulnerable.json \
  --out results/reference/combined-matrix.md
```

The block below is **generated**, not written by hand — `ci/check_claims.py`
re-derives it from the reference report JSONs and fails if this file's copy does
not match byte-for-byte, so the summary cannot be edited to say more than the run
supports. Refresh it with `python -m mcpsb.cli report --out REPORT.md`.

<!-- BEGIN GENERATED: reference-summary -->
## Summary

- **2 of 2 target(s) were exercised live** (`secure`, `vulnerable`): each produced at least one non-INCONCLUSIVE verdict.
- **Verdicts were confirmed by the out-of-band observation plane** for `secure`, `vulnerable` (evidence from the sink/DNS/IMDS, not the target's own response).
- **Every target with a PASS has a verified positive control** (`secure`): a legitimate request was accepted before a blocked one was scored.

Target versions (sourced from the artifact under test):
- `secure` — mcpsb-reference/0.1.0.dev0
- `vulnerable` — mcpsb-reference/0.1.0.dev0
<!-- END GENERATED: reference-summary -->

The full 35-sub-ID matrix (every cell, positive-control rows, and per-cell reason
footnotes) is the generated, gate-checked
[`results/reference/combined-matrix.md`](results/reference/combined-matrix.md).
In it, `secure` is PASS on every sub-ID and `vulnerable` is FAIL on every sub-ID;
the SSRF / IMDS / rebinding / EGRESS rows are the ones whose evidence comes from
the **observation plane** (`sink`/`dns`), not the target's reply. On `vulnerable`
the AUDIT positive control fails (its log records nothing for a legitimate
action), which is why that control cannot be scored as auditing selectively.

---

## 4. Real intermediaries — live findings

### ToolHive (`thv` v0.46.0, OrbStack) — one live verdict, honest INCONCLUSIVE for the rest

- **AUTH-001 enforced live.** With OIDC configured, an unauthenticated
  `tools/list` / `tools/call` is blocked (HTTP 401); with no OIDC configured,
  ToolHive serves the request and warns it "will accept every request
  unauthenticated." A clean differential, independent of token validation.
- **AUTH-003 / AUTH-004 (token expiry / audience) — `INCONCLUSIVE`.** Their
  positive control requires a *valid* token to be accepted first. ToolHive
  validates OIDC in a **detached host-side proxy** that fetches discovery/JWKS
  from the host; the host does not route to the bench bridge, so the issuer must
  be host-reachable over HTTPS (the bench issuer now supports TLS). Even then,
  ToolHive v0.46 rejects the bench's self-signed issuer cert
  (`x509: unknown authority`) and **does not honor `--thv-ca-bundle` on the
  discovery path**, nor `SSL_CERT_FILE`. The only remaining route is installing
  the cert into the host's system trust store — which the bench refuses to do
  (an out-of-band change to the operator's machine, and a host-exposure the bench
  exists to avoid). Full detail: [`targets/toolhive/NOTES.md`](targets/toolhive/NOTES.md).

This is a precise upgrade over the earlier "issuer unreachable" note: the issuer
*is* reachable; ToolHive will not trust its certificate on the discovery path.

### Docker MCP Gateway (v2.0.1) — prior PASSes superseded, not reproducible here

An **earlier** run reported PASS on AUTH-001, AUTHZ-002, and AUDIT-001/002 against
`docker/mcp-gateway` v2.0.1. Those verdicts are **superseded to `INCONCLUSIVE`**,
explicitly — they are not dropped and not silently retained. They predate the
evidence-source (D1) and per-family positive-control (D2) requirements: under the
current discipline a PASS must carry an `evidence_source` and a *verified positive
control* for its family, which that run did not record in structured form. This
environment cannot reproduce them (the `docker mcp` plugin is absent). A
publishable Docker verdict now requires a fresh run on an in-range build (2.0.x —
enforced by the tested-version gate) that establishes each family's positive
control. The full prior record is retained, marked superseded, at
[`results/live/docker_mcp_gateway.md`](results/live/docker_mcp_gateway.md).

The earlier, still-valid *observation* — Docker refuses to **start** when two
config-declared servers collide on a tool name — is a **start-time** control on a
different surface than `SCHEMA-003` (which tests **runtime-discovered** shadowing);
it does not establish a `SCHEMA-003.b` PASS. The SECRET-001 result remains
withheld under `DISCLOSURE.md`. Detail:
[`targets/docker_mcp_gateway/NOTES.md`](targets/docker_mcp_gateway/NOTES.md).

### MCP Hangar — not run here

Live provisioning is not yet implemented, so every sub-ID is `INCONCLUSIVE`. The
adapter's `version()` reads the installed `mcp-hangar` wheel; in this environment
that wheel is **1.4.0** (an old build), which is precisely why the version is
sourced from the artifact and never pinned from memory.

---

## 5. Key findings (methodological)

1. **Sourcing the version from the artifact caught a real discrepancy.** The
   adapter reported the *installed* `mcp-hangar` **1.4.0**, not the version
   assumed from memory. A remembered version is not evidence; the mechanism made
   the gap visible instead of hiding it behind a literal.
2. **The claim gate makes over-statement structurally impossible.** The
   observation-plane headline, the "N targets run live" count, the
   positive-control claim, and the version list are all derived from run data and
   re-checked in CI; a stale or hand-edited report fails the gate.
3. **The positive-control discipline changes what a PASS means.** On the
   vulnerable control the AUDIT family fails its positive control, so any AUDIT
   "block" there would degrade to `INCONCLUSIVE` rather than masquerade as a pass.
4. **The observation plane is demonstrated on the controls, and not over-claimed
   for third parties.** No third-party target wired a sink into its egress path in
   this environment, so the report makes **no observation-plane differentiator
   claim for third parties** — the gate enforces this automatically.

---

## 6. Limitations and honest gaps

- **Third-party live coverage is not established here.** ToolHive is partial;
  Docker and Hangar did not run. This is reported as `INCONCLUSIVE`, never a
  guessed verdict (invariant #8).
- **The observation plane has only ever observed a system the author wrote.**
  Every verdict confirmed out-of-band in this study was confirmed against the
  reference `secure`/`vulnerable` controls — which are part of this project. The
  observation tooling (sink, DNS, IMDS, redirector) has **not yet** recorded a
  verdict against an intermediary the author did not write, so the "verdict comes
  from an independent plane" property, while real, is so far **self-referential**.
  Making it non-self-referential — a third-party target with the sink in its
  egress path — is the first objective after WS-B, not something this report
  claims to have done.
- **Reproducibility depends on the environment.** The reference-control result is
  fully reproducible with the commands in §3. The ToolHive AUTH-001 finding was
  reproduced this session with `thv` v0.46.0 on OrbStack.

### What full live coverage would require

- **ToolHive AUTH-003/004:** a `thv` release that honors `--thv-ca-bundle` on the
  OIDC discovery path (or an operator-provided, system-trusted issuer cert). The
  bench issuer already serves HTTPS and mints the principals' tokens.
- **Docker MCP Gateway:** the `docker mcp` plugin installed, plus the sink placed
  on the gateway's egress path (reachable-when-allowed, then blocked-when-forbidden).
- **MCP Hangar:** live provisioning (Hangar running with auth + a fixture MCP
  server behind it) and the current wheel installed so `version()` reports it.

---

## 7. Disclosure and conflict-of-interest status

No third-party finding is published in this report. Any FAIL against a target the
author does not maintain goes to that maintainer privately first and is withheld
until the disclosure window closes or the maintainer consents. MCP Hangar is the
author's own target and runs under the **same disclosure clock as everyone else**
(90 days or until a fix ships, whichever comes first — no longer grace period for
the author's own product). See [`DISCLOSURE.md`](DISCLOSURE.md) and
[`GOVERNANCE.md`](GOVERNANCE.md).

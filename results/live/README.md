# results/live

Point-in-time **prose records** of the bench run against real intermediaries.
The authoritative, gate-checked current report is [`../../REPORT.md`](../../REPORT.md)
and the generated reference matrix in [`../reference/`](../reference/); these files
are the narrative context behind it. Some predate the current gated discipline
(evidence-source, per-family positive control, tested-version gate) and are marked
accordingly — a verdict is only stood behind where a positive control held.

| File | Target | Current disposition |
| --- | --- | --- |
| [`docker_mcp_gateway.md`](docker_mcp_gateway.md) | Docker MCP Gateway v2.0.1 | **SUPERSEDED** — its earlier PASSes predate D1/D2 (no structured positive control/evidence) and are not reproducible here; superseded to `INCONCLUSIVE` pending a fresh gated run. SCHEMA-003 = start-time observation, not a verdict. SECRET-001 withheld pending disclosure. |
| [`hangar.md`](hangar.md) | MCP Hangar (author's own) | Auth + tenancy PASS **with positive controls shown**, but on a v2 HEAD checkout and **before** the current gated harness / version gate; treat as a prior record pending a gated re-run. egress/audit not vouched for. |
| [`toolhive.md`](toolhive.md) | ToolHive v0.46.0 | AUTH-001 PASS (reproduced this session); AUTH-003/004 `INCONCLUSIVE` (OIDC issuer-trust barrier); harness portability proven. |

**Disclosure.** Third-party findings are NOT published here: any FAIL against a
target the author does not maintain goes to that maintainer privately first and
is withheld until the window closes / consent is given
([`../../DISCLOSURE.md`](../../DISCLOSURE.md) §7). Embargoed findings are kept out
of the tree (see `.gitignore`). Hangar is the author's own target; its own
findings about **unfixed** behaviour are likewise withheld until fixed, to avoid
publishing an attack roadmap — GOVERNANCE §1.4 (no self-marketing) still applies.

*Point-in-time, version-specific, best-effort. A targeted benchmark run, not a
comprehensive security audit; no warranty.*

Reproduction: each target's `README.md` under `targets/<name>/` carries the exact
commands. The reusable live harness is the OIDC issuer (`fixtures/oidc/`), the
stdio fixture (`fixtures/mcp/stdio_server.py`), and the Streamable-HTTP client
(`mcpsb/streamable.py`).

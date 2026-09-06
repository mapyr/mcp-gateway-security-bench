# Live run — Docker MCP Gateway

> **SUPERSEDED (2026-09-04).** This run predates the evidence-source (D1),
> positive-control (D2), and claim (D3) gates and the tested-version gate. Under
> the current discipline a PASS must carry an `evidence_source` **and** a
> *verified positive control* for its family; this run recorded neither in the
> structured form the gates require. Its PASSes below (AUTH-001, AUTHZ-002,
> AUDIT-001/002) are therefore **superseded to `INCONCLUSIVE`** — they are given
> an explicit disposition, not deleted. They are **not** reproducible in the
> current environment (the `docker mcp` plugin is absent), and a publishable
> Docker verdict now requires a fresh run on an in-range build (2.0.x) that
> establishes each family's positive control. The config-time collision refusal
> remains a valid *observation*, not a `SCHEMA-003.b` verdict (see
> `targets/docker_mcp_gateway/NOTES.md`). SECRET-001 remains withheld under
> `DISCLOSURE.md`. The original record is retained verbatim below for provenance.

Target: `docker/mcp-gateway` v2.0.1 (standalone image, OrbStack), Streamable HTTP `/mcp`, `MCP_GATEWAY_AUTH_TOKEN` set, proxying a stdio fixture MCP server (`fixtures/mcp/stdio_server.py`) via a custom catalog, with `admin_ping` excluded from the `--tools` allowlist. Real run through the bench adapter, session-aware Streamable-HTTP client, and attack corpus.

## Verdicts (real)

| Sub-ID | Verdict | Detail |
| --- | --- | --- |
| `AUTH-001.a` | PASS | a: blocked (HTTP 401) |
| `AUTH-001.b` | PASS | b: blocked (HTTP 401) |
| `AUTHZ-002.a` | PASS | hidden tool not disclosed |
| `AUTHZ-002.b` | PASS | b: blocked (unknown tool "admin_ping") |

## SCHEMA-003 (name-collision control) — observed directly

Configuring a second server that also exposes `echo` made the gateway **refuse to start** (exit 1) with: `tool name collision: server "mcpsbfix" and server "mcpsbshadow" both expose tool name "echo"`. Docker MCP Gateway rejects cross-upstream tool-name collisions **fail-closed at config load** — it does not silently shadow. This is the SCHEMA-003 premise upheld; it manifests before serving rather than as a probe of a running gateway, so it is recorded here as a direct observation rather than a sub-ID verdict.

## SSRF / egress — attempted, INCONCLUSIVE (not a finding)

The fixture gained a `fetch` tool and was made to request a bench sink. Two setups:

* sink at `host.docker.internal` — resolves to `0.250.250.254` under OrbStack, an
  OrbStack-special host address that is **not** a forbidden range, so reaching it
  is expected and tests nothing.
* sink as a bridge-peer container at `192.168.215.2` (private). The proxied server
  reached it **both with and without `--block-network`** (sink hit each time).

This is **not** reported as a FAIL. The sink and the proxied server sit on the
same Docker bridge, so this is container-to-container peer traffic, which
`--block-network` may legitimately allow — it is indistinguishable here from an
egress-control gap. A defensible SSRF-to-forbidden test needs the observation
plane at a genuinely forbidden address (link-local / `169.254.169.254`) **inside
the server container's network namespace**, which the gateway does not expose (it
runs servers with a fixed `--network bridge`). Recorded as **INCONCLUSIVE**
(invariant #8): the harness could not establish the precondition, so no verdict.

## SECRET-001 — withheld pending disclosure

The SECRET-001 probe produced a result that is being handled as a **third-party
finding under `DISCLOSURE.md` §7**: it is reported to the maintainer through their
private security channel first, and its details are **withheld from this published
record** until the disclosure window closes or the maintainer consents. This is
the project's own policy — the bench does not publish third-party findings before
disclosure (it is not a 0-day feed). The reproduction is retained privately.

## AUDIT — both PASS (real)

`--log-calls` (default on) writes to the gateway's stdout; that output is the
audit subject (SPEC §3.1 exception for the `AUDIT-*` family). Observed entry for a
call: `Calling tool echo with arguments: object with 1 field(s)` — the tool name
and argument **shape**, never the raw value.

| Sub-ID | Verdict | Detail |
| --- | --- | --- |
| `AUDIT-001.b` | PASS | the call produced an audit event (accountable) |
| `AUDIT-002.b` | PASS | the trail records argument shape only; the sensitive value never appears |

(`AUDIT-001.e` is the batch surface — `UNSUPPORTED` for this target.)

## Live coverage summary

| Family | Live result |
| --- | --- |
| AUTH-001 | PASS |
| AUTHZ-002 | PASS |
| SCHEMA-003 | collision → gateway refuses to start (observed) |
| SSRF / EGRESS | INCONCLUSIVE (harness limitation, honest — not a finding) |
| SECRET-001 | withheld pending disclosure (DISCLOSURE.md §7) |
| AUDIT-001/002 | PASS |

A representative live run against a real intermediary. Any finding is handled
privately with the maintainer first; the remaining families are `UNSUPPORTED` by
Docker's declared model (see the target README).

---

*Point-in-time, version-specific, best-effort. This is a targeted benchmark run,
not a comprehensive security audit, and carries no warranty. Capability claims
are sourced to public docs at the version noted and may change between releases.*

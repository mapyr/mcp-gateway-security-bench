# targets/toolhive — ToolHive adapter (WS-6)

[ToolHive](https://github.com/stacklok/toolhive) (Stacklok, CLI `thv`) is an MCP
server runtime and proxy. This adapter runs the bench against it as an
intermediary.

## Capability map (sourced)

The adapter's `capabilities()` is grounded in ToolHive's documented model. It
determines which tests are `UNSUPPORTED` — a target with no notion of a policy
does not *fail* it, it does not *offer* it (SPEC §4).

| Concept | ToolHive | Source |
| --- | --- | --- |
| MCP proxy (list/call/prompt/resource) | ✅ | [run-mcp-servers](https://docs.stacklok.com/toolhive/guides-cli/run-mcp-servers) |
| Authentication (OIDC bearer) | ✅ (off by default) | [auth](https://docs.stacklok.com/toolhive/guides-cli/auth) |
| Token audience (RFC 8707) | ✅ (`--oidc-audience`) | [auth](https://docs.stacklok.com/toolhive/guides-cli/auth) |
| Authorization (per-call, Cedar) | ✅ real deny | [authz-policy-reference](https://docs.stacklok.com/toolhive/reference/authz-policy-reference) |
| Egress allowlist / network isolation | ✅ default-on | [network-isolation](https://docs.stacklok.com/toolhive/guides-cli/network-isolation) |
| Multi-tenancy | ❌ no evidence | [faq](https://docs.stacklok.com/toolhive/faq) |
| Schema pinning / drift verification | ❌ admission-time name check only | [run-mcp-servers](https://docs.stacklok.com/toolhive/guides-cli/run-mcp-servers) |
| Session isolation across reconnect | ❌ no evidence | — |
| Audit log (CLI `thv run`) | ❌ vMCP-only | [vmcp/audit-logging](https://docs.stacklok.com/toolhive/guides-vmcp/audit-logging) |
| Secret isolation from the proxied server | ❌ secrets injected as env vars | [secrets-management](https://docs.stacklok.com/toolhive/guides-cli/secrets-management) |

Tool filtering (`--tools`) exists but the docs state it is **"not a security
feature,"** so the adapter does not rely on it for authorization.

## Expected verdict profile

The capability map yields (validated in `tests/test_toolhive_adapter.py`):

* **Runs (PASS/FAIL against a live target):** AUTH-001/002/003/004, AUTHZ-001
  (call/prompt/resource surfaces), AUTHZ-002, AUTHZ-003, SSRF-001..005, EGRESS-001.
* **`UNSUPPORTED`:** TENANT-001/002, SCHEMA-001/002/003, SESSION-001, SECRET-001,
  AUDIT-001/002, and the batch surfaces AUTHZ-001.e / AUTHZ-004.e.

These `UNSUPPORTED` calls are the honest report: ToolHive does not claim these
boundaries. A maintainer who considers one out of scope can supply a public
document and it becomes `DECLARED-OUT-OF-SCOPE` (SPEC §3.3).

## Running it live

The adapter provisions **honestly**: without the full secure harness it returns
an *unavailable* endpoint and every test is `INCONCLUSIVE` — it never brings
ToolHive up in a partial/insecure config and reports the resulting spurious
failures (which would be a config artifact, not a finding; invariant #8).

A faithful run needs:

1. `brew install stacklok/tap/thv` (or a release binary) + Docker/Podman.
2. An **OIDC issuer** ToolHive trusts, minting the principals' tokens. Export:
   `MCPSB_TOOLHIVE_OIDC_ISSUER`, `MCPSB_TOOLHIVE_OIDC_AUDIENCE`,
   `MCPSB_TOOLHIVE_TOKEN_A`, `MCPSB_TOOLHIVE_TOKEN_B` (and `_EXPIRED`,
   `_WRONGAUD`).
3. A **Cedar authz policy** and an **egress permission profile** — generated from
   the bench's policy by `targets/toolhive/config.py`
   (`generate_cedar_authz`, `generate_permission_profile`).
4. The **egress-capable fixtures** (`fixtures/mcp/`) proxied by ToolHive, plus an
   egress-triggering tool for the SSRF/EGRESS family.
5. ToolHive launched roughly as:

   ```sh
   thv run --transport streamable-http --proxy-mode streamable-http \
     --oidc-issuer "$MCPSB_TOOLHIVE_OIDC_ISSUER" \
     --oidc-audience "$MCPSB_TOOLHIVE_OIDC_AUDIENCE" \
     --authz-config authz.json --isolate-network \
     --permission-profile perms.json <fixture-name> <fixture-url>
   ```

The adapter's transport client (`client.py`) already speaks ToolHive's
Streamable HTTP `/mcp` endpoint, so the attack corpus is unchanged.

## Status

Adapter, capability map, config translation, and transport client are complete
and unit-tested. **The harness has been proven live** against `thv` v0.46.0
(OrbStack): ToolHive proxied the bench's stdio fixture and the session-aware
Streamable-HTTP client drove it end-to-end (`tools/list`, `tools/call echo`) — the
same pattern that runs against Docker MCP Gateway, now against a second,
architecturally different real intermediary. ToolHive's egress isolation (a
dedicated egress proxy + DNS container) was observed active.

With the bench's OIDC issuer harness (`fixtures/oidc/`), **AUTH-001 is PASS live**
— OIDC-configured ToolHive blocks unauthenticated access (401) where the
un-configured run served it openly. AUTH-003/004 stay `INCONCLUSIVE`: the
positive control (a valid token accepted) could not be established because
ToolHive's proxy could not reach the local issuer's JWKS in this environment, so
expired/wrong-audience rejection cannot be shown to be specific. SSRF and the
rest remain `INCONCLUSIVE`/`UNSUPPORTED`. Full record:
[`results/live/toolhive.md`](../../results/live/toolhive.md).

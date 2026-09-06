# targets/docker_mcp_gateway — Docker MCP Gateway adapter (WS-7)

[Docker MCP Gateway](https://github.com/docker/mcp-gateway) (`docker mcp gateway`,
part of Docker's MCP Toolkit + Catalog) aggregates MCP servers behind one
endpoint. This adapter runs the bench against it as an intermediary.

The directory uses an underscore (`docker_mcp_gateway`) so it imports as a Python
module; the target name is `docker_mcp_gateway`.

> **Version-sensitive.** The gateway's security surface changed materially across
> releases (bearer auth landed ~v0.43.1; DNS-rebinding fix in 0.28.0; tool-name
> collision rejection in v0.43.1). This adapter is pinned to **≥ v0.43.1**. Pin
> your run to a specific version and record it with the results.

## Capability map (sourced)

| Concept | Docker MCP Gateway | Source |
| --- | --- | --- |
| MCP proxy (list/call/prompt/resource) | ✅ (`--transport streaming`) | [mcp-gateway.md](https://github.com/docker/mcp-gateway/blob/main/docs/mcp-gateway.md) |
| Authentication (incoming) | ✅ shared Bearer token, HTTP only, v0.43.1+ | [security.md](https://github.com/docker/mcp-gateway/blob/main/docs/security.md) |
| Per-principal identity / expiry / audience | ❌ single shared token | [security.md](https://github.com/docker/mcp-gateway/blob/main/docs/security.md) |
| Per-caller authorization (policy language) | ❌ only custom interceptors | [security.md](https://github.com/docker/mcp-gateway/blob/main/docs/security.md) |
| Tool allowlist | ✅ (`--tools`) | [mcp-gateway.md](https://github.com/docker/mcp-gateway/blob/main/docs/mcp-gateway.md) |
| Egress / SSRF hardening | ✅ `--block-network`, `allowHosts`, blocks loopback/private/link-local/metadata | [security.md](https://github.com/docker/mcp-gateway/blob/main/docs/security.md) |
| Tool-name collision rejection | ✅ v0.43.1+ (rejects shadowing) | [releases](https://github.com/docker/mcp-gateway/releases) |
| Schema-drift pinning | ❌ no evidence | — |
| Multi-tenancy | ❌ no real tenant boundary | [security.md](https://github.com/docker/mcp-gateway/blob/main/docs/security.md) |
| Audit / call logging | ✅ `--log-calls` (name + arg-shape only) | [security.md](https://github.com/docker/mcp-gateway/blob/main/docs/security.md) |
| Secret scanning | ✅ `--block-secrets` (heuristic, in/out) | [security.md](https://github.com/docker/mcp-gateway/blob/main/docs/security.md) |
| Session isolation across reconnect | ❌ no evidence | — |

## Expected verdict profile

Validated in `tests/test_docker_mcp_gateway_adapter.py`. This profile is **very
different from ToolHive's** — which is exactly what the bench is for.

* **Runs (PASS/FAIL live):** AUTH-001, AUTHZ-002, SSRF-001..005, EGRESS-001,
  **SCHEMA-003** (collision rejection), SECRET-001, AUDIT-001.b, AUDIT-002.
* **`UNSUPPORTED`:** AUTH-002/003/004 and AUTHZ-001 (no per-principal identity),
  AUTHZ-003 (no per-caller policy language), TENANT-001/002, SCHEMA-001/002
  (no drift pinning), SESSION-001, and the batch surfaces (AUTHZ-001.e,
  AUTHZ-004.e, AUDIT-001.e).

Contrast: ToolHive *runs* the per-principal AUTH/AUTHZ family (OIDC + Cedar) but
is `UNSUPPORTED` on audit/secret/collision; Docker is the mirror image.

## Security advisories to be aware of

* **CVE-2025-64443** — DNS rebinding on `sse`/`streaming` (≤ 0.27.0, fixed
  0.28.0). [advisory](https://github.com/advisories/GHSA-46gc-mwh4-cc5r)
* **CVE-2026-55887** — argument injection via OCI image label (0.21.0–0.42.1,
  fixed 0.42.2).
* Tool-name shadowing hardening — v0.43.1 (relevant to SCHEMA-003).

## Running it live

The adapter supports **attach-to-running-gateway** mode: an operator starts the
gateway with its own secure config and points the adapter at it. This is a real,
honest provision — the gateway is brought up properly, not faked.

```sh
# Start the standalone gateway image (works with the Docker engine alone; the
# `docker mcp` Desktop plugin is not required):
docker run -d --name mcpsb-dmg -p 8765:8765 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e MCP_GATEWAY_AUTH_TOKEN=<token> \
  docker/mcp-gateway:latest \
  --transport streaming --port 8765 --host 0.0.0.0

# Point the adapter at it and run:
export MCPSB_DMG_AUTH_TOKEN=<token>
export MCPSB_DMG_ENDPOINT=http://127.0.0.1:8765
mcpsb run --target docker_mcp_gateway
```

Without `MCPSB_DMG_ENDPOINT` the adapter is unavailable and every test is
`INCONCLUSIVE` (invariant #8). The transport client (`mcpsb/streamable.py`, `/mcp`)
is session-aware (initialize → `Mcp-Session-Id` → calls) and shared with the other
targets, so the attack corpus is unchanged.

### The catalog-fixture harness (built)

Tool-dependent families need the gateway to proxy a fixture MCP server exposing
the scenario's tools. `fixtures/mcp/stdio_server.py` + `Dockerfile.stdio` build a
stdio MCP server image; a catalog entry (`registry: { mcpsbfix: { type: server,
image: mcpsb/fixture-stdio, tools: [...] } }`) mounted under
`~/.docker/mcp/catalogs/` and enabled with `--servers mcpsbfix --tools echo,...`
proxies it. Excluding `admin_ping` from `--tools` hides it (AUTHZ-002).

Still to wire: the observation plane reachable from the server-container network
(egress family), a provisioned secret + marker (SECRET), and an audit reader on
`--log-calls` output (AUDIT).

## Status

Adapter, capability map, config translation, session-aware transport client, and
the catalog-fixture harness are complete and tested. **A representative
multi-family live run has been done** against `docker/mcp-gateway` v2.0.1
(OrbStack):

* **AUTH-001 PASS** — unauthenticated `tools/list`/`tools/call` blocked (HTTP 401).
* **AUTHZ-002 PASS** — a tool excluded from the `--tools` allowlist is neither
  listed nor callable.
* **SCHEMA-003** — a colliding tool name makes the gateway **refuse to start**
  (fail-closed; no silent shadowing).
* **SECRET-001 FAIL** — an injected named secret leaks through a tool response
  with `--block-secrets` on (it redacts recognized patterns like `ghp_…` but not
  arbitrary named secrets). Fairly caveated: `--block-secrets` is documented as
  heuristic/best-effort, so this is likely `DECLARED-OUT-OF-SCOPE`.
* **AUDIT-001 / AUDIT-002 PASS** — calls are logged (accountable) and the trail
  records argument shape only, not raw values.
* **SSRF / EGRESS INCONCLUSIVE** — not a finding; the harness cannot place the
  observation plane at a forbidden address inside the server container's netns.

Full record: [`results/live/docker_mcp_gateway.md`](../../results/live/docker_mcp_gateway.md).

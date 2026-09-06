# Live run — ToolHive

Target: ToolHive `thv` v0.46.0 (Homebrew), container runtime OrbStack. ToolHive
runs an MCP server as a container and proxies it over Streamable HTTP at `/mcp`.

## The bench harness works against ToolHive (proven)

`thv run --transport stdio --name mcpsbfix mcpsb/fixture-stdio:latest` brought the
fixture up; ToolHive proxied it and the bench's session-aware Streamable-HTTP
client drove it end-to-end:

* `tools/list` → `['echo', 'whoami', 'admin_ping', 'render', 'fetch']`
* `tools/call echo` → returned the fixture's response through the ToolHive proxy.

This is the portability milestone: the **same** adapter pattern, transport client,
and stdio fixture that ran against Docker MCP Gateway also run against ToolHive —
a second, architecturally different real intermediary (OIDC + a dedicated egress
proxy, versus Docker's shared token + bridge network).

## ToolHive's egress isolation is active (observed)

On `thv run`, ToolHive stood up a **dedicated egress proxy and a DNS container**
(`mcpsbfix-egress`, `mcpsbfix-dns`) alongside the server. The fixture's `fetch`
tool could not reach a bench sink at any Docker-gateway address
(`host.docker.internal`, `172.17.0.1`, `gateway.docker.internal`) — with **or**
without `--allow-docker-gateway`.

## Auth — one real verdict via the OIDC issuer harness

The bench now ships an OIDC issuer harness (`fixtures/oidc/issuer.py`, `live`
extra): it serves discovery + JWKS and mints RS256 tokens (valid / expired /
wrong-audience). Running ToolHive with `--oidc-issuer <harness> --oidc-audience`:

* **AUTH-001 PASS** — with OIDC configured, an unauthenticated `tools/list`/
  `tools/call` is blocked (HTTP 401), whereas the earlier run *without* OIDC
  served it openly (ToolHive even warns it "will accept every request
  unauthenticated"). Clean differential; independent of token validation.

* **AUTH-003 / AUTH-004 INCONCLUSIVE** — the **positive control fails**: a *valid*
  token is also rejected (401), because ToolHive's proxy could not reach the
  local issuer's JWKS during validation in this environment (its network model
  routes/blocks the loopback discovery). With every token rejected, expired and
  wrong-audience *cannot be shown to be rejected specifically* rather than as
  part of a blanket failure — so they are **not** claimed as PASS. The issuer
  harness itself is verified correct in `tests/test_oidc_issuer.py`; making the
  positive control pass needs the issuer on an address ToolHive's validator
  admits.

## Still INCONCLUSIVE / UNSUPPORTED

* **SSRF / egress** — isolation is active (egress proxy + DNS containers), but the
  sink was unreachable whether egress was allowed or not, so "blocked" ≠ a
  finding (same observability limit as Docker).
* **Tool filtering (`--tools`)** — validates names against registry image
  metadata a custom image lacks; did not establish.
* Secret / schema / session / audit are `UNSUPPORTED` by ToolHive's CLI-proxy
  model (see the target README).

Nothing was reported as PASS/FAIL that could not be defended (invariant #8).

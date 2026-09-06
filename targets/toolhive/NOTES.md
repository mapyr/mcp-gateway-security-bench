# targets/toolhive — live integration notes

Run-derived observations from driving ToolHive `thv` v0.46.0 (OrbStack) live.
These are notes about *how ToolHive is built*, not verdicts — verdicts come from
the observation plane and the harness.

## Architecture (observed, `thv run --transport stdio`)

`thv run` produces three containers and one host process:

| Component | Where | Role |
| --- | --- | --- |
| workload (`<name>`) | container, net `toolhive-<name>-internal` | the proxied MCP server |
| `<name>-egress` | container, nets `toolhive-external` + `…-internal` | **egress enforcement point** for the workload |
| `<name>-dns` | container, both nets | dnsmasq for the workload |
| MCP proxy | **detached host process** (`127.0.0.1:<port>/mcp`) | transport + **OIDC validation** |

Two consequences for the bench harness:

1. **OIDC is validated on the host, not in a container.** The proxy fetches
   OIDC discovery/JWKS from the *host* network namespace. So an issuer that is
   only reachable on the bench bridge (`mcpsb-bench`, e.g. `mcpsb-issuer`) is
   **not** reachable by ToolHive — the host does not route to the bridge on this
   OrbStack setup (`curl http://10.77.0.20:8080` → connection refused). The
   issuer must be reachable from the host (e.g. `https://localhost:<port>`).
2. **Egress runs through `<name>-egress`.** That container, on `toolhive-external`,
   is where a bench sink must sit to observe the workload's egress (WS-B).

## The OIDC positive control cannot pass on v0.46 without touching host trust

With the issuer reachable from the host, a **valid** token is still rejected
(HTTP 401). Root cause, from the proxy log (`~/Library/Application Support/toolhive/logs/<name>.log`):

- Plain-HTTP issuer → `oidc discovery failed … is not HTTPS scheme`, even with
  `--oidc-insecure-allow-http=true`. So the issuer must serve **HTTPS** (the
  harness issuer now can: `--tls-cert/--tls-key`).
- HTTPS issuer with a self-signed cert → `x509: certificate signed by unknown
  authority`. `--thv-ca-bundle <cert>` (documented for "JWKS, OIDC discovery") is
  **not honored by the detached discovery path** in v0.46 — the error persists
  even with a proper `CA:TRUE` cert supplied as the bundle. `SSL_CERT_FILE` on
  the `thv run` invocation is likewise not inherited by the detached proxy.

The only remaining way to make ToolHive trust the issuer is to install the cert
into the host's **system trust store**, which the harness will not do: it is an
out-of-band change to the operator's machine and a host-exposure the bench is
supposed to avoid.

### Verdict impact (honest, invariant #8)

- **AUTH-001** — enforced live: unauthenticated `tools/list`/`tools/call` → 401;
  with no OIDC configured ToolHive warns it "will accept every request
  unauthenticated". Clean differential, independent of token validation.
- **AUTH-003 / AUTH-004** (token expiry / audience) — **INCONCLUSIVE**: their
  positive control is "a valid token is accepted", which cannot be established on
  v0.46 without host-trust modification (above). This is a precise upgrade over
  the earlier "issuer unreachable" characterization: the issuer *is* reachable;
  ToolHive will not trust its cert on the discovery path.

If a future ToolHive release honors `--thv-ca-bundle` on the discovery path, the
harness issuer's `--tls-cert/--tls-key` + `--thv-ca-bundle <bench cert>` is the
wiring that turns AUTH-003/004 into live verdicts.

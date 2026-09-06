# fixtures/net — observation-plane network (WS-2)

`compose.yml` runs the four observation servers on a dedicated bench bridge
network (`mcpsb-bench`, `10.77.0.0/24`):

| Service | Address | Role |
| --- | --- | --- |
| `sink` | `10.77.0.10:8080` | records every inbound HTTP request |
| `issuer` | `10.77.0.20:8080` (alias `mcpsb-issuer`) | OIDC issuer: discovery, JWKS, `/mint` |
| `dns` | `10.77.0.53:53` | resolver with the rebinding zone |
| `imds` | `10.77.0.169` + `169.254.169.254:80` | fake instance metadata |
| `redirector` | `10.77.0.81:8081` | 302 chains |

## The OIDC issuer is first-class here (WS-A)

An OIDC target validates the bench's tokens against a *reachable* issuer. Making
the issuer a service on `mcpsb-bench` — rather than something each adapter stands
up on the host — means the harness can attach it to every target's network and a
target reaches it in-namespace at the `mcpsb-issuer` alias. It advertises that
alias as its `iss` (`--public-url http://mcpsb-issuer:8080`), so discovery, `iss`,
and `jwks_uri` all match what the target validates. The signing key never leaves
the container: the bench mints principals' tokens over HTTP at
`GET /mint?sub=<principal>&tenant=<t>&aud=<a>&expired=<0|1>`.

Reachability is checked, not assumed: `mcpsb doctor --target <t>` execs inside the
target's container and probes the issuer's discovery endpoint from there.

The servers are stdlib-only, so the stock `python:3.11-slim` image runs them with
the repo mounted read-only at `/app` — no build step.

## Reading the record of truth

Each server records out-of-band. The sink exposes its log at
`GET http://10.77.0.10:8080/__mcpsb__/records` (and `DELETE` to clear). The DNS,
IMDS, and redirector controllers are read in-process by attacks via
`ObservationPlane`; for the networked deployment they are queried the same way
from the bench process that also drives the target.

## Wiring a target in (WS-6)

A target's own `compose.yml` joins `mcpsb-bench` as an external network and:

1. sets its resolver to `10.77.0.53` so a malicious server's hostnames resolve
   through the rebinding zone;
2. routes `169.254.169.254` to the `imds` container (a static route in the
   target namespace, `NET_ADMIN`), so an SSRF to the metadata address lands on
   the fake IMDS and is recorded.

Both steps are target-specific and finalized per adapter, which is why they live
in `targets/<name>/`, not here — the neutral fixtures only stand the servers up.

## In-process use

Tests and attacks use the same servers without Docker via
`mcpsb.observation.ObservationPlane`, which starts all four on `127.0.0.1` with
ephemeral ports. The verdict logic is identical; only the wiring differs.

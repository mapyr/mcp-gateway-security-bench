# Live run — MCP Hangar

> **PRE-GATE RECORD (2026-09-04).** This is a prose record from before the
> evidence-source (D1), positive-control (D2), claim (D3), and tested-version
> gates existed. Unlike the Docker record it *does* show positive controls (a
> valid token accepted before the negatives are counted), so its AUTH/TENANCY
> results are not superseded to INCONCLUSIVE — but they are **not** a current,
> gate-checked verdict either: the run was on an **unpinned v2 HEAD checkout**,
> not a released build, and the adapter's tested floor is now **v2.17.1**
> (`supports_version`), so a *publishable* Hangar verdict needs a fresh gated run
> on a pinned ≥2.17.1 build. It is **not reproducible in the current environment**
> (the installed `mcp-hangar` wheel is 1.4.0, which the version gate withholds as
> ERROR rather than scoring). Treat everything below as a prior signal pending
> that re-run; [`../../REPORT.md`](../../REPORT.md) is the authoritative report.

**Hangar is maintained by this bench's author (GOVERNANCE §1).** It runs through
the same pipeline as every other target; per §1.4 no MCPSB result appears in
Hangar's own marketing until an external maintainer publishes a run.

Target: local `mcp-hangar` checkout run as `mcp-hangar serve --config … --http`
(a host uvicorn process), Streamable HTTP at `/mcp`, auth enabled with OIDC
pointed at the bench's OIDC issuer harness, proxying the bench's stdio fixture in
`subprocess` mode.

> **Environment note.** The local checkout is HEAD-of-development and its `.venv`
> had drifted from its pinned deps (`mcp==2.0.0`), crashing startup with
> `'Server' object has no attribute 'add_request_handler'`. Running `uv sync`
> (the project's own dependency-alignment step — not a patch) fixed it and Hangar
> started cleanly. Recorded for reproducibility.

## Auth family — PASS, with a verified positive control

Because Hangar's validator is a host process, it *can* reach the local issuer's
JWKS (unlike the ToolHive run) — so the positive control holds and the negative
verdicts are meaningful, not a blanket failure.

| Check | Result |
| --- | --- |
| **positive control** — valid token | **accepted (HTTP 200)** |
| `AUTH-001.a` / `.b` — no token | **PASS** (401 `authentication_failed`) |
| `AUTH-003.b` — expired token | **PASS** (rejected) |
| `AUTH-004.b` — wrong-audience token | **PASS** (rejected) |

Driven through the bench's own attack corpus. Hangar genuinely enforces JWT
signature, expiry, and audience: it accepts a valid token and rejects
unauthenticated, expired, and wrong-audience ones *specifically* (the valid one
works, so the rejections are the defect being caught, not a broken auth state).
This confirms, live, the auth invariants the code review found enforced.

## Tenancy — PASS (tenant from the token, not client input)

Hangar resolves the tenant only from the verified token claim (`require_tenant`
is a fail-closed gate). Demonstrated observably: with `require_tenant: true`, a
token that carries **no** tenant claim is rejected — and stays rejected even when
the client supplies a tenant through an argument, an `X-Tenant` header, or
`_meta`.

| Check | Result |
| --- | --- |
| **positive control** — token *with* tenant | accepted (200) |
| no-tenant token (baseline) | rejected (401) |
| `TENANT-001` — no-tenant token + `tenant` **argument** | **PASS** (still 401 — arg ignored) |
| `TENANT-002` — no-tenant token + `X-Tenant` **header** | **PASS** (still 401 — header ignored) |
| `TENANT-002` — no-tenant token + `_meta.tenant` | **PASS** (still 401 — `_meta` ignored) |

No request-controlled field can supply or override the tenant; it comes from the
authenticated principal. This confirms, live, the anti-spoof tenancy the code
review found (tenant read from the token claim, headers/`_meta` untrusted).

## AUTHZ-001 / AUDIT-002 — attempted, INCONCLUSIVE

I tried to reach two more families and could not establish clean positive
controls, so neither is claimed:

* **Authorization (AUTHZ-001)** — invoking a proxied tool goes through `hangar_call`
  in egress mode, and Hangar's RBAC **default-denied** it:
  `AuthorizationDenied: tool:invoke permission required`. That is Hangar's
  per-caller authorization *working* (fail-closed). But granting the permission
  to establish the positive control (a role-holder succeeds, a non-holder is
  denied) did not take effect with the `user:<sub>` / `admin` config I tried, so
  every principal was denied — with no positive control, "denied" is not a clean
  AUTHZ-001 PASS. Recorded INCONCLUSIVE. (The fail-closed denial is a genuine
  positive signal, just not a full differential.)

* **Audit redaction (AUDIT-002)** — could not be observed live (a tool call was
  blocked by the RBAC denial above, and the event surface returned nothing in this
  setup). No verdict is claimed either way. Any concrete concern here is handled
  privately as an own-target finding until addressed (see below).

## What this run does NOT vouch for

This is the **auth and tenancy families only**. It is **not** a clean bill of
health: the egress and audit families are declared in the adapter (so the bench
runs them rather than hiding them behind `UNSUPPORTED`), but they were **not
reachable live here** and are **not vouched for** by this run.

Consistent with `DISCLOSURE.md`, any specific own-target finding about **unfixed**
behaviour is kept **out of this published record** — fix first, then run the bench
live to confirm, then publish (GOVERNANCE §1.3). Publishing the internals of an
unfixed weakness would be an attack roadmap, which protecting the project's
security forbids. This is the same discipline applied to third-party findings, and
it is stricter than §7's "own results unrestricted" allowance — deliberately.

## Not covered

SECRET / SCHEMA / SESSION / AUDIT were not reachable live (observation limits and
the RBAC/positive-control obstacles above). Further harness steps. Nothing was
reported as PASS/FAIL that could not be defended (invariant #8).

---

*Point-in-time, version-specific, best-effort. A targeted benchmark run, not a
comprehensive security audit; no warranty.*

# controls/

Two variants of one minimal MCP intermediary — the credibility engine
(GOVERNANCE §3). The differential gate rejects any attack that is not FAIL on
`vulnerable` and PASS on `secure`, so `secure` is an executable definition of
what the bench considers correct.

## Layout

| Path | What |
| --- | --- |
| `common/policy.py` | `Policy` (one boolean per enforcement point) + `SECURE_POLICY` (all on) / `VULNERABLE_POLICY` (all off). |
| `common/identities.py` | Fixed tokens, principals, tenants, grants the intermediary recognizes. |
| `common/intermediary.py` | The shared JSON-RPC-over-HTTP intermediary; every enforcement point gated on one policy flag. |
| `common/egress.py` | The `fetch` egress engine: resolve → range-check → connect → follow redirects. Where SSRF/rebinding is (not) blocked. |
| `common/adapter_base.py` | Shared adapter; both controls differ only in `policy`. |
| `secure/adapter.py`, `vulnerable/adapter.py` | Thin adapters selecting the policy. |

The two variants are the **same code**; only the policy differs. That is the
whole point — it makes "secure" auditable line by line, and guarantees, by
construction, that every dimension can distinguish a correct intermediary from a
broken one.

## Driving it

The intermediary speaks JSON-RPC over HTTP `POST /`, bearer auth via
`Authorization: Bearer <token>` (see `identities.py` for valid tokens). Control
endpoints outside the JSON-RPC path let an attack set up a scenario over the
wire without touching internals:

| Endpoint | Purpose |
| --- | --- |
| `POST /__egress__` | configure the `fetch` resolver (static map, rebinding sequences) and allowlist |
| `POST /__drift__` | flip a tool's live schema/description (SCHEMA-*) |
| `GET /__audit__`, `GET /__trace__` | read the audit log / trace (AUDIT-*; the §3.1 exception) |
| `DELETE /__state__` | reset audit, trace, sessions, egress counters |

## Coverage note

`common/` implements enforcement points for every policy family in the registry.
The auth/authz/tenancy/egress/secret/audit/session dimensions are exercised
end-to-end by the WS-3 tests; the schema and some batch/session refinements are
scaffolded and will be driven fully by the WS-4 attacks and WS-5 malicious
fixtures. Controls are not frozen like the registry — an attack that needs a
sharper enforcement point extends `common/`, and the differential gate keeps
both variants honest.

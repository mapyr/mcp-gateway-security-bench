# targets/docker_mcp_gateway — live integration notes

## SCHEMA-003: two different surfaces, only one of them observed

SCHEMA-003's premise is **runtime** tool shadowing: a name resolves to one
upstream, and *a second upstream claiming the same name must not silently shadow
it*. The attack exercises exactly that — `scenario.trigger_shadow()` introduces a
second upstream that claims an existing tool name **after admission**, then
checks discovery (surface a) and a call (surface b).

Docker MCP Gateway was observed to **refuse to start** when two *config-declared*
servers declare the same tool name. That is a real control, but it is a
**start-time, config-time** check — a different surface from what SCHEMA-003
tests. It does **not** establish a SCHEMA-003.b verdict, because SCHEMA-003.b
asks whether a *runtime-discovered* malicious upstream can shadow a name on the
call path, which the config-collision refusal never exercises.

Honest consequence (invariant #7 — verify against the artifact, not the docs):

- "Docker refuses config-declared collisions" is a legitimate **observation**,
  reported as such — not as a SCHEMA-003 PASS.
- SCHEMA-003.a / .b against Docker remain **INCONCLUSIVE** until a malicious
  runtime-discovery upstream is actually introduced behind the gateway and the
  discovery/call surfaces are driven. The refuse-start behavior does not stand in
  for that run.

A separate registry sub-ID for "config-declared collision refused at start" was
considered and **not** added: it is a distinct control worth naming, but adding
an ID is a `spec-change:` to `mcpsb/registry.py` (invariant #4) and should be
proposed on its own, with a premise about the start-time trust boundary, rather
than folded into this integration note.

## Egress path (WS-B prerequisite — to confirm live)

To observe the gateway's egress with the bench sink (WS-B), the sink must sit on
the gateway's outbound path. Docker MCP Gateway runs its MCP servers as
containers on a Docker network and mediates their outbound traffic; the sink
must be reachable on that network (or via the gateway's allowlist) so a fixture
`fetch` to an *allowed* destination lands on the sink (reachable-when-allowed
positive control) before a *forbidden* one is shown blocked.

This requires the `docker mcp` gateway plugin. It is **not installed in the
current environment** (`docker mcp version` → "unknown command"), so the egress
path here is documented from the architecture, not confirmed from a live run.
`adapter.version()` returns empty until the plugin is present, and the WS-D3
claim gate refuses to publish an empty-version report — so no Docker verdict can
be published from this environment without the real artifact.

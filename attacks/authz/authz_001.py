"""AUTHZ-001 — authenticated but not authorized, across surfaces.

Premise: authorization is required on every value-bearing surface;
authenticating a caller does not by itself authorize a specific tool, prompt, or
resource.

Principal B is authenticated but lacks the grant that principal A has. On every
surface B reaches for A's tool/prompt/resource, a correct intermediary denies.
"""

import mcpsb
from mcpsb import Verdict
from attacks._helpers import batch_entry, client, served_or_blocked


@mcpsb.test(id="AUTHZ-001", surfaces="bcde", evidence="client_response")
def authz_001(ctx):
    s = ctx.scenario
    c = client(ctx, token=s.principal_b_token)  # authenticated, under-privileged

    if ctx.surface == "b":
        return served_or_blocked(ctx, c.tools_call(s.tenant_tool, {}))
    if ctx.surface == "c":
        return served_or_blocked(ctx, c.prompts_get(s.authorized_prompt))
    if ctx.surface == "d":
        return served_or_blocked(ctx, c.resources_read(s.authorized_resource))
    if ctx.surface == "e":
        response = c.batch([
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": s.tenant_tool, "arguments": {}}},
        ])
        entry = batch_entry(response, 1)
        if entry is None:
            ctx.reason = "batch produced no comparable entry"
            return Verdict.INCONCLUSIVE
        if "error" in entry:
            ctx.reason = "batch: unauthorized call blocked"
            return Verdict.PASS
        ctx.reason = "batch: unauthorized call executed"
        return Verdict.FAIL
    return Verdict.INCONCLUSIVE

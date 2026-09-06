"""SCHEMA-003 — tool shadowing / cross-upstream name collision.

Premise: a tool name resolves to exactly one upstream; a second upstream
claiming the same name must not silently shadow or override the first.

Surface a: a colliding name must not appear twice in discovery. Surface b: a call
to the name must not be served by the shadowing upstream.
"""

import mcpsb
from mcpsb import Verdict
from attacks._helpers import client, tool_names


@mcpsb.test(id="SCHEMA-003", surfaces="ab", evidence="client_response")
def schema_003(ctx):
    s = ctx.scenario
    s.reset_state()
    c = client(ctx, token=s.principal_a_token)
    s.trigger_shadow()  # a second upstream claims the same tool name

    if ctx.surface == "a":
        names = tool_names(c.tools_list())
        if names.count(s.schema_tool) > 1:
            ctx.reason = "a colliding tool name appears more than once"
            return Verdict.FAIL
        ctx.reason = "tool names stayed unique"
        return Verdict.PASS

    # surface b: a call must not reach the shadowing upstream.
    response = c.tools_call(s.schema_tool, {"message": "probe"})
    if s.shadow_marker and s.shadow_marker in str(response.body):
        ctx.reason = "call served by the shadowing upstream"
        return Verdict.FAIL
    ctx.reason = "call served by the original upstream"
    return Verdict.PASS

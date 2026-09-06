"""AUTHZ-002 — a tool hidden from tools/list, called directly.

Premise: hiding a tool from tools/list is a discovery-layer decision; the
enforcement decision on tools/call must not depend on whether the caller could
see the tool.

Surface a checks the tool is not disclosed by discovery; surface b checks that
calling it directly is nonetheless blocked. Enforcement must not ride on
visibility, so both must hold.
"""

import mcpsb
from mcpsb import Verdict
from attacks._helpers import client, served_or_blocked


@mcpsb.test(id="AUTHZ-002", surfaces="ab", evidence="client_response")
def authz_002(ctx):
    s = ctx.scenario
    c = client(ctx, token=s.principal_a_token)

    if ctx.surface == "a":
        response = c.tools_list()
        names = _tool_names(response)
        if s.hidden_tool in names:
            ctx.reason = "hidden tool disclosed by tools/list"
            return Verdict.FAIL
        ctx.reason = "hidden tool not disclosed"
        return Verdict.PASS

    # surface b: call it directly.
    return served_or_blocked(ctx, c.tools_call(s.hidden_tool, {}))


def _tool_names(response) -> set[str]:
    result = response.result or {}
    return {t.get("name") for t in result.get("tools", []) if isinstance(t, dict)}

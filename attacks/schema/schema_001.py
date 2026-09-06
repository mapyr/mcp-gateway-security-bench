"""SCHEMA-001 — silent schema expansion (a new argument after admission).

Premise: a tool's input contract is what the intermediary vouched for; a server
adding arguments after admission changes that contract and must be surfaced, not
silently accepted.

Surface a: the argument set the intermediary advertises must not silently gain a
field after admission. Surface b: a call carrying an argument outside the
admitted contract must be rejected, not accepted.
"""

import mcpsb
from mcpsb import Verdict
from attacks._helpers import client, schema_props, served_or_blocked


@mcpsb.test(id="SCHEMA-001", surfaces="ab", evidence="client_response")
def schema_001(ctx):
    s = ctx.scenario
    s.reset_state()
    c = client(ctx, token=s.principal_a_token)

    before = schema_props(c.tools_list(), s.schema_tool)
    s.trigger_drift()  # a server adds an argument after admission
    after = schema_props(c.tools_list(), s.schema_tool)

    if ctx.surface == "a":
        gained = after - before
        if gained:
            ctx.reason = f"tool silently gained argument(s): {sorted(gained)}"
            return Verdict.FAIL
        ctx.reason = "advertised argument set stayed pinned"
        return Verdict.PASS

    # surface b: send an argument outside the admitted contract.
    new = sorted(after - before) or ["mcpsb_unadmitted_arg"]
    response = c.tools_call(s.schema_tool, {name: "x" for name in new})
    return served_or_blocked(ctx, response)

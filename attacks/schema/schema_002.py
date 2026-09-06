"""SCHEMA-002 — tool description rug pull (tool poisoning).

Premise: the tool description an agent reasons over is part of the trust
surface; a server mutating it after admission is a change the intermediary must
detect.

Both surfaces observe the definition the caller would rely on — at discovery
(a) and immediately before a call (b): a mutated description passing through
after admission is the failure.
"""

import mcpsb
from mcpsb import Verdict
from attacks._helpers import client, description


@mcpsb.test(id="SCHEMA-002", surfaces="ab", evidence="client_response")
def schema_002(ctx):
    s = ctx.scenario
    s.reset_state()
    c = client(ctx, token=s.principal_a_token)

    before = description(c.tools_list(), s.schema_tool)
    s.trigger_drift()  # a server rewrites its description after admission
    after = description(c.tools_list(), s.schema_tool)

    if after != before:
        ctx.reason = "tool description mutated after admission"
        return Verdict.FAIL
    ctx.reason = "description stayed pinned to what was admitted"
    return Verdict.PASS

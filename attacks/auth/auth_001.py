"""AUTH-001 — unauthenticated tools/list and tools/call.

Premise: an unauthenticated caller is outside the trust boundary; the
intermediary must not reveal tool inventory or accept calls before identity is
established.
"""

import mcpsb
from mcpsb import Verdict
from attacks._helpers import client, served_or_blocked


@mcpsb.test(id="AUTH-001", surfaces="ab", evidence="client_response")
def auth_001(ctx):
    c = client(ctx)  # deliberately no credentials
    s = ctx.scenario
    if ctx.surface == "a":
        response = c.tools_list()
    else:
        response = c.tools_call(s.authorized_tool, {"message": "probe"})
    return served_or_blocked(ctx, response)

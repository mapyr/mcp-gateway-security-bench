"""AUTH-004 — wrong audience (RFC 8707).

Premise: a token minted for a different resource audience is not addressed to
this intermediary and must be rejected even if otherwise valid.
"""

import mcpsb
from mcpsb import Verdict
from attacks._helpers import client, served_or_blocked


@mcpsb.test(id="AUTH-004", surfaces="b", evidence="client_response")
def auth_004(ctx):
    s = ctx.scenario
    c = client(ctx, token=s.wrong_audience_token)
    response = c.tools_call(s.authorized_tool, {"message": "probe"})
    return served_or_blocked(ctx, response)

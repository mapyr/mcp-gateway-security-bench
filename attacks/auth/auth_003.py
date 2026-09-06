"""AUTH-003 — expired token.

Premise: token validity is time-bounded; an expired credential carries no
authority regardless of prior validity.
"""

import mcpsb
from mcpsb import Verdict
from attacks._helpers import client, served_or_blocked


@mcpsb.test(id="AUTH-003", surfaces="b", evidence="client_response")
def auth_003(ctx):
    s = ctx.scenario
    c = client(ctx, token=s.expired_token)
    response = c.tools_call(s.authorized_tool, {"message": "probe"})
    return served_or_blocked(ctx, response)

"""AUTH-002 — principal A's token presented as principal B.

Premise: a bearer token authenticates exactly one principal; presenting
principal A's token must never grant principal B's authority.

The attacker holds A's token and claims, through an untrusted channel, to be B.
Acting as B would return B's tenant-scoped data — the marker only B should see.
"""

import mcpsb
from mcpsb import Verdict
from attacks._helpers import client


@mcpsb.test(id="AUTH-002", surfaces="b", evidence="client_response")
def auth_002(ctx):
    s = ctx.scenario
    c = client(ctx, token=s.principal_a_token)
    response = c.tools_call(
        s.tenant_tool, {}, headers={s.impersonation_header: s.principal_b_identity}
    )
    if s.tenant_b_marker and s.tenant_b_marker in str(response.body):
        ctx.reason = "A's token was accepted while acting as principal B"
        return Verdict.FAIL
    ctx.reason = "token stayed bound to its own principal"
    return Verdict.PASS

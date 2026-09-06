"""TENANT-001 — tenant override in tool arguments.

Premise: the caller's tenant is bound by the authenticated session, not by data
the caller supplies; tool arguments cannot re-scope authority.

Principal A (tenant A) asks the tenant-scoped tool for tenant B's data by
passing B's identifier as an argument. Leaking B's marker is a cross-tenant
breach.
"""

import mcpsb
from mcpsb import Verdict
from attacks._helpers import client


@mcpsb.test(id="TENANT-001", surfaces="b", evidence="client_response")
def tenant_001(ctx):
    s = ctx.scenario
    c = client(ctx, token=s.principal_a_token)
    response = c.tools_call(
        s.tenant_tool, {s.tenant_override_arg: s.other_tenant_id}
    )
    leaked = s.tenant_b_marker in str(response.body)
    if leaked:
        ctx.reason = "argument re-scoped the tenant; other tenant's data returned"
        return Verdict.FAIL
    ctx.reason = "tenant stayed bound to the session"
    return Verdict.PASS

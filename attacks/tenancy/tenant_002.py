"""TENANT-002 — tenant override in a header / path / _meta field.

Premise: tenant identity derives from the authenticated principal; no
request-controlled header, path segment, or _meta field may override it.
"""

import mcpsb
from mcpsb import Verdict
from attacks._helpers import client


@mcpsb.test(id="TENANT-002", surfaces="b", evidence="client_response")
def tenant_002(ctx):
    s = ctx.scenario
    c = client(ctx, token=s.principal_a_token)
    response = c.tools_call(
        s.tenant_tool,
        {},
        headers={s.tenant_override_header: s.other_tenant_id},
        meta={"tenant": s.other_tenant_id},
    )
    if s.tenant_b_marker and s.tenant_b_marker in str(response.body):
        ctx.reason = "a request-controlled field re-scoped the tenant"
        return Verdict.FAIL
    ctx.reason = "tenant stayed bound to the session"
    return Verdict.PASS

"""AUDIT-002 — secrets / raw arguments in the audit trail or trace.

Premise: the audit trail is itself a disclosure surface; recording secrets or
raw sensitive arguments turns an accountability mechanism into a leak.

AUDIT-* is the family where the SUT's own record is the subject of study
(SPEC §3.1): a sensitive argument is passed, then the trace is read back through
the scenario's target-agnostic reader.
"""

import mcpsb
from mcpsb import Verdict
from attacks._helpers import client


@mcpsb.test(id="AUDIT-002", surfaces="b", evidence="target_audit")
def audit_002(ctx):
    s = ctx.scenario
    s.reset_state()
    marker = f"sensitive-value-{ctx.sub_id}"

    c = client(ctx, token=s.principal_a_token)
    c.tools_call(s.authorized_tool, {"message": marker})

    trace = s.read_trace()
    if any(marker in str(entry) for entry in trace):
        ctx.reason = "raw sensitive argument recorded in the trace"
        return Verdict.FAIL
    ctx.reason = "trace redacted the sensitive argument"
    return Verdict.PASS

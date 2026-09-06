"""The AUDIT-family positive control (WS-D2).

AUDIT is the one family whose subject of study is the target's own log (SPEC
§3.1), so its positive control legitimately reads that log
(``evidence_source=target_audit``): a legitimate action must produce an audit
entry. If the log records nothing for a benign action, "the action was not
logged" findings are not distinguishable from a log that never works — so the
family is not verified.
"""

import mcpsb
from mcpsb import Verdict
from attacks._helpers import client


@mcpsb.positive_control(family="AUDIT", evidence="target_audit")
def audit_pc(ctx):
    s = ctx.scenario
    s.reset_state()
    c = client(ctx, token=s.principal_a_token)
    c.tools_call(s.authorized_tool, {"message": "positive-control"})
    entries = [e for e in s.read_audit() if isinstance(e, dict)]
    if entries:
        ctx.reason = "a legitimate action produced an audit entry (the log is live)"
        return Verdict.PASS
    ctx.reason = "the audit log recorded nothing for a legitimate action"
    return Verdict.FAIL

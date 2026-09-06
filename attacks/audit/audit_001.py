"""AUDIT-001 — an action executed with no audit event.

Premise: a security-relevant action and its audit record are one atomic fact; an
action that executes without a corresponding event is unaccountable.

AUDIT-* is the one family where the SUT's own log is the subject of study
(SPEC §3.1): the action is driven, then the audit log is read back through the
scenario's target-agnostic reader.
"""

import mcpsb
from mcpsb import Verdict
from attacks._helpers import client


@mcpsb.test(id="AUDIT-001", surfaces="be", evidence="target_audit")
def audit_001(ctx):
    s = ctx.scenario
    s.reset_state()
    c = client(ctx, token=s.principal_a_token)

    if ctx.surface == "b":
        c.tools_call(s.authorized_tool, {"message": "auditable"})
    else:  # surface e: drive the action through the batch/aggregating path
        c.batch([
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": s.authorized_tool, "arguments": {"message": "auditable"}}},
        ])

    audit = s.read_audit()
    recorded = any(s.authorized_tool in str(e.get("action", "")) for e in audit if isinstance(e, dict))
    if recorded:
        ctx.reason = "action produced an audit event"
        return Verdict.PASS
    ctx.reason = "action executed with no audit event"
    return Verdict.FAIL

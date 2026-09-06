"""AUTHZ-004 — a batch path that bypasses the per-call gate.

Premise: an aggregating or batch surface is not a trust-exempt fast path; every
constituent call must pass the same gate as a singleton call.

The batch pairs an authorized call with an unauthorized one. A pre-gate that
authorizes the batch on its first call lets the second slip through.
"""

import mcpsb
from mcpsb import Verdict
from attacks._helpers import batch_entry, client


@mcpsb.test(id="AUTHZ-004", surfaces="e", evidence="client_response")
def authz_004(ctx):
    s = ctx.scenario
    c = client(ctx, token=s.principal_a_token)
    response = c.batch([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": s.authorized_tool, "arguments": {"message": "ok"}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": s.hidden_tool, "arguments": {}}},
    ])
    entry = batch_entry(response, 2)  # the unauthorized call
    if entry is None:
        ctx.reason = "batch produced no comparable entry"
        return Verdict.INCONCLUSIVE
    if "error" in entry:
        ctx.reason = "batch: unauthorized call gated"
        return Verdict.PASS
    ctx.reason = "batch: unauthorized call slipped past the gate"
    return Verdict.FAIL

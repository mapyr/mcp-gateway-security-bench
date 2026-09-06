"""SESSION-001 — state leak across sessions after reconnect.

Premise: session state is bound to its session; reconnection or resumption must
not expose one session's state, identity, or authority to another.

Principal A stashes a marker under one session; a different principal reconnects
under a new session and reads it back. Recovering the marker is a leak.
"""

import mcpsb
from mcpsb import Verdict
from attacks._helpers import client


@mcpsb.test(id="SESSION-001", surfaces="f", evidence="client_response")
def session_001(ctx):
    s = ctx.scenario
    s.reset_state()
    marker = f"session-marker-{ctx.sub_id}"

    writer = client(ctx, token=s.principal_a_token)
    writer.tools_call(
        s.session_write_tool,
        {s.session_value_arg: marker},
        headers={s.session_header: "session-A"},
    )

    # Reconnect as a different principal under a fresh session id.
    reader = client(ctx, token=s.principal_b_token)
    response = reader.tools_call(
        s.session_read_tool, {}, headers={s.session_header: "session-B"}
    )

    if marker in str(response.body):
        ctx.reason = "one session's state was readable from another"
        return Verdict.FAIL
    ctx.reason = "session state stayed isolated across reconnect"
    return Verdict.PASS

"""SECRET-001 — environment exfiltration via a tool argument / response.

Premise: the intermediary's own secrets (environment, tokens) are outside every
caller's and server's trust boundary; no argument or response path may induce
their disclosure.

The response delivered to the attacking client is a legitimate observation
surface (SPEC §3.1) — it is the exfiltration channel itself.
"""

import mcpsb
from mcpsb import Verdict
from attacks._helpers import client


@mcpsb.test(id="SECRET-001", surfaces="b", evidence="client_response")
def secret_001(ctx):
    s = ctx.scenario
    c = client(ctx, token=s.principal_a_token)
    response = c.tools_call(s.secret_tool, {s.secret_template_arg: s.secret_probe})
    if s.secret_marker and s.secret_marker in str(response.body):
        ctx.reason = "secret interpolated into the response"
        return Verdict.FAIL
    ctx.reason = "probe returned without interpolating the secret"
    return Verdict.PASS

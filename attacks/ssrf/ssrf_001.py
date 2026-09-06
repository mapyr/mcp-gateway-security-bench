"""SSRF-001 — egress to loopback / RFC1918.

Premise: the intermediary's network position is not delegable to a malicious
server; requests it originates must honor an egress policy, not the server's
chosen destination.

A malicious hostname resolves (through the bench DNS) to an internal address
where the sink stands in for the internal resource. The verdict comes from the
sink out-of-band, never from the intermediary's response (invariant #1).
"""

import mcpsb
from mcpsb import Verdict
from attacks._helpers import client

_HOST = "internal-target.mcpsb.test"
_PROBE = "/ssrf-001-probe"


@mcpsb.test(id="SSRF-001", surfaces="b", evidence="sink")
def ssrf_001(ctx):
    if ctx.observation is None:
        ctx.reason = "no observation plane; cannot establish the test"
        return Verdict.INCONCLUSIVE

    obs = ctx.observation
    obs.sink.recorder.clear()
    obs.dns.controller.set_static(_HOST, "127.0.0.1")  # internal, resolved via bench DNS

    s = ctx.scenario
    c = client(ctx, token=s.principal_a_token)
    url = f"http://{_HOST}:{obs.sink.port}{_PROBE}"
    try:
        c.tools_call(s.egress_tool, {s.egress_url_arg: url})
    except Exception:  # noqa: BLE001 — a blocked egress may surface however; the sink is the truth
        pass

    reached = obs.sink.recorder.received(path=_PROBE)
    if reached:
        ctx.reason = "intermediary forwarded the call to the internal address"
        ctx.evidence = {"sink": _PROBE}
        return Verdict.FAIL
    ctx.reason = "egress to the internal address was blocked"
    return Verdict.PASS

"""SSRF-004 — DNS rebinding across the check/connect boundary.

Premise: the destination checked at policy time must be the destination
connected to; a name that re-resolves between check and connect is the same
request, not a new one.

The host is on the egress allowlist (it is a legitimately configured upstream),
so it passes the policy-time check with a benign address — then rebinds to
loopback at connect time. Only re-checking the connect-time address stops it.
"""

import mcpsb
from mcpsb import Verdict
from attacks._helpers import client

_PROBE = "/ssrf-004-probe"
_BENIGN = "203.0.113.10"  # TEST-NET-3; not in any blocked range, never connected to


@mcpsb.test(id="SSRF-004", surfaces="b", evidence="sink")
def ssrf_004(ctx):
    if ctx.observation is None:
        ctx.reason = "no observation plane; cannot establish the test"
        return Verdict.INCONCLUSIVE

    obs = ctx.observation
    obs.sink.recorder.clear()
    s = ctx.scenario
    host = s.rebindable_host
    # First lookup (policy time) benign; every lookup after (connect) is loopback.
    obs.dns.controller.set_rebind(host, [_BENIGN, "127.0.0.1"])

    c = client(ctx, token=s.principal_a_token)
    url = f"http://{host}:{obs.sink.port}{_PROBE}"
    try:
        c.tools_call(s.egress_tool, {s.egress_url_arg: url})
    except Exception:  # noqa: BLE001
        pass

    if obs.sink.recorder.received(path=_PROBE):
        ctx.reason = "rebinding reached loopback after a benign policy check"
        ctx.evidence = {"sink": _PROBE}
        return Verdict.FAIL
    ctx.reason = "connect-time address was re-checked and blocked"
    return Verdict.PASS

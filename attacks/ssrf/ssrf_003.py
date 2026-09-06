"""SSRF-003 — IPv6 and IPv4-mapped address encodings.

Premise: an egress allow/deny decision must be made on the resolved
destination, not its textual form; alternate address encodings address the same
host.

The URL names loopback via an IPv4-mapped IPv6 literal. A correct intermediary
resolves the encoding and blocks it; a naive one range-checks the literal string
and connects. Verdict from the sink, out-of-band.
"""

import mcpsb
from mcpsb import Verdict
from attacks._helpers import client

_PROBE = "/ssrf-003-probe"


@mcpsb.test(id="SSRF-003", surfaces="b", evidence="sink")
def ssrf_003(ctx):
    if ctx.observation is None:
        ctx.reason = "no observation plane; cannot establish the test"
        return Verdict.INCONCLUSIVE

    obs = ctx.observation
    obs.sink.recorder.clear()
    s = ctx.scenario
    c = client(ctx, token=s.principal_a_token)
    url = f"http://[::ffff:127.0.0.1]:{obs.sink.port}{_PROBE}"
    try:
        c.tools_call(s.egress_tool, {s.egress_url_arg: url})
    except Exception:  # noqa: BLE001
        pass

    if obs.sink.recorder.received(path=_PROBE):
        ctx.reason = "IPv4-mapped encoding reached loopback"
        ctx.evidence = {"sink": _PROBE}
        return Verdict.FAIL
    ctx.reason = "alternate encoding was resolved and blocked"
    return Verdict.PASS

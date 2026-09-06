"""SSRF-005 — a redirect chain leading past the allowlist.

Premise: an egress allowlist governs the final destination reached, not only the
first hop; following a redirect does not exit the policy.

The first hop is a redirector that 302s to an internal address. A correct
intermediary re-applies the policy on each hop; a naive one follows the chain to
loopback. Verdict from the sink at the final destination.
"""

import mcpsb
from mcpsb import Verdict
from attacks._helpers import client

_FINAL = "/ssrf-005-final"
_REDIR_HOST = "redirector.mcpsb.test"
_INTERNAL_HOST = "internal-5.mcpsb.test"


@mcpsb.test(id="SSRF-005", surfaces="b", evidence="sink")
def ssrf_005(ctx):
    if ctx.observation is None:
        ctx.reason = "no observation plane; cannot establish the test"
        return Verdict.INCONCLUSIVE

    obs = ctx.observation
    obs.sink.recorder.clear()
    obs.dns.controller.set_static(_REDIR_HOST, "127.0.0.1")
    obs.dns.controller.set_static(_INTERNAL_HOST, "127.0.0.1")

    s = ctx.scenario
    c = client(ctx, token=s.principal_a_token)
    final = f"http://{_INTERNAL_HOST}:{obs.sink.port}{_FINAL}"
    url = f"http://{_REDIR_HOST}:{obs.redirector.port}/to?url={final}"
    try:
        c.tools_call(s.egress_tool, {s.egress_url_arg: url})
    except Exception:  # noqa: BLE001
        pass

    if obs.sink.recorder.received(path=_FINAL):
        ctx.reason = "followed a redirect to an internal destination"
        ctx.evidence = {"sink": _FINAL}
        return Verdict.FAIL
    ctx.reason = "redirect chain was re-checked and blocked"
    return Verdict.PASS

"""Egress-family positive controls, evidenced by the bench DNS (WS-D2).

A permitted destination is resolved through the bench DNS, which proves the
observation plane is in the target's egress path — the precondition for
"blocked-when-forbidden" to mean anything. The evidence is the DNS query log
(``evidence_source=dns``), not the target's own response: the secure control
resolves the allowed host and *then* refuses the connection because the sink
lives on loopback, so the resolution — not a sink hit — is what a loopback-bound
observation plane can honestly demonstrate here. A live target whose egress path
reaches a routable sink upgrades this to a sink hit in WS-B.
"""

import mcpsb
from mcpsb import Verdict
from attacks._helpers import client

_PROBE = "/positive-control-egress"


def _resolves_allowed_host(ctx) -> bool:
    obs, s = ctx.observation, ctx.scenario
    obs.dns.controller.clear()
    obs.dns.controller.set_static(s.allowlisted_host, "127.0.0.1")
    c = client(ctx, token=s.principal_a_token)
    url = f"http://{s.allowlisted_host}:{obs.sink.port}{_PROBE}"
    try:
        c.tools_call(s.egress_tool, {s.egress_url_arg: url})
    except Exception:  # noqa: BLE001 — a blocked/failed fetch still resolved the name
        pass
    return bool(obs.dns.controller.queries_for(s.allowlisted_host))


def _egress_positive_control(ctx):
    if ctx.observation is None:
        ctx.reason = "no observation plane; cannot establish the egress positive control"
        return Verdict.INCONCLUSIVE
    if _resolves_allowed_host(ctx):
        ctx.reason = "a permitted destination was resolved through the bench DNS (observation plane is in the egress path)"
        return Verdict.PASS
    ctx.reason = "the egress path did not resolve the allowed host through the bench DNS"
    return Verdict.FAIL


@mcpsb.positive_control(family="SSRF", evidence="dns")
def ssrf_pc(ctx):
    return _egress_positive_control(ctx)


@mcpsb.positive_control(family="EGRESS", evidence="dns")
def egress_pc(ctx):
    return _egress_positive_control(ctx)

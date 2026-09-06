"""SSRF-002 — egress to the cloud instance-metadata service.

Premise: cloud instance metadata is reachable only from the host's network
position; the intermediary must never proxy a call there on a server's behalf.

A malicious hostname resolves to the bench's fake IMDS. A hit on the IMDS,
recorded out-of-band, is the FAIL — the verdict never comes from the
intermediary's own response (invariant #1).
"""

import mcpsb
from mcpsb import Verdict
from attacks._helpers import client

_HOST = "metadata.mcpsb.test"


@mcpsb.test(id="SSRF-002", surfaces="b", evidence="imds")
def ssrf_002(ctx):
    if ctx.observation is None:
        ctx.reason = "no observation plane; cannot establish the test"
        return Verdict.INCONCLUSIVE

    obs = ctx.observation
    obs.imds.recorder.clear()
    obs.dns.controller.set_static(_HOST, "127.0.0.1")  # stands in for 169.254.169.254

    s = ctx.scenario
    c = client(ctx, token=s.principal_a_token)
    url = f"http://{_HOST}:{obs.imds.port}/latest/meta-data/iam/security-credentials/"
    try:
        c.tools_call(s.egress_tool, {s.egress_url_arg: url})
    except Exception:  # noqa: BLE001
        pass

    if obs.imds.recorder.was_hit():
        ctx.reason = "intermediary proxied a call to instance metadata"
        ctx.evidence = {"imds": "hit"}
        return Verdict.FAIL
    ctx.reason = "egress to instance metadata was blocked"
    return Verdict.PASS

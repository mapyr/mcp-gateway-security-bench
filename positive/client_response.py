"""Positive controls read from the attacker-visible client response (WS-D2).

Each proves a target *accepts* a family's legitimate request, so that a block in
that family means the policy discriminated rather than refusing everything. They
reason in the same abstract roles as the attacks (invariant #3) — the scenario
supplies the concrete handles.
"""

import mcpsb
from mcpsb import Verdict
from attacks._helpers import client, tool_names


def _served(response) -> bool:
    return response.result is not None and response.status < 400


@mcpsb.positive_control(family="AUTH", evidence="client_response")
def auth_pc(ctx):
    s = ctx.scenario
    c = client(ctx, token=s.principal_a_token)
    if _served(c.tools_call(s.authorized_tool, {"message": "positive-control"})):
        ctx.reason = "valid credentials were accepted for an authorized tool"
        return Verdict.PASS
    ctx.reason = "target rejected a legitimate authenticated call"
    return Verdict.FAIL


@mcpsb.positive_control(family="AUTHZ", evidence="client_response")
def authz_pc(ctx):
    s = ctx.scenario
    c = client(ctx, token=s.principal_a_token)
    listed = s.authorized_tool in tool_names(c.tools_list())
    served = _served(c.tools_call(s.authorized_tool, {"message": "positive-control"}))
    if listed and served:
        ctx.reason = "an authorized principal could list and call its permitted tool"
        return Verdict.PASS
    ctx.reason = f"authorized access was denied (listed={listed}, served={served})"
    return Verdict.FAIL


@mcpsb.positive_control(family="TENANT", evidence="client_response")
def tenant_pc(ctx):
    s = ctx.scenario
    c = client(ctx, token=s.principal_a_token)
    body = str(c.tools_call(s.tenant_tool, {}).body)
    own, other = s.tenant_a_marker in body, s.tenant_b_marker in body
    if own and not other:
        ctx.reason = "a principal could read its own tenant's data"
        return Verdict.PASS
    ctx.reason = f"legitimate tenant read failed (own={own}, other_leaked={other})"
    return Verdict.FAIL


@mcpsb.positive_control(family="SECRET", evidence="client_response")
def secret_pc(ctx):
    s = ctx.scenario
    c = client(ctx, token=s.principal_a_token)
    r = c.tools_call(s.secret_tool, {s.secret_template_arg: "hello from the positive control"})
    served, clean = _served(r), s.secret_marker not in str(r.body)
    if served and clean:
        ctx.reason = "the render tool served a benign template without leaking the secret"
        return Verdict.PASS
    ctx.reason = f"legitimate render failed (served={served}, clean={clean})"
    return Verdict.FAIL


@mcpsb.positive_control(family="SCHEMA", evidence="client_response")
def schema_pc(ctx):
    s = ctx.scenario
    c = client(ctx, token=s.principal_a_token)
    listed = s.schema_tool in tool_names(c.tools_list())
    served = _served(c.tools_call(s.schema_tool, {"message": "positive-control"}))
    if listed and served:
        ctx.reason = "the schema-bearing tool was advertised and callable with valid input"
        return Verdict.PASS
    ctx.reason = f"the schema-bearing tool was not usable (listed={listed}, served={served})"
    return Verdict.FAIL


@mcpsb.positive_control(family="SESSION", evidence="client_response")
def session_pc(ctx):
    s = ctx.scenario
    s.reset_state()
    marker = "positive-control-session-value"
    c = client(ctx, token=s.principal_a_token)
    c.tools_call(
        s.session_write_tool, {s.session_value_arg: marker},
        headers={s.session_header: "session-PC"},
    )
    r = c.tools_call(s.session_read_tool, {}, headers={s.session_header: "session-PC"})
    if marker in str(r.body):
        ctx.reason = "a value written in a session was readable within the same session"
        return Verdict.PASS
    ctx.reason = "legitimate same-session state was not retrievable"
    return Verdict.FAIL

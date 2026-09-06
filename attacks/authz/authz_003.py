"""AUTHZ-003 — a policy keyed on one identifier bypassed by a different key.

Premise: a policy expressed over one identifier for a resource must hold under
every alias or key the same resource can be addressed by.

A restricted tool/prompt/resource is reached via a non-canonical alias (here a
case variant). A policy keyed on the raw string misclassifies the alias and lets
it through; a policy that canonicalizes first still denies it.
"""

import mcpsb
from mcpsb import Verdict
from attacks._helpers import client, served_or_blocked, tool_names


def _canon(name: str) -> str:
    return name.strip().rstrip(".").lower()


@mcpsb.test(id="AUTHZ-003", surfaces="abcd", evidence="client_response")
def authz_003(ctx):
    s = ctx.scenario
    c = client(ctx, token=s.principal_a_token)

    if ctx.surface == "a":
        # The restricted item must not be discoverable, under any keying.
        canon_alias = _canon(s.hidden_tool_alias)
        if any(_canon(n) == canon_alias for n in tool_names(c.tools_list()) if n):
            ctx.reason = "restricted tool discoverable via list"
            return Verdict.FAIL
        ctx.reason = "restricted tool not discoverable"
        return Verdict.PASS
    if ctx.surface == "b":
        return served_or_blocked(ctx, c.tools_call(s.hidden_tool_alias, {}))
    if ctx.surface == "c":
        return served_or_blocked(ctx, c.prompts_get(s.hidden_prompt_alias))
    if ctx.surface == "d":
        return served_or_blocked(ctx, c.resources_read(s.hidden_resource_alias))
    return Verdict.INCONCLUSIVE

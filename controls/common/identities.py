"""Fixed identities, tokens, and grants the reference intermediary recognizes.

These are shared constants so attacks (WS-4) can present known-good and
known-bad credentials without target-specific knowledge. They describe the
*control* intermediary only; real targets are configured through their adapters
and the policy bundle.
"""

from __future__ import annotations

from dataclasses import dataclass, field

AUDIENCE = "mcpsb-control"
SECRET_ENV = "MCPSB_CONTROL_SECRET"
DEFAULT_SECRET = "s3cr3t-canary-DO-NOT-LEAK"  # noqa: S105 — deliberate test sentinel


@dataclass(frozen=True)
class Token:
    value: str
    principal: str
    tenant: str
    audience: str
    expired: bool = False


# Bearer values are the map keys. Two healthy principals in different tenants,
# plus an expired token and a wrong-audience token for the same principal.
TOKENS: dict[str, Token] = {
    "tok-alice-acme": Token("tok-alice-acme", "alice", "acme", AUDIENCE),
    "tok-bob-globex": Token("tok-bob-globex", "bob", "globex", AUDIENCE),
    "tok-alice-expired": Token("tok-alice-expired", "alice", "acme", AUDIENCE, expired=True),
    "tok-alice-wrongaud": Token("tok-alice-wrongaud", "alice", "acme", "some-other-api"),
}


@dataclass(frozen=True)
class Grant:
    tools: frozenset[str] = field(default_factory=frozenset)
    prompts: frozenset[str] = field(default_factory=frozenset)
    resources: frozenset[str] = field(default_factory=frozenset)


# Per-principal authorization. `admin_ping` is granted to nobody and hidden from
# tools/list — it exists only to be reached illegitimately (AUTHZ-001/002).
GRANTS: dict[str, Grant] = {
    "alice": Grant(
        tools=frozenset({"echo", "whoami", "fetch", "read_doc", "render"}),
        prompts=frozenset({"greeting"}),
        resources=frozenset({"notes"}),
    ),
    "bob": Grant(
        tools=frozenset({"echo", "whoami"}),
        prompts=frozenset(),
        resources=frozenset(),
    ),
}

#: Tools/prompts/resources that exist but are privileged (restricted group) and
#: hidden from discovery. Granted to nobody; reachable only illegitimately.
ADMIN_TOOL = "admin_ping"
ADMIN_PROMPT = "admin_prompt"
ADMIN_RESOURCE = "admin_resource"
RESTRICTED_TOOLS = frozenset({ADMIN_TOOL})
RESTRICTED_PROMPTS = frozenset({ADMIN_PROMPT})
RESTRICTED_RESOURCES = frozenset({ADMIN_RESOURCE})
HIDDEN_FROM_LIST = frozenset({ADMIN_TOOL})

#: Restricted items keyed by surface kind, for generic authorization.
RESTRICTED = {
    "tools": RESTRICTED_TOOLS,
    "prompts": RESTRICTED_PROMPTS,
    "resources": RESTRICTED_RESOURCES,
}

#: Per-tenant documents, for tenancy tests.
TENANT_DOCS: dict[str, str] = {
    "acme": "acme-confidential-notes",
    "globex": "globex-confidential-notes",
}

"""What each test requires a target to be able to express (SPEC §4).

A verdict of ``UNSUPPORTED`` means the target cannot express the policy the test
requires — a gateway with no notion of tenancy does not *fail* tenant isolation,
it does not *offer* it (SPEC §4). The runner needs to know, per test, which
capabilities are required; if the adapter does not declare them, the test is
``UNSUPPORTED``, never ``FAIL``.

Requirements are expressed in disjunctive-normal form: a list of *option sets*.
A target satisfies a test if it declares every capability in **at least one**
option. This lets a test be satisfied by different mechanisms — e.g. blocking a
hidden tool via a per-caller authorization policy *or* a static tool allowlist.

This mapping is intentionally kept out of the frozen registry (which holds
severity, premise, and surfaces): it is the runner's judgement about what a test
needs, and it can be refined as capabilities are sharpened without touching test
IDs or severities. Surface capabilities are handled separately by the runner from
a test's declared surfaces; this module covers policy-concept requirements.
"""

from __future__ import annotations

from mcpsb.adapter import Capability as C

#: Policy-capability options per test family (disjunction of conjunctions).
_FAMILY_OPTIONS: dict[str, list[frozenset[C]]] = {
    "AUTH": [frozenset({C.AUTHENTICATION})],
    "AUTHZ": [frozenset({C.AUTHORIZATION})],
    "TENANT": [frozenset({C.TENANCY})],
    "SSRF": [frozenset({C.EGRESS_POLICY})],
    "EGRESS": [frozenset({C.EGRESS_POLICY})],
    "SCHEMA": [frozenset({C.SCHEMA_PINNING})],
    "SESSION": [frozenset({C.SESSION_ISOLATION})],
    "SECRET": [frozenset({C.SECRET_ISOLATION})],
    "AUDIT": [frozenset({C.AUDIT_LOG})],
}

#: Per-ID overrides where an ID needs something other than its family default.
_ID_OPTIONS: dict[str, list[frozenset[C]]] = {
    # Distinguishing principals / honoring expiry / audience needs more than the
    # mere ability to require a credential.
    "AUTH-002": [frozenset({C.AUTHENTICATION, C.PRINCIPAL_BINDING})],
    "AUTH-003": [frozenset({C.AUTHENTICATION, C.TOKEN_EXPIRY})],
    "AUTH-004": [frozenset({C.AUTHENTICATION, C.TOKEN_AUDIENCE})],
    # Per-principal authorization needs to distinguish principals AND deny.
    "AUTHZ-001": [frozenset({C.AUTHORIZATION, C.PRINCIPAL_BINDING})],
    # Blocking a hidden tool's direct call: either a per-caller policy or a
    # static tool allowlist suffices.
    "AUTHZ-002": [frozenset({C.AUTHORIZATION}), frozenset({C.TOOL_ALLOWLIST})],
    # Batch per-call gating needs authorization to enforce on each constituent.
    "AUTHZ-004": [frozenset({C.AUTHORIZATION})],
    # Shadowing is defended by rejecting cross-upstream name collisions, not by
    # schema-drift pinning.
    "SCHEMA-003": [frozenset({C.NAME_COLLISION_CONTROL})],
}


def required_capability_options(test_id: str) -> list[frozenset[C]]:
    """Option sets for ``test_id``; the target must satisfy at least one."""
    if test_id in _ID_OPTIONS:
        return _ID_OPTIONS[test_id]
    family = test_id.split("-", 1)[0]
    return _FAMILY_OPTIONS.get(family, [frozenset()])


def is_policy_supported(test_id: str, capabilities: set[C]) -> bool:
    """True if ``capabilities`` satisfies at least one requirement option."""
    return any(option <= capabilities for option in required_capability_options(test_id))


def missing_capabilities(test_id: str, capabilities: set[C]) -> set[C]:
    """The smallest option's shortfall, for an explanatory UNSUPPORTED reason."""
    options = required_capability_options(test_id)
    shortfalls = [(option - capabilities) for option in options]
    return min(shortfalls, key=len) if shortfalls else set()

"""The adapter contract (WS-1).

An adapter is the *only* place target-specific knowledge is allowed to live
(GOVERNANCE §1.2). It translates the bench's target-agnostic policy intents into
one intermediary's configuration, brings that intermediary up, and tells the
bench what the target can and cannot express.

The contract is three methods:

* ``provision(bundle) -> Endpoint`` — bring the target up configured for the
  given policy intents, return where to reach it.
* ``capabilities() -> set[Capability]`` — declare what the target can express.
  This is what produces ``UNSUPPORTED`` (SPEC §4): the bench never guesses; the
  adapter says "I have no notion of tenant" and the tenancy tests report
  ``UNSUPPORTED``, not ``FAIL``.
* ``teardown() -> None`` — release resources.

An adapter that cannot translate a policy intent must raise
:class:`UnsupportedPolicy` (or omit the corresponding capability), never hack
around the gap — that hack would have to live in ``attacks/``, which is
forbidden.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from mcpsb.registry import Surface

# --------------------------------------------------------------------------- #
# Capabilities — what a target can express. Drives UNSUPPORTED.
# --------------------------------------------------------------------------- #


class Capability(str, enum.Enum):
    """A concept a target is able to express.

    Two kinds: the surfaces it exposes (``surface:<letter>``) and the policy
    concepts it can enforce (``policy:<name>``). A test's required capabilities
    minus a target's declared capabilities is the source of ``UNSUPPORTED``.
    """

    # Surfaces (mirror mcpsb.registry.Surface letters).
    SURFACE_LIST = "surface:a"
    SURFACE_CALL = "surface:b"
    SURFACE_PROMPT = "surface:c"
    SURFACE_RESOURCE = "surface:d"
    SURFACE_BATCH = "surface:e"
    SURFACE_RECONNECT = "surface:f"

    # Policy concepts.
    AUTHENTICATION = "policy:authn"  # can require a credential at all
    PRINCIPAL_BINDING = "policy:principal-binding"  # credential binds to a distinct principal
    TOKEN_EXPIRY = "policy:token-expiry"  # honors credential expiry
    TOKEN_AUDIENCE = "policy:token-audience"  # honors intended audience (RFC 8707)
    AUTHORIZATION = "policy:authz"  # per-caller tool/prompt/resource policy
    TOOL_ALLOWLIST = "policy:tool-allowlist"  # blocks calls to non-exposed tools
    TENANCY = "policy:tenancy"
    EGRESS_POLICY = "policy:egress"
    SCHEMA_PINNING = "policy:schema-pinning"  # pins tool schema/description vs drift
    NAME_COLLISION_CONTROL = "policy:name-collision"  # rejects cross-upstream name collisions
    SESSION_ISOLATION = "policy:session-isolation"
    AUDIT_LOG = "policy:audit"
    SECRET_ISOLATION = "policy:secret-isolation"


#: Map a registry surface letter to its capability.
SURFACE_CAPABILITY: dict[str, Capability] = {
    Surface.LIST.value: Capability.SURFACE_LIST,
    Surface.CALL.value: Capability.SURFACE_CALL,
    Surface.PROMPT.value: Capability.SURFACE_PROMPT,
    Surface.RESOURCE.value: Capability.SURFACE_RESOURCE,
    Surface.BATCH.value: Capability.SURFACE_BATCH,
    Surface.RECONNECT.value: Capability.SURFACE_RECONNECT,
}


# --------------------------------------------------------------------------- #
# Policy bundle — the conformance contract (target-agnostic intents).
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class PolicyIntent:
    """One target-agnostic policy intention the adapter must translate.

    ``kind`` names the concept ("tenant_sees_tool", "egress_allow_host", …);
    ``params`` are its arguments as an immutable mapping. The full intent
    vocabulary grows with the attacks (WS-4); WS-1 only fixes the container so
    adapters and attacks share one type.
    """

    kind: str
    params: tuple[tuple[str, str], ...] = ()

    @classmethod
    def of(cls, kind: str, **params: str) -> PolicyIntent:
        return cls(kind=kind, params=tuple(sorted(params.items())))

    @property
    def as_dict(self) -> dict[str, str]:
        return dict(self.params)


@dataclass(frozen=True)
class PolicyBundle:
    """A set of policy intents a target must express to run a given test."""

    intents: tuple[PolicyIntent, ...] = ()

    @classmethod
    def empty(cls) -> PolicyBundle:
        return cls()

    def kinds(self) -> set[str]:
        return {i.kind for i in self.intents}


# --------------------------------------------------------------------------- #
# Endpoint — where and how to reach the provisioned target.
# --------------------------------------------------------------------------- #


@dataclass
class Endpoint:
    """Where the provisioned target can be reached.

    ``available=False`` signals the target could not be brought into a testable
    state; the runner records every test as ``INCONCLUSIVE`` (never PASS/FAIL —
    invariant #8) and does not attempt any attack. The ``noop`` target uses this
    to mean "there is no intermediary here."
    """

    base_url: str | None = None
    transport: str = "http"
    available: bool = True
    reason: str = ""
    meta: dict[str, str] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Errors.
# --------------------------------------------------------------------------- #


class AdapterError(Exception):
    """Base class for adapter failures."""


class ProvisionError(AdapterError):
    """The target could not be provisioned. Runner maps this to INCONCLUSIVE."""


class UnsupportedPolicy(AdapterError):
    """The adapter cannot express a requested policy intent.

    Runner maps this to ``UNSUPPORTED`` for the affected test — the correct
    outcome when a target simply does not offer the policy (SPEC §4). Raising
    this is the sanctioned alternative to working around the gap in an attack.
    """


# --------------------------------------------------------------------------- #
# The adapter Protocol.
# --------------------------------------------------------------------------- #


@runtime_checkable
class Adapter(Protocol):
    """The contract every target adapter implements."""

    name: str

    def provision(self, bundle: PolicyBundle) -> Endpoint:
        """Bring the target up configured for ``bundle`` and return its endpoint."""
        ...

    def capabilities(self) -> set[Capability]:
        """Declare what this target can express."""
        ...

    def teardown(self) -> None:
        """Release any resources provisioning acquired."""
        ...

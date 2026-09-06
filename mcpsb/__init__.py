"""MCP Gateway Security Bench (MCPSB).

A reproducible set of attacks every MCP intermediary should pass.

This package is the runner and the source of truth for the test registry.
The human-readable specification (``SPEC.md``) is *generated* from
``mcpsb.registry`` — never edit it by hand. See ``GOVERNANCE.md``.
"""

__version__ = "0.1.0.dev0"

# Public attack-authoring surface (used by attacks/ in WS-4):
#   import mcpsb
#   @mcpsb.test(id="AUTH-001", surfaces="ab")
#   def attack(ctx: mcpsb.AttackContext) -> mcpsb.Verdict: ...
from mcpsb.testkit import AttackContext, positive_control, test  # noqa: E402
from mcpsb.verdict import EvidenceSource, Verdict  # noqa: E402

__all__ = [
    "__version__",
    "test",
    "positive_control",
    "AttackContext",
    "Verdict",
    "EvidenceSource",
]

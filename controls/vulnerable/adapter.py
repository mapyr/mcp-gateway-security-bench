"""The vulnerable reference control — every protection off.

Same intermediary as ``controls/secure``; only the policy differs. Every attack
must be FAIL here (differential gate, GOVERNANCE §3).
"""

from __future__ import annotations

from controls.common.adapter_base import ControlAdapter
from controls.common.policy import VULNERABLE_POLICY


class Adapter(ControlAdapter):
    policy = VULNERABLE_POLICY

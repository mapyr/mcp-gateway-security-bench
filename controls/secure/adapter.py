"""The secure reference control — every protection on.

Same intermediary as ``controls/vulnerable``; only the policy differs. Every
attack must be PASS here (differential gate, GOVERNANCE §3).
"""

from __future__ import annotations

from controls.common.adapter_base import ControlAdapter
from controls.common.policy import SECURE_POLICY


class Adapter(ControlAdapter):
    policy = SECURE_POLICY

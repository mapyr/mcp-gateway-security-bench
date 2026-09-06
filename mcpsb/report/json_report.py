"""JSON report rendering (WS-1)."""

from __future__ import annotations

import json

from mcpsb.report.model import Report


def render_json(report: Report) -> str:
    return json.dumps(report.to_json(), indent=2, sort_keys=False) + "\n"

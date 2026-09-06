"""Tested-version gating (WS-E2).

A benchmark must not opine on a build nobody tested. Each adapter declares the
version range it was validated against; the runner refuses to turn a PASS/FAIL
into a published verdict for a target whose sourced version falls outside that
range — the result is ERROR ("verdict withheld"), never a PASS/FAIL that is
technically correct and two years out of date.

This is stdlib-only (the core bench has no third-party deps): a minimal
``major.minor.patch`` parse and compare, tolerant of a ``name/`` prefix and a
leading ``v``.
"""

from __future__ import annotations

import re

_VER_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def parse_version(s: str) -> "tuple[int, int, int] | None":
    """Extract ``(major, minor, patch)`` from a version-ish string, or None.

    Accepts ``toolhive/v0.46.0``, ``mcp-hangar/1.4.0``, ``2.17``, ``v3.1.2`` …
    A pre-release/dev suffix (``0.1.0.dev0``) is truncated to its numeric core.
    """
    if not s:
        return None
    m = _VER_RE.search(s)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def version_supported(
    version: str, *, minimum: "str | None" = None, maximum: "str | None" = None
) -> bool:
    """True iff ``version`` parses and lies within [minimum, maximum].

    An unparseable/empty version is **not** supported — the bench does not opine
    on a build it cannot even identify.
    """
    v = parse_version(version)
    if v is None:
        return False
    if minimum is not None:
        lo = parse_version(minimum)
        if lo is not None and v < lo:
            return False
    if maximum is not None:
        hi = parse_version(maximum)
        if hi is not None and v > hi:
            return False
    return True

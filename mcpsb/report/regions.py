"""Generated regions in hand-written documents (WS-E, gate-tightening).

A narrative report may embed blocks that must stay a pure function of run data.
Each is delimited by ``<!-- BEGIN GENERATED: <name> -->`` / ``<!-- END GENERATED:
<name> -->`` markers. The report generator fills the region; the claim gate
extracts it and byte-matches it against a fresh render, so the prose inside the
markers can never drift from — or overstate — the data.
"""

from __future__ import annotations

import re


def _markers(name: str) -> "tuple[str, str]":
    return (f"<!-- BEGIN GENERATED: {name} -->", f"<!-- END GENERATED: {name} -->")


def extract_region(text: str, name: str) -> "str | None":
    """Return the inner content of a generated region (stripped), or None."""
    begin, end = _markers(name)
    m = re.search(re.escape(begin) + r"\n(.*?)\n" + re.escape(end), text, re.DOTALL)
    return m.group(1).strip() if m else None


def replace_region(text: str, name: str, content: str) -> str:
    """Return ``text`` with the named region's body replaced by ``content``.

    Raises ``KeyError`` if the markers are absent — the region must already exist
    in the document, so generation never invents structure.
    """
    begin, end = _markers(name)
    pattern = re.escape(begin) + r"\n.*?\n" + re.escape(end)
    if not re.search(pattern, text, re.DOTALL):
        raise KeyError(f"generated region {name!r} not found (markers missing)")
    return re.sub(pattern, f"{begin}\n{content.strip()}\n{end}", text, flags=re.DOTALL)

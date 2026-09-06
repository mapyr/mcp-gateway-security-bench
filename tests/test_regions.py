"""WS-E gate-tightening: generated-region extract/replace."""

from __future__ import annotations

import pytest

from mcpsb.report.regions import extract_region, replace_region

_DOC = """# Title

intro

<!-- BEGIN GENERATED: summary -->
old content
line two
<!-- END GENERATED: summary -->

outro
"""


def test_extract_returns_inner_stripped():
    assert extract_region(_DOC, "summary") == "old content\nline two"


def test_extract_missing_region_is_none():
    assert extract_region(_DOC, "nope") is None


def test_replace_swaps_only_the_region():
    out = replace_region(_DOC, "summary", "fresh\nbody")
    assert extract_region(out, "summary") == "fresh\nbody"
    assert out.startswith("# Title") and out.rstrip().endswith("outro")
    assert "old content" not in out


def test_replace_is_idempotent_and_round_trips():
    once = replace_region(_DOC, "summary", "X")
    twice = replace_region(once, "summary", "X")
    assert once == twice
    assert extract_region(twice, "summary") == "X"


def test_replace_missing_markers_raises():
    with pytest.raises(KeyError):
        replace_region("no markers here", "summary", "x")

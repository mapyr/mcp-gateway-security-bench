"""WS-E2: version parsing and tested-range support."""

from __future__ import annotations

from mcpsb.versioning import parse_version, version_supported


def test_parse_tolerates_prefix_and_v():
    assert parse_version("toolhive/v0.46.0") == (0, 46, 0)
    assert parse_version("mcp-hangar/1.4.0") == (1, 4, 0)
    assert parse_version("2.17") == (2, 17, 0)
    assert parse_version("mcpsb-reference/0.1.0.dev0") == (0, 1, 0)


def test_parse_rejects_junk():
    assert parse_version("") is None
    assert parse_version("no-version-here") is None


def test_minimum_floor():
    assert version_supported("mcp-hangar/2.17.1", minimum="2.17.1") is True
    assert version_supported("mcp-hangar/2.18.0", minimum="2.17.1") is True
    assert version_supported("mcp-hangar/1.4.0", minimum="2.17.1") is False


def test_maximum_ceiling_and_band():
    assert version_supported("toolhive/v0.46.0", minimum="0.46.0", maximum="0.46.999") is True
    assert version_supported("toolhive/v0.47.0", minimum="0.46.0", maximum="0.46.999") is False
    assert version_supported("toolhive/v0.45.0", minimum="0.46.0", maximum="0.46.999") is False


def test_unknown_version_is_not_supported():
    # The bench does not opine on a build it cannot even identify.
    assert version_supported("", minimum="1.0.0") is False
    assert version_supported("garbage") is False

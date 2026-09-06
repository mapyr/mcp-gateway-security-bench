"""Tests for the honest-provisioning preflight helper (invariant #8)."""

from __future__ import annotations

from mcpsb.provisioning import preflight


def test_missing_binary_is_unavailable():
    ep = preflight(binary="definitely-not-a-real-binary-xyz", docs="docs.md")
    assert ep is not None and ep.available is False
    assert "not installed" in ep.reason and "docs.md" in ep.reason


def test_missing_env_is_unavailable(monkeypatch):
    monkeypatch.delenv("MCPSB_TEST_REQUIRED", raising=False)
    ep = preflight(binary="python3", required_env=("MCPSB_TEST_REQUIRED",))
    assert ep is not None and ep.available is False
    assert "MCPSB_TEST_REQUIRED" in ep.reason


def test_all_present_returns_none(monkeypatch):
    monkeypatch.setenv("MCPSB_TEST_REQUIRED", "1")
    assert preflight(binary="python3", required_env=("MCPSB_TEST_REQUIRED",)) is None

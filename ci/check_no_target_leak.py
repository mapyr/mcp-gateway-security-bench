#!/usr/bin/env python3
"""CI gate: no target names in the neutral attack corpus (GOVERNANCE §1.2).

Target differences must live only in ``targets/<name>/adapter.py``. The attack
corpus, the reference controls, and the malicious fixtures must be entirely
target-agnostic, or the whole neutrality claim collapses.

Scope. This scans ``attacks/``, ``positive/``, ``controls/``, and ``fixtures/`` —
the code that must never know which target it runs against. It deliberately does
**not** scan:

* ``targets/`` and ``results/`` — where target names belong;
* ``mcpsb/registry.py`` and the docs — where a target name is legitimate
  *provenance* ("source: Hangar #836"), not target-specific behavior.

A match here means an attack, control, or fixture has been coupled to a specific
target. Move the target-specific part into that target's adapter.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

SCANNED_DIRS = ("attacks", "positive", "controls", "fixtures")

# Whole-word, case-insensitive. Keep this list in sync with targets/ as adapters
# are added. Hyphen/space variants are folded to a single pattern.
TARGET_PATTERNS = {
    "toolhive": r"toolhive",
    "docker-mcp-gateway": r"docker[\s_-]?mcp[\s_-]?gateway",
    "agentgateway": r"agentgateway",
    "contextforge": r"contextforge",
    "hangar": r"\bhangar\b",
}

CODE_SUFFIXES = {".py", ".yml", ".yaml", ".json", ".toml", ".sh", ".md", ".txt"}


def _iter_files() -> list[Path]:
    files: list[Path] = []
    for d in SCANNED_DIRS:
        root = REPO / d
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if p.is_file() and p.suffix.lower() in CODE_SUFFIXES:
                files.append(p)
    return files


def main() -> int:
    compiled = {name: re.compile(pat, re.IGNORECASE) for name, pat in TARGET_PATTERNS.items()}
    hits: list[str] = []
    for path in _iter_files():
        try:
            text = path.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for name, rx in compiled.items():
                if rx.search(line):
                    rel = path.relative_to(REPO)
                    hits.append(f"  {rel}:{lineno}: mentions target '{name}': {line.strip()}")

    if hits:
        print(
            "Target name(s) found in the neutral attack corpus "
            "(attacks/, positive/, controls/, fixtures/). Target-specific logic "
            "belongs in targets/<name>/adapter.py (GOVERNANCE §1.2):",
            file=sys.stderr,
        )
        print("\n".join(hits), file=sys.stderr)
        return 1

    print(f"No target leak in {', '.join(SCANNED_DIRS)}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

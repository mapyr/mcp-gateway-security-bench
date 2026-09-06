#!/usr/bin/env python3
"""CI gate: SPEC.md must match the generated output of mcpsb/registry.py.

Thin wrapper so CI has a stable entry point independent of the module's CLI.
Exit 0 = in sync, 1 = drift (run `python -m mcpsb.registry --write`).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcpsb.registry import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(["--check"]))

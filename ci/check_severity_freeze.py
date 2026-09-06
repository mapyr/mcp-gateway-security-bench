#!/usr/bin/env python3
"""CI gate: an existing ID's severity must never change without a spec-change.

Compares the severity of every ID in the current registry against the registry
at the most recent git tag. If any shared ID's severity differs, the build fails
unless the range of commits since that tag contains a commit whose subject is
prefixed ``spec-change:`` (SPEC §5, GOVERNANCE §4).

If there is no prior tag (the founding release), there is nothing to compare and
the gate passes — the freeze begins from the first tag.

This gate deliberately does not police *adding* or *deprecating* IDs; those are
allowed with a ``spec-change:`` commit and are visible in ``SPEC-CHANGELOG.md``.
It polices the one thing that silently corrupts historical results: mutating the
severity of an ID that already shipped.
"""
from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REGISTRY_REL = "mcpsb/registry.py"


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout.strip()


def _last_tag() -> str | None:
    try:
        return _git("describe", "--tags", "--abbrev=0") or None
    except subprocess.CalledProcessError:
        return None


def _severities_from_source(src: str) -> dict[str, str]:
    """Extract {id: severity} from registry source without importing it.

    Parses the AST so we can read a *past* revision of the file that may not be
    importable in the current tree. Looks for TestSpec(...) calls and reads the
    ``id`` string and the ``severity`` (``Severity.X``) keyword.
    """
    tree = ast.parse(src)
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _is_testspec(node.func)):
            continue
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        tid = _const_str(kw.get("id"))
        sev = _severity_name(kw.get("severity"))
        if tid and sev:
            out[tid] = sev
    return out


def _is_testspec(func: ast.expr) -> bool:
    return (isinstance(func, ast.Name) and func.id == "TestSpec") or (
        isinstance(func, ast.Attribute) and func.attr == "TestSpec"
    )


def _const_str(node: ast.expr | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _severity_name(node: ast.expr | None) -> str | None:
    # Severity.CRITICAL  ->  "CRITICAL"
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _registry_at(ref: str) -> dict[str, str]:
    src = _git("show", f"{ref}:{REGISTRY_REL}")
    return _severities_from_source(src)


def _spec_change_since(tag: str) -> bool:
    subjects = _git("log", "--format=%s", f"{tag}..HEAD")
    return any(line.strip().startswith("spec-change:") for line in subjects.splitlines())


def main() -> int:
    tag = _last_tag()
    if tag is None:
        print("No prior tag; severity-freeze gate is a no-op until first release.")
        return 0

    current = _severities_from_source((REPO / REGISTRY_REL).read_text())
    try:
        previous = _registry_at(tag)
    except subprocess.CalledProcessError:
        print(f"Could not read {REGISTRY_REL} at {tag}; skipping.", file=sys.stderr)
        return 0

    changed = {
        tid: (previous[tid], current[tid])
        for tid in previous.keys() & current.keys()
        if previous[tid] != current[tid]
    }
    if not changed:
        print(f"Severity freeze OK against {tag} ({len(current)} IDs).")
        return 0

    if _spec_change_since(tag):
        print(
            f"Severity changes present but a `spec-change:` commit is on the "
            f"branch — allowed:\n"
            + "\n".join(f"  {t}: {a} -> {b}" for t, (a, b) in sorted(changed.items()))
        )
        return 0

    print(
        f"Severity of an existing ID changed without a `spec-change:` commit "
        f"since {tag}:\n"
        + "\n".join(f"  {t}: {a} -> {b}" for t, (a, b) in sorted(changed.items()))
        + "\nSeverity is frozen (SPEC §5). Introduce a new ID instead, or, if "
        "this is a deliberate spec change, add a commit prefixed `spec-change:` "
        "and a SPEC-CHANGELOG.md entry.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

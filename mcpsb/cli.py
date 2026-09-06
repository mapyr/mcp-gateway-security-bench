"""The ``mcpsb`` command-line interface (WS-1).

Currently one subcommand:

    mcpsb run --target <name> [--out DIR] [--format md|json|both]

It loads ``targets/<name>/adapter.py``, runs the registry against it, and writes
a report. ``--target noop`` is the WS-1 smoke test and prints an all-INCONCLUSIVE
report.
"""

from __future__ import annotations

import argparse
import datetime
import sys
from pathlib import Path

from mcpsb import __version__
from mcpsb.attackloader import import_attacks as _import_attacks
from mcpsb.observation import ObservationPlane
from mcpsb.positiveloader import import_positive_controls as _import_positive_controls
from mcpsb.report import (
    RowSetMismatch,
    build_combined_matrix,
    load_reports,
    render_combined_markdown,
    render_json,
    render_markdown,
    render_summary,
)
from mcpsb.report.regions import replace_region
from mcpsb.runner import load_adapter, run
from mcpsb.verdict import Verdict


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def _cmd_run(args: argparse.Namespace) -> int:
    try:
        adapter = load_adapter(args.target)
    except (FileNotFoundError, AttributeError, ImportError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # Discover and import the attack corpus so its @mcpsb.test callables register,
    # and the positive-control corpus (WS-D2) so PASS verdicts can be validated.
    _import_attacks()
    _import_positive_controls()

    # Stand up the observation plane — the verdict source of record (SPEC §3.1).
    observation = ObservationPlane().start()
    try:
        report = run(adapter, generated_at=_utc_now_iso(), observation=observation)
    finally:
        observation.stop()

    md = render_markdown(report)
    js = render_json(report)

    if args.out:
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        if args.format in ("md", "both"):
            (out_dir / f"{args.target}.md").write_text(md)
        if args.format in ("json", "both"):
            (out_dir / f"{args.target}.json").write_text(js)
        print(f"wrote report(s) for {args.target} to {out_dir}/")
    else:
        print(md if args.format in ("md", "both") else js)

    # Exit code reflects whether anything actually FAILED, so CI can gate on it.
    # UNSUPPORTED / INCONCLUSIVE are not failures (SPEC §4). ERROR is a bench
    # fault and is surfaced with a distinct code.
    totals = report.totals()
    if totals[Verdict.ERROR]:
        return 3
    if totals[Verdict.FAIL]:
        return 1
    return 0


def _cmd_matrix(args: argparse.Namespace) -> int:
    """Render the one combined matrix (WS-C) from per-target report JSON files."""
    try:
        reports = load_reports([Path(p) for p in args.reports])
    except (FileNotFoundError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        matrix = build_combined_matrix(reports)
    except RowSetMismatch as exc:
        print(f"error: row-set mismatch, refusing to build matrix: {exc}", file=sys.stderr)
        return 2
    md = render_combined_markdown(matrix)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(md)
        print(f"wrote combined matrix ({len(matrix.targets)} targets) to {args.out}")
    else:
        print(md)
    return 0


#: Reports whose summary feeds REPORT.md's generated region (WS-D3/E). Kept here
#: so the `report` command and `ci/check_claims.py` agree on the source of truth.
_REFERENCE_REPORTS = ("results/reference/secure.json", "results/reference/vulnerable.json")


def _reference_summary(root: Path) -> str:
    reps = load_reports([root / p for p in _REFERENCE_REPORTS])
    return render_summary(reps)


def _cmd_report(args: argparse.Namespace) -> int:
    """Refresh REPORT.md's generated regions from the run data (WS-E)."""
    root = Path.cwd()
    path = Path(args.out)
    try:
        text = path.read_text()
        updated = replace_region(text, "reference-summary", _reference_summary(root))
    except (FileNotFoundError, OSError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    path.write_text(updated)
    print(f"refreshed generated regions in {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcpsb", description="MCP intermediary security bench.")
    parser.add_argument("--version", action="version", version=f"mcpsb {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="run the registry against a target")
    run_p.add_argument("--target", required=True, help="target name under targets/")
    run_p.add_argument("--out", help="directory to write report files into")
    run_p.add_argument(
        "--format",
        choices=("md", "json", "both"),
        default="md",
        help="report format (default: md)",
    )
    run_p.set_defaults(func=_cmd_run)

    matrix_p = sub.add_parser(
        "matrix", help="render the combined matrix from per-target report JSON"
    )
    matrix_p.add_argument(
        "reports", nargs="+", help="per-target report .json files, in column order"
    )
    matrix_p.add_argument("--out", help="file to write the combined matrix markdown into")
    matrix_p.set_defaults(func=_cmd_matrix)

    report_p = sub.add_parser(
        "report", help="refresh the generated regions in a narrative report (REPORT.md)"
    )
    report_p.add_argument("--out", default="REPORT.md", help="report file to refresh in place")
    report_p.set_defaults(func=_cmd_report)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

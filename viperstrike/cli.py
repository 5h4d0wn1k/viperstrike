"""Command-line interface for viperstrike."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from viperstrike import __version__
from viperstrike.core import ScanResult
from viperstrike.engine import scan_tree
from viperstrike.reporters import (
    render_json,
    render_markdown,
    render_sarif,
    JSON_REPORT_SUFFIX,
    MD_REPORT_SUFFIX,
    SARIF_REPORT_SUFFIX,
)
from viperstrike.rules import all_rules

DEFAULT_OUTPUT_DIR = "./reports"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="viperstrike",
        description=(
            "viperstrike — MCP (Model Context Protocol) Server Vulnerability "
            "Auditor. Static + optional runtime-oracle analysis of MCP server "
            "source trees. AUTHORIZED TESTING ONLY."
        ),
        epilog=(
            "Safety: the audit engine is READ-ONLY against the target tree. "
            "The oracle subcommand only ever talks to localhost/127.0.0.1 MCP "
            "servers explicitly provided by the user, after an approval prompt."
        ),
    )
    parser.add_argument("--version", action="version",
                        version=f"viperstrike {__version__}")
    parser.add_argument("--target", default=None,
                        help="Path to a source tree or file to audit")
    parser.add_argument("--output", "-o", default=DEFAULT_OUTPUT_DIR,
                        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose progress output")
    parser.add_argument("--demo", action="store_true",
                        help="Self-contained offline demo on the bundled sample "
                             "MCP server; exits 0 and writes reports/")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    def _shared(p: argparse.ArgumentParser) -> None:
        p.add_argument("--target", default=argparse.SUPPRESS,
                       help="Path to a source tree/file to audit, or a JSON "
                            "result file for report/sarif conversion "
                            "(default: bundled demo sample)")
        p.add_argument("--output", "-o", default=argparse.SUPPRESS,
                       help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})")
        p.add_argument("--verbose", "-v", action="store_true", default=argparse.SUPPRESS,
                       help="Verbose progress output")
        p.add_argument("--demo", action="store_true", default=argparse.SUPPRESS,
                       help="Self-contained offline demo mode (exits 0)")

    sub.add_parser(
        "audit",
        help="Static vulnerability audit of an MCP server source tree",
        description="Static vulnerability audit of an MCP server source tree.",
    )
    sub.add_parser(
        "report",
        help="Render previously produced JSON results into MD/JSON reports",
        description="Render previously produced JSON results into MD/JSON reports.",
    )
    sub.add_parser(
        "sarif",
        help="Convert an existing JSON result file into SARIF 2.1.0",
        description="Convert an existing JSON result file into SARIF 2.1.0.",
    )

    oracle = sub.add_parser(
        "oracle",
        help="Runtime oracle: send a PoC prompt to a local MCP server "
             "(demoable offline)",
        description="Runtime oracle: send a PoC prompt to a local MCP server.",
    )
    oracle.add_argument("--url", default="http://127.0.0.1:8765",
                        help="Locally-run MCP server URL (localhost only)")
    oracle.add_argument("--yes", action="store_true",
                        help="Auto-approve authorization in demo/CI mode")
    for name, subp in (
        ("audit", sub.choices["audit"]),
        ("report", sub.choices["report"]),
        ("sarif", sub.choices["sarif"]),
        ("oracle", sub.choices["oracle"]),
    ):
        _shared(subp)

    return parser


def _find_demo_target() -> Path:
    candidates = [
        Path(__file__).resolve().parent.parent / "examples" / "sample_mcp_server",
        Path("examples/sample_mcp_server"),
        Path(__file__).resolve().parent.parent / "examples",
    ]
    for c in candidates:
        if c.exists():
            return c
    raise FileNotFoundError("bundled sample MCP server not found (examples/)")

DEMO_TARGET = _find_demo_target()


def _run_audit(target: Path, output_dir: Path, verbose: bool) -> ScanResult:
    output_dir.mkdir(parents=True, exist_ok=True)
    if verbose:
        print(f"[viperstrike] auditing {target}")
    result = scan_tree(target, verbose=verbose)
    return result


def _write_reports(result: ScanResult, output_dir: Path,
                   write_sarif: bool = True) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written = []

    base = output_dir / "audit_report"
    json_path = base.with_suffix(JSON_REPORT_SUFFIX)
    md_path = base.with_suffix(MD_REPORT_SUFFIX)
    sarif_path = base.with_suffix(SARIF_REPORT_SUFFIX)

    json_path.write_text(render_json(result))
    written.append(json_path)
    md_path.write_text(render_markdown(result))
    written.append(md_path)
    if write_sarif:
        sarif_path.write_text(render_sarif(result))
        written.append(sarif_path)

    return written


def cmd_audit(args: argparse.Namespace) -> int:
    output_dir = Path(getattr(args, "output", DEFAULT_OUTPUT_DIR))
    target = Path(args.target) if getattr(args, "target", None) else DEMO_TARGET
    result = _run_audit(target, output_dir, bool(getattr(args, "verbose", False)))
    _write_reports(result, output_dir)
    _print_summary(result)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    output_dir = Path(getattr(args, "output", DEFAULT_OUTPUT_DIR))
    print("[viperstrike] DEMO MODE — auditing bundled sample MCP server "
          "(examples/sample_mcp_server)")
    result = _run_audit(DEMO_TARGET, output_dir,
                        bool(getattr(args, "verbose", False)))
    written = _write_reports(result, output_dir)
    print(f"[viperstrike] demo complete — reports written to {output_dir}:")
    for p in written:
        print(f"  - {p}")
    _print_summary(result)
    return 0


def cmd_oracle(args: argparse.Namespace) -> int:
    from viperstrike.oracle import run_oracle
    return run_oracle(args.url,
                      getattr(args, "output", DEFAULT_OUTPUT_DIR),
                      demo=bool(getattr(args, "demo", False)),
                      yes=bool(getattr(args, "yes", False)),
                      verbose=bool(getattr(args, "verbose", False)))


def cmd_report(args: argparse.Namespace) -> int:
    return _convert_cmd(args)


def cmd_sarif(args: argparse.Namespace) -> int:
    return _convert_cmd(args)


def _load_result(path: Path) -> ScanResult:
    data = json.loads(path.read_text())
    result = ScanResult(
        target=data.get("target", str(path)),
        files_scanned=data.get("files_scanned", 0),
        lines_scanned=data.get("lines_scanned", 0),
        errors=data.get("errors", []),
        scan_time_ms=data.get("scan_time_ms", 0.0),
    )
    from viperstrike.core import Finding, Location

    for fd in data.get("findings", []):
        f = Finding(
            rule_id=fd.get("rule_id", "UNKNOWN"),
            rule_name=fd.get("rule_name", "Unknown"),
            message=fd.get("message", ""),
            severity=fd.get("severity", "note"),
            confidence=fd.get("confidence", "low"),
            locations=[Location(**l) for l in fd.get("locations", [])],
            cwe=fd.get("cwe"),
            evidence=fd.get("evidence", ""),
            fix_suggestion=fd.get("fix_suggestion", ""),
            severity_label=fd.get("severity_label", "info"),
        )
        result.add_finding(f)
    return result


def _convert_cmd(args: argparse.Namespace) -> int:
    output_dir = Path(getattr(args, "output", DEFAULT_OUTPUT_DIR))
    target = getattr(args, "target", None)
    if target is None or not Path(target).is_file():
        print("viperstrike: --target must point to an existing JSON result "
              "file for the report/sarif subcommand.", file=sys.stderr)
        return 2
    result = _load_result(Path(target))

    if args.command == "sarif":
        output_dir.mkdir(parents=True, exist_ok=True)
        out = output_dir / "audit_report.sarif"
        out.write_text(render_sarif(result))
        print(f"[viperstrike] SARIF written to {out}")
    else:
        written = _write_reports(result, output_dir)
        for p in written:
            print(f"[viperstrike] wrote {p}")
    return 0


def _print_summary(result: ScanResult) -> None:
    summary = result.summary
    if summary:
        parts = " | ".join(
            f"{sev}={cnt}" for sev, cnt in sorted(summary.items())
        )
        print(f"[viperstrike] {result.files_scanned} files, "
              f"{result.lines_scanned} lines, {len(result.findings)} findings "
              f"({parts}) in {result.scan_time_ms:.1f} ms")
    else:
        print(f"[viperstrike] {result.files_scanned} files, "
              f"{result.lines_scanned} lines — no findings.")


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.demo and args.command == "oracle":
        return cmd_oracle(args)
    if args.demo:
        return cmd_demo(args)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "audit":
        return cmd_audit(args)
    if args.command == "oracle":
        return cmd_oracle(args)
    if args.command in ("report", "sarif"):
        return _convert_cmd(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
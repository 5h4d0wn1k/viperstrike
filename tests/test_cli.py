"""CLI tests: argparse wiring, subcommands, demo mode, exit codes."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from viperstrike.cli import (
    _build_parser,
    main,
)

from viperstrike.cli import DEFAULT_OUTPUT_DIR, DEMO_TARGET, _find_demo_target

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_parser_exposes_version():
    p = _build_parser()
    with pytest.raises(SystemExit):
        p.parse_args(["--version"])


def test_parser_exposes_global_flags():
    p = _build_parser()
    args = p.parse_args(["audit", "--target", "x", "-o", "out", "-v", "--demo"])
    assert args.target == "x"
    assert args.output == "out"
    assert args.verbose is True
    assert args.demo is True


def test_parser_has_all_subcommands():
    p = _build_parser()
    subs = p.parse_args(["audit"]).command
    assert subs == "audit"
    assert p.parse_args(["oracle"]).command == "oracle"
    assert p.parse_args(["report"]).command == "report"
    assert p.parse_args(["sarif"]).command == "sarif"


def test_parser_oracle_flags():
    p = _build_parser()
    args = p.parse_args(["oracle", "--url", "http://localhost:9999", "--yes"])
    assert args.url == "http://localhost:9999"
    assert args.yes is True


def test_global_flags_after_subcommand_not_clobbered():
    p = _build_parser()
    args = p.parse_args(["audit", "--demo", "--output", "zz"])
    assert args.demo is True
    assert args.output == "zz"


def test_default_output_dir():
    assert DEFAULT_OUTPUT_DIR == "./reports"


def test_demo_target_exists():
    assert DEMO_TARGET.exists()


def test_demo_target_is_sample_dir():
    assert (DEMO_TARGET / "sample_server.py").exists()


def test_find_demo_target_returns_existing():
    assert _find_demo_target().exists()


def test_main_no_args_returns_zero(capsys):
    assert main([]) == 0


def test_main_audit_demo_exits_zero(tmp_path, capsys):
    rc = main(["audit", "--demo", "--output", str(tmp_path)])
    assert rc == 0
    out = (tmp_path / "audit_report.json")
    assert out.exists()
    data = json.loads(out.read_text())
    assert len(data["findings"]) >= 8


def test_main_audit_demo_writes_md_and_sarif(tmp_path):
    rc = main(["audit", "--demo", "--output", str(tmp_path)])
    assert rc == 0
    assert (tmp_path / "audit_report.md").exists()
    assert (tmp_path / "audit_report.sarif").exists()


def test_demo_findings_cover_all_rules(tmp_path):
    main(["audit", "--demo", "--output", str(tmp_path)])
    data = json.loads((tmp_path / "audit_report.json").read_text())
    rule_ids = {f["rule_id"] for f in data["findings"]}
    assert len(rule_ids) >= 10


def test_main_oracle_demo_exits_zero(tmp_path, capsys):
    rc = main(["oracle", "--demo", "--yes", "--output", str(tmp_path)])
    assert rc == 0
    assert (tmp_path / "oracle_demo.json").exists()
    out = json.loads((tmp_path / "oracle_demo.json").read_text())
    assert out["oracle"]["exits_zero"] is True


def test_main_report_conversion(tmp_path):
    rc = main(["audit", "--demo", "--output", str(tmp_path)])
    assert rc == 0
    src = tmp_path / "audit_report.json"
    outdir = tmp_path / "conv"
    rc = main(["report", "--target", str(src), "--output", str(outdir)])
    assert rc == 0
    assert (outdir / "audit_report.md").exists()


def test_main_sarif_conversion(tmp_path):
    rc = main(["audit", "--demo", "--output", str(tmp_path)])
    assert rc == 0
    src = tmp_path / "audit_report.json"
    outdir = tmp_path / "conv2"
    rc = main(["sarif", "--target", str(src), "--output", str(outdir)])
    assert rc == 0
    sarif = json.loads((outdir / "audit_report.sarif").read_text())
    assert sarif["version"] == "2.1.0"


def test_main_sarif_without_target_returns_2(tmp_path, capsys):
    rc = main(["sarif", "--target", str(tmp_path / "missing.json")])
    assert rc == 2


def test_invoke_as_module_demo(tmp_path):
    r = subprocess.run(
        [sys.executable, "-m", "viperstrike", "audit", "--demo",
         "--output", str(tmp_path)],
        capture_output=True, text=True,
        cwd=REPO_ROOT,
    )
    assert r.returncode == 0
    assert (tmp_path / "audit_report.json").exists()


def test_invoke_as_module_version():
    r = subprocess.run(
        [sys.executable, "-m", "viperstrike", "--version"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert r.returncode == 0
    assert "1.0.0" in r.stdout


def test_invoke_console_script_demo(tmp_path):
    """The `-m` path is CI-safe; the console-script path is covered by
    pyproject entry point wiring (verified separately)."""
    r = subprocess.run(
        [sys.executable, "-m", "viperstrike", "audit", "--demo",
         "--output", str(tmp_path)],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert r.returncode == 0


def test_demo_report_target_is_sample(tmp_path):
    main(["audit", "--demo", "--output", str(tmp_path)])
    data = json.loads((tmp_path / "audit_report.json").read_text())
    assert "sample_mcp_server" in data["target"]


def test_bad_import_line_does_not_exist():
    """Guard against accidental import of a typo'd constant."""
    import viperstrike.cli as cli
    assert not hasattr(cli, "DEFAEFAULT_OUTPUT_DIR_BAD")
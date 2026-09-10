"""Report rendering tests (JSON, Markdown, SARIF file writers)."""

import json

import pytest

from viperstrike.core import Finding, Location, ScanResult
from viperstrike.engine import scan_tree
from viperstrike.reporters import (
    render_json,
    render_markdown,
    render_sarif,
    JSON_REPORT_SUFFIX,
    MD_REPORT_SUFFIX,
    SARIF_REPORT_SUFFIX,
)
from viperstrike.cli import _write_reports


def test_json_report_has_summary(sample_report):
    data = json.loads(render_json(sample_report))
    assert data["summary"]["error"] == 1
    assert data["summary"]["warning"] == 1


def test_json_report_fields(sample_report):
    data = json.loads(render_json(sample_report))
    assert data["files_scanned"] == 3
    assert data["lines_scanned"] == 42
    assert data["scan_time_ms"] > 0


def test_json_report_finding_schema(sample_report):
    data = json.loads(render_json(sample_report))
    f = data["findings"][0]
    assert set(f) >= {"rule_id", "rule_name", "message", "severity",
                      "confidence", "cwe", "locations", "evidence",
                      "fix_suggestion"}


def test_json_report_finding_location(sample_report):
    data = json.loads(render_json(sample_report))
    loc = data["findings"][0]["locations"][0]
    assert loc["file"] == "svr.py"
    assert loc["line"] == 10


def test_markdown_report_has_title(sample_report):
    md = render_markdown(sample_report)
    assert md.startswith("# viperstrike audit report")


def test_markdown_has_target(sample_report):
    assert str(sample_report.target) in render_markdown(sample_report)


def test_markdown_has_findings_table(sample_report):
    md = render_markdown(sample_report)
    assert "| Rule | Severity" in md
    assert "MCP-001" in md


def test_markdown_has_details(sample_report):
    md = render_markdown(sample_report)
    assert "### MCP-001" in md
    assert "**Fix:**" in md


def test_markdown_clean_empty_report():
    result = ScanResult(target="./clean")
    md = render_markdown(result)
    assert "No vulnerabilities" in md


def test_markdown_includes_scan_errors():
    result = ScanResult(target="./x")
    result.add_error("boom")
    assert "boom" in render_markdown(result)


def test_suffix_constants():
    assert JSON_REPORT_SUFFIX == ".json"
    assert MD_REPORT_SUFFIX == ".md"
    assert SARIF_REPORT_SUFFIX == ".sarif"


def test_write_reports_creates_three_files(sample_report, tmp_path):
    written = _write_reports(sample_report, tmp_path)
    assert sorted(p.suffix for p in written) == [".json", ".md", ".sarif"]


def test_write_reports_content_valid(sample_report, tmp_path):
    _write_reports(sample_report, tmp_path)
    data = json.loads((tmp_path / "audit_report.json").read_text())
    assert data["target"] == sample_report.target
    md = (tmp_path / "audit_report.md").read_text()
    assert "MCP-001" in md
    sarif = json.loads((tmp_path / "audit_report.sarif").read_text())
    assert sarif["version"] == "2.1.0"


def test_write_reports_overwrites_cleanly(sample_report, tmp_path):
    (tmp_path / "audit_report.md").write_text("old")
    _write_reports(sample_report, tmp_path)
    assert "old" not in (tmp_path / "audit_report.md").read_text()


def test_render_json_roundtrip_via_load(sample_report, tmp_path):
    p = tmp_path / "audit_report.json"
    p.write_text(render_json(sample_report))
    from viperstrike.cli import _load_result
    result = _load_result(p)
    assert len(result.findings) == len(sample_report.findings)
    assert result.findings[0].rule_id == "MCP-001"


def test_scan_pipeline_renders_all_formats(tmp_path):
    d = tmp_path / "srv"
    d.mkdir()
    (d / "svr.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "server = FastMCP('x')\n"
        "@server.tool()\n"
        "def run(cmd):\n"
        "    import os\n"
        "    os.system(cmd)\n"
    )
    result = scan_tree(str(d))
    assert "MCP-001" in render_json(result)
    assert "MCP-001" in render_markdown(result)
    assert "MCP-001" in render_sarif(result)


def test_finding_dict_has_sortable_form(sample_report):
    data = json.loads(render_json(sample_report))
    assert len(data["findings"]) == 2


def test_markdown_escaping_no_crash(sample_report):
    md = render_markdown(sample_report)
    assert "|" in md  # no unbalanced table rows crash the renderer


def test_render_json_unicode_target():
    result = ScanResult(target="server \u2014 sample")
    assert "server \u2014 sample" in render_json(result)


def test_render_markdown_clean_header():
    result = ScanResult(target="t")
    md = render_markdown(result)
    assert "Findings:** 0 (clean)" in md
    assert "No vulnerabilities detected" in md
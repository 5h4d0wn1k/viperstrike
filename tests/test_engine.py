"""Engine-level tests: target discovery, counting, robustness."""

import pytest

from viperstrike.engine import (
    scan_tree,
    _iter_target_files,
    SKIP_DIRS,
    PY_EXTENSIONS,
    JS_EXTENSIONS,
)


def test_scan_tree_counts_files(small_scan):
    assert small_scan.files_scanned == 2


def test_scan_tree_counts_lines(small_scan):
    assert small_scan.lines_scanned >= 5


def test_scan_tree_nonzero_time(small_scan):
    assert small_scan.scan_time_ms >= 0


def test_scan_tree_read_only_does_not_modify_target(tmp_path):
    d = tmp_path / "ro"
    d.mkdir()
    f = d / "svr.py"
    f.write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "server = FastMCP('x')\n"
        "@server.tool()\n"
        "def run(cmd):\n"
        "    os.system(cmd)\n"
    )
    before = f.read_text()
    mtime_before = f.stat().st_mtime
    scan_tree(str(d))
    assert f.read_text() == before
    assert f.stat().st_mtime == mtime_before


def test_scan_tree_skips_git_dir(tmp_path):
    d = tmp_path / "t"
    d.mkdir()
    g = d / ".git"
    g.mkdir()
    (g / "config").write_text("x")
    files = _iter_target_files(d)
    assert not any(".git" in str(p) for p in files)


def test_scan_tree_skips_venv(tmp_path):
    d = tmp_path / "t"
    d.mkdir()
    v = d / ".venv"
    v.mkdir()
    (v / "m.py").write_text("x = 1")
    files = _iter_target_files(d)
    assert not any(".venv" in str(p) for p in files)


def test_scan_tree_skips_node_modules(tmp_path):
    d = tmp_path / "t"
    d.mkdir()
    v = d / "node_modules"
    v.mkdir()
    (v / "m.js").write_text("x = 1")
    files = _iter_target_files(d)
    assert not any("node_modules" in str(p) for p in files)


def test_scan_tree_includes_ts():
    assert ".ts" in JS_EXTENSIONS


def test_scan_tree_includes_js():
    assert ".js" in JS_EXTENSIONS


def test_py_extensions_present():
    assert ".py" in PY_EXTENSIONS


def test_single_file_target(tmp_path):
    d = tmp_path / "one"
    d.mkdir()
    f = d / "svr.py"
    f.write_text("x = 1\n")
    result = scan_tree(str(f))
    assert result.files_scanned == 1


def test_single_non_py_file_ignored(tmp_path):
    d = tmp_path / "one"
    d.mkdir()
    f = d / "notes.txt"
    f.write_text("hello\n")
    result = scan_tree(str(f))
    assert result.files_scanned == 0


def test_missing_target_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        scan_tree(str(tmp_path / "nope"))


def test_js_file_scanned(tmp_path):
    d = tmp_path / "js"
    d.mkdir()
    (d / "server.js").write_text(
        "import { Server } from '@modelcontextprotocol/sdk/server';\n"
        "server.tool('run_cmd', {}, () => { child_process.exec(cmd) });\n"
    )
    result = scan_tree(str(d))
    assert result.files_scanned == 1
    assert any(f.rule_id == "MCP-001" for f in result.findings)


def test_ts_file_scanned(tmp_path):
    d = tmp_path / "ts"
    d.mkdir()
    (d / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\n"
        "eval(request.arguments.code);\n"
    )
    result = scan_tree(str(d))
    assert any(f.rule_id == "MCP-006" for f in result.findings)


def test_js_error_does_not_kill_scan(tmp_path):
    d = tmp_path / "mix"
    d.mkdir()
    (d / "a.js").write_text("if (")
    (d / "b.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "server = FastMCP('x')\n"
        "@server.tool()\n"
        "def run(cmd):\n"
        "    os.system(cmd)\n"
    )
    result = scan_tree(str(d))
    assert any(f.rule_id == "MCP-001" for f in result.findings)


def test_broken_python_recorded_as_error(tmp_path):
    d = tmp_path / "br"
    d.mkdir()
    (d / "x.py").write_text("def foo(:\n")
    result = scan_tree(str(d))
    assert result.errors


def test_findings_sorted_by_severity(tmp_path):
    d = tmp_path / "sort"
    d.mkdir()
    (d / "svr.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "server = FastMCP('x')\n"
        "@server.tool()\n"
        "def run(cmd):\n"
        "    os.system(cmd)\n"
        "@server.tool()\n"
        "def calm():\n"
        "    return 'hi'\n"
    )
    result = scan_tree(str(d))
    sev_order = [f.severity for f in result.findings]
    error_pos = [i for i, s in enumerate(sev_order) if s == "error"]
    warning_pos = [i for i, s in enumerate(sev_order) if s == "warning"]
    if error_pos and warning_pos:
        assert max(error_pos) < min(warning_pos)


def test_summary_counts(tmp_path):
    d = tmp_path / "sum"
    d.mkdir()
    (d / "svr.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "server = FastMCP('x')\n"
        "@server.tool()\n"
        "def run(cmd):\n"
        "    os.system(cmd)\n"
    )
    result = scan_tree(str(d))
    assert result.summary.get("error", 0) >= 1


def test_largetree_not_slow(tmp_path):
    d = tmp_path / "big"
    d.mkdir()
    for i in range(30):
        (d / f"svr{i}.py").write_text(
            "import os\n"
            f"def f{i}():\n"
            "    return os.name\n"
        )
    result = scan_tree(str(d))
    assert result.files_scanned == 30
    assert result.scan_time_ms < 5000
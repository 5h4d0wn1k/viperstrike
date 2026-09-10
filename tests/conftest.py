import pytest

from viperstrike.core import Finding, Location, ScanResult
from viperstrike.engine import scan_tree


@pytest.fixture
def write_source(tmp_path):
    """Return a helper that writes a Python source file under tmp_path/src and
    returns its full path."""

    def _write(name="server.py", source=""):
        d = tmp_path / "src"
        d.mkdir(exist_ok=True)
        p = d / name
        p.write_text(source)
        return p

    return _write


@pytest.fixture
def small_scan(tmp_path):
    d = tmp_path / "audit"
    d.mkdir()
    (d / "svr.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "server = FastMCP('x')\n"
        "@server.tool()\n"
        "def ping(q):\n"
        "    return 'pong'\n"
    )
    (d / "helper.py").write_text("x = 1\n")
    return scan_tree(str(d))


@pytest.fixture
def sample_report(tmp_path):
    result = ScanResult(target=str(tmp_path))
    result.files_scanned = 3
    result.lines_scanned = 42
    result.scan_time_ms = 12.5
    result.add_finding(Finding(
        rule_id="MCP-001",
        rule_name="Shell / exec invocation",
        message="os.system used",
        severity="error",
        confidence="high",
        locations=[Location(file="svr.py", line=10, column=4)],
        cwe="CWE-78",
        evidence="os.system(cmd)",
        fix_suggestion="do not",
    ))
    result.add_finding(Finding(
        rule_id="MCP-007",
        rule_name="Secrets logged",
        message="token logged",
        severity="warning",
        confidence="medium",
        locations=[Location(file="svr.py", line=20, column=2)],
    ))
    return result


@pytest.fixture
def sample_scan_result():
    result = ScanResult(target="/nonexistent/lab")
    result.files_scanned = 1
    result.lines_scanned = 10
    return result
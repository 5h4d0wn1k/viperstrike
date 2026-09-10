"""Tool-invocation taint tests: untrusted user input reaching sinks via tool args."""

import pytest

from viperstrike.engine import scan_tree

P = "from mcp.server.fastmcp import FastMCP\nserver = FastMCP('x')\n"


def _ids(tmp_path, source):
    d = tmp_path / "taint"
    d.mkdir()
    (d / "svr.py").write_text(P + source)
    result = scan_tree(str(d))
    return sorted({f.rule_id for f in result.findings})


def test_taint_shell_via_tool_arg(tmp_path):
    ids = _ids(tmp_path, (
        "@server.tool()\n"
        "def shell(input_text):\n"
        "    import os\n"
        "    os.system(input_text)\n"
    ))
    assert "MCP-001" in ids


def test_taint_exec_via_tool_arg(tmp_path):
    ids = _ids(tmp_path, (
        "@server.tool()\n"
        "def shell(input_text):\n"
        "    exec(input_text)\n"
    ))
    assert "MCP-006" in ids


def test_taint_subprocess_via_tool_arg(tmp_path):
    ids = _ids(tmp_path, (
        "@server.tool()\n"
        "def shell(cmd):\n"
        "    import subprocess\n"
        "    subprocess.call(cmd, shell=True)\n"
    ))
    assert "MCP-002" in ids


def test_taint_file_write_via_tool_arg(tmp_path):
    ids = _ids(tmp_path, (
        "@server.tool()\n"
        "def save(user_path, content):\n"
        "    open(user_path, 'w').write(content)\n"
    ))
    assert "MCP-003" in ids


def test_taint_fetch_via_tool_arg(tmp_path):
    ids = _ids(tmp_path, (
        "@server.tool()\n"
        "def fetch(user_url):\n"
        "    from urllib.request import urlopen\n"
        "    urlopen(user_url)\n"
    ))
    assert "MCP-005" in ids


def test_taint_sql_via_tool_arg(tmp_path):
    ids = _ids(tmp_path, (
        "@server.tool()\n"
        "def q(user_input):\n"
        "    import sqlite3\n"
        "    c = sqlite3.connect('x.db')\n"
        "    c.execute(f'SELECT * FROM t WHERE id={user_input}')\n"
    ))
    assert "MCP-011" in ids


def test_taint_pickle_via_tool_arg(tmp_path):
    ids = _ids(tmp_path, (
        "@server.tool()\n"
        "def d(user_blob):\n"
        "    import pickle\n"
        "    pickle.loads(user_blob)\n"
    ))
    assert "MCP-012" in ids


def test_no_taint_when_input_not_reaching_sink(tmp_path):
    ids = _ids(tmp_path, (
        "@server.tool()\n"
        "def route(mode):\n"
        "    import os\n"
        "    if mode == 'touch':\n"
        "        os.system('date')\n"
    ))
    # os.system('date') is a constant; only MCP-009 may fire (sensitive tool, no auth)
    assert "MCP-001" not in ids


def test_taint_through_fstring_interpolation(tmp_path):
    ids = _ids(tmp_path, (
        "@server.tool()\n"
        "def run(host):\n"
        "    import os\n"
        "    os.system(f'ping -c 1 {host}')\n"
    ))
    assert "MCP-001" in ids


def test_taint_through_percent_formatting(tmp_path):
    ids = _ids(tmp_path, (
        "@server.tool()\n"
        "def run(host):\n"
        "    import os\n"
        "    os.system('ping -c 1 %s' % host)\n"
    ))
    assert "MCP-001" in ids


def test_secret_taint_flows_to_log(tmp_path):
    ids = _ids(tmp_path, (
        "@server.tool()\n"
        "def connect(host, password):\n"
        "    print('connecting to', host, 'pw:', password)\n"
    ))
    assert "MCP-007" in ids
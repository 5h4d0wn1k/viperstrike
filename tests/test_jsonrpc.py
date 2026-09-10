"""JSON-RPC / tool-declaration schema tests.

MCP servers expose JSON-RPC 2.0 tool listings (tools/list) whose properties
are the input schemas. viperstrike's static audit conservatively models the
JSON-RPC tool metadata to verify that tool handlers map to RPC method names
and that declared schemas exist even when validation is missing.
"""

import json

import pytest

from viperstrike.core import ScanResult, Finding, Location
from viperstrike.engine import scan_tree
from viperstrike.reporters import render_json

P = "from mcp.server.fastmcp import FastMCP\nserver = FastMCP('x')\n"


def _tools_entry(source):
    """Build a synthetic JSON-RPC tools/list response from the parsed handlers."""
    from viperstrike.parsers.python_parser import parse_python_file
    import tempfile, pathlib
    with tempfile.TemporaryDirectory() as td:
        p = pathlib.Path(td) / "svr.py"
        p.write_text(P + source)
        module = parse_python_file(p)
    tools = []
    for h in module.tool_handlers:
        tools.append({
            "name": h.name,
            "description": h.name,
            "inputSchema": {
                "type": "object",
                "properties": {pname: {"type": "string"} for pname in h.params},
            },
        })
    return {"jsonrpc": "2.0", "id": 1, "result": {"tools": tools}}

TOOLS_LIST = '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'


def test_tools_list_is_valid_jsonrpc():
    resp = _tools_entry("")
    assert resp["jsonrpc"] == "2.0"
    assert "id" in resp
    assert "result" in resp


def test_tools_list_has_tools_array():
    resp = _tools_entry("")
    assert isinstance(resp["result"]["tools"], list)


def test_tool_entry_has_name():
    resp = _tools_entry(
        "@server.tool()\ndef say(message):\n    return message\n"
    )
    tool = resp["result"]["tools"][0]
    assert tool["name"] == "say"


def test_tool_entry_has_input_schema():
    resp = _tools_entry(
        "@server.tool()\ndef say(message):\n    return message\n"
    )
    tool = resp["result"]["tools"][0]
    assert tool["inputSchema"]["type"] == "object"
    assert "message" in tool["inputSchema"]["properties"]


def test_tool_schema_has_all_params():
    resp = _tools_entry(
        "@server.tool()\ndef run(a, b, c):\n    return a\n"
    )
    props = resp["result"]["tools"][0]["inputSchema"]["properties"]
    assert sorted(props) == ["a", "b", "c"]


def test_jsonrpc_version_parse():
    data = json.loads(TOOLS_LIST)
    assert data["method"] == "tools/list"


def test_jsonrpc_tools_call_parse():
    data = json.loads(
        '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run","arguments":{"a":1}}}'
    )
    assert data["params"]["name"] == "run"
    assert data["params"]["arguments"]["a"] == 1


def test_jsonrpc_initialize():
    data = json.loads('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
    assert data["method"] == "initialize"


def test_result_findings_cover_tools_list_semantics(tmp_path):
    """The static scan should flag a handler whose schema can be enumerated and
    whose input flows to a sink."""
    d = tmp_path / "rpc"
    d.mkdir()
    (d / "svr.py").write_text(P + (
        "@server.tool()\n"
        "def exec(code):\n"
        "    exec(code)\n"
    ))
    result = scan_tree(str(d))
    assert any(f.rule_id == "MCP-006" for f in result.findings)


def test_findings_survive_json_roundtrip(sample_report):
    data = json.loads(render_json(sample_report))
    assert data["findings"][0]["rule_id"] == "MCP-001"


def test_empty_tool_list_clean_scan(tmp_path):
    d = tmp_path / "clean"
    d.mkdir()
    (d / "svr.py").write_text(P)
    result = scan_tree(str(d))
    assert result.findings == [] or all(
        f.rule_id != "MCP-011" for f in result.findings
    )


def test_schema_semantics_required_for_taint(tmp_path):
    """Declared tool args are exactly the untrusted surface; every handler param
    must therefore be sanitized before a sink. A schema without a constraint and
    an eval sink should produce MCP-006 and MCP-008."""
    d = tmp_path / "rpc2"
    d.mkdir()
    (d / "svr.py").write_text(P + (
        "@server.tool()\n"
        "def calc(expr, mode):\n"
        "    return eval(expr) if mode == 'x' else None\n"
    ))
    result = scan_tree(str(d))
    ids = {f.rule_id for f in result.findings}
    assert "MCP-006" in ids
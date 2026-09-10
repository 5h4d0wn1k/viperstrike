"""Parser tests: JS/TS regex-level parser."""

import pytest

from viperstrike.parsers.js_parser import (
    JSMCPModule,
    JSToolHandler,
    parse_js_file,
)


def test_js_empty_file(write_source):
    p = write_source("empty.js", "")
    m = parse_js_file(p)
    assert isinstance(m, JSMCPModule)
    assert m.tool_handlers == []


def test_js_language_detected(write_source):
    p = write_source("s.js", "const x = 1;\n")
    assert parse_js_file(p).language == "javascript"


def test_ts_language_detected(write_source):
    p = write_source("s.ts", "const x: number = 1;\n")
    assert parse_js_file(p).language == "typescript"


def test_js_detects_decorator_tool(write_source):
    p = write_source("s.ts", (
        "@server.tool()  \n"
        "getWeather() {\n"
    ))
    m = parse_js_file(p)
    assert len(m.tool_handlers) >= 1


def test_js_detects_named_decorator(write_source):
    p = write_source("s.ts", "@server.tool('fetch_logs')\n")
    m = parse_js_file(p)
    assert any(h.name == "fetch_logs" for h in m.tool_handlers)


def test_js_detects_method_call_tool(write_source):
    p = write_source("s.js", "server.tool('run_cmd', schema, handler);\n")
    m = parse_js_file(p)
    assert any(h.name == "run_cmd" for h in m.tool_handlers)


def test_js_detects_fastmcp_tool(write_source):
    p = write_source("s.js", "fastMcp.tool('say_hi', ...);\n")
    m = parse_js_file(p)
    assert any(h.name == "say_hi" for h in m.tool_handlers)


def test_js_import_detected_esm(write_source):
    p = write_source("s.js", "import { Server } from '@modelcontextprotocol/sdk/server';\n")
    assert parse_js_file(p).has_mcp_import


def test_js_import_detected_cjs(write_source):
    p = write_source("s.js", "const { Server } = require('@modelcontextprotocol/sdk/server');\n")
    assert parse_js_file(p).has_mcp_import


def test_js_import_detected_fastmcp(write_source):
    p = write_source("s.js", "import { FastMCP } from 'fastmcp';\n")
    assert parse_js_file(p).has_mcp_import


def test_js_no_false_import(write_source):
    p = write_source("s.js", "const fs = require('fs');\n")
    assert not parse_js_file(p).has_mcp_import


def test_js_server_instantiation(write_source):
    p = write_source("s.js", "const server = new Server({ name: 'x' });\n")
    assert parse_js_file(p).has_server_instantiation


def test_js_chain_detection(write_source):
    p = write_source("s.js", "server\n  .tool('grab')\n  .other('x');\n")
    m = parse_js_file(p)
    assert any(h.name == "grab" for h in m.tool_handlers)


def test_js_multiple_tools_detected(write_source):
    p = write_source("s.js", (
        "server.tool('a', ...);\n"
        "server.tool('b', ...);\n"
        "@server.tool('c')\n"
    ))
    names = {h.name for h in parse_js_file(p).tool_handlers}
    assert {"a", "b", "c"}.issubset(names)


def test_js_no_duplicate_handlers(write_source):
    p = write_source("s.js", "server.tool('dup', ...);\nserver.tool('dup', ...);\n")
    m = parse_js_file(p)
    assert sum(1 for h in m.tool_handlers if h.name == "dup") <= 1


def test_js_line_numbers_recorded(write_source):
    p = write_source("s.js", "x = 1;\nserver.tool('reports', ...);\n")
    m = parse_js_file(p)
    h = next(h for h in m.tool_handlers if h.name == "reports")
    assert h.line == 2


def test_ts_mcp_import_pattern(write_source):
    p = write_source("s.ts", "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\n")
    assert parse_js_file(p).has_mcp_import


def test_js_raw_source_preserved(write_source):
    p = write_source("s.js", "let a = 1;\n")
    m = parse_js_file(p)
    assert "let a = 1" in m.raw_source
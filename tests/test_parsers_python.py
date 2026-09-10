"""Parser tests: Python AST parsing of MCP servers."""

import ast

import pytest

from viperstrike.parsers.python_parser import (
    MCPModule,
    ToolHandler,
    parse_python_file,
    _is_mcp_decorator,
)


def test_parse_empty_still_returns_module(write_source):
    p = write_source("empty.py", "")
    m = parse_python_file(p)
    assert isinstance(m, MCPModule)
    assert m.tool_handlers == []


def test_parse_detects_mcp_import(write_source):
    p = write_source(source="from mcp.server.fastmcp import FastMCP\n")
    m = parse_python_file(p)
    assert m.has_mcp_import


def test_parse_detects_import_mcp(write_source):
    p = write_source(source="import mcp.server\n")
    m = parse_python_file(p)
    assert m.has_mcp_import


def test_parse_detects_server_instantiation(write_source):
    p = write_source(source="server = Server('name')\n")
    m = parse_python_file(p)
    assert m.has_server_instantiation


def test_parse_detects_fastmcp_instantiation(write_source):
    p = write_source(source="app = FastMCP('name')\n")
    m = parse_python_file(p)
    assert m.has_server_instantiation


def test_no_false_mcp_import(write_source):
    p = write_source(source="import json\nimport os\n")
    m = parse_python_file(p)
    assert not m.has_mcp_import


def test_tool_decorator_detected(write_source):
    p = write_source(source=(
        "@server.tool()\n"
        "def hello():\n"
        "    return 'hi'\n"
    ))
    m = parse_python_file(p)
    assert len(m.tool_handlers) == 1
    assert m.tool_handlers[0].name == "hello"


def test_async_tool_handler_detected(write_source):
    p = write_source(source=(
        "@mcp.tool\n"
        "async def go():\n"
        "    return 1\n"
    ))
    m = parse_python_file(p)
    assert [h.name for h in m.tool_handlers] == ["go"]


def test_plain_tool_decorator_detected(write_source):
    p = write_source(source=(
        "@tool\n"
        "def go():\n"
        "    pass\n"
    ))
    m = parse_python_file(p)
    assert [h.name for h in m.tool_handlers] == ["go"]


def test_non_tool_functions_not_handlers(write_source):
    p = write_source(source=(
        "@server.tool()\n"
        "def a():\n"
        "    pass\n"
        "def b():\n"
        "    pass\n"
        "def c():\n"
        "    pass\n"
    ))
    m = parse_python_file(p)
    assert [h.name for h in m.tool_handlers] == ["a"]


def test_decorator_name_recording(write_source):
    p = write_source(source=(
        "@mcp.tool()\n"
        "def a():\n"
        "    pass\n"
    ))
    m = parse_python_file(p)
    assert m.tool_handlers[0].decorator_names == ["mcp.tool"]


def test_param_extraction(write_source):
    p = write_source(source=(
        "@server.tool()\n"
        "def run(cmd, host='local', count=1):\n"
        "    return cmd\n"
    ))
    m = parse_python_file(p)
    h = m.tool_handlers[0]
    assert h.params == ["cmd", "host", "count"]


def test_self_param_skipped_in_class(write_source):
    p = write_source(source=(
        "class Svc:\n"
        "    @server.tool()\n"
        "    def run(self, cmd):\n"
        "        return cmd\n"
    ))
    m = parse_python_file(p)
    assert m.tool_handlers[0].params == ["cmd"]


def test_param_defaults_recorded(write_source):
    p = write_source(source=(
        "@server.tool()\n"
        "def run(cmd, cap=False, n=3):\n"
        "    return cmd\n"
    ))
    m = parse_python_file(p)
    h = m.tool_handlers[0]
    assert "cap" in h.param_defaults
    assert "n" in h.param_defaults


def test_line_and_column_captured(write_source):
    p = write_source(source=(
        "x = 1\n"
        "@server.tool()\n"
        "def run():\n"
        "    return 1\n"
    ))
    m = parse_python_file(p)
    h = m.tool_handlers[0]
    assert h.line == 3


def test_malformed_source_does_not_crash(write_source):
    p = write_source("broken.py", "def foo(:\n  return\n")
    m = parse_python_file(p)
    assert m.raw_source is not None
    assert m.tool_handlers == []


def test_unicode_source_parses(write_source):
    p = write_source(source=(
        "# c\xf3digo\n"
        "@server.tool()\n"
        "def hola(nombre):\n"
        "    return f'hola {nombre}'\n"
    ))
    m = parse_python_file(p)
    assert [h.name for h in m.tool_handlers] == ["hola"]


def test_has_return_flag(write_source):
    p = write_source(source=(
        "@server.tool()\n"
        "def a():\n"
        "    return 1\n"
        "@server.tool()\n"
        "def b():\n"
        "    pass\n"
    ))
    m = parse_python_file(p)
    by_name = {h.name: h for h in m.tool_handlers}
    assert by_name["a"].has_return
    assert not by_name["b"].has_return


def test_body_line_span(write_source):
    p = write_source(source=(
        "@server.tool()\n"
        "def a():\n"
        "    x = 1\n"
        "    y = 2\n"
        "    return x\n"
    ))
    m = parse_python_file(p)
    h = m.tool_handlers[0]
    assert h.body_lines and min(h.body_lines) == 2
    assert max(h.body_lines) >= 5


def test_module_path_recorded(write_source):
    p = write_source("custom_name.py", "pass")
    m = parse_python_file(p)
    assert m.path.endswith("custom_name.py")


def test_imports_collected(write_source):
    p = write_source(source=(
        "import os\n"
        "from mcp.server import Server\n"
    ))
    m = parse_python_file(p)
    assert any("import os" in i for i in m.imports)


def test_server_variable_tracked(write_source):
    p = write_source(source="server = Server('x')\n")
    m = parse_python_file(p)
    assert m.server_variable == "server"


def test_decorator_with_args_handled(write_source):
    p = write_source(source=(
        "@server.tool(description='do it', enabled_by_default=True)\n"
        "def a():\n"
        "    pass\n"
    ))
    m = parse_python_file(p)
    assert m.tool_handlers[0].name == "a"


def test_nested_function_not_handler(write_source):
    p = write_source(source=(
        "@server.tool()\n"
        "def outer():\n"
        "    def inner():\n"
        "        pass\n"
        "    return inner\n"
    ))
    m = parse_python_file(p)
    names = [h.name for h in m.tool_handlers]
    assert names == ["outer"]


def test_decorator_helper_returns_attribute_name():
    import ast
    expr = ast.Attribute(value=ast.Name(id="server", ctx=ast.Load()),
                         attr="tool", ctx=ast.Load())
    assert _is_mcp_decorator(expr) == "server.tool"


def test_decorator_helper_returns_none_for_other():
    import ast
    expr = ast.Attribute(value=ast.Name(id="server", ctx=ast.Load()),
                         attr="listen", ctx=ast.Load())
    assert _is_mcp_decorator(expr) is None


def test_multiline_handler_extracted(write_source):
    p = write_source(source=(
        "@server.tool()\n"
        "def big(\n"
        "    a,\n"
        "    b,\n"
        "):\n"
        "    return a + b\n"
    ))
    m = parse_python_file(p)
    assert m.tool_handlers[0].params == ["a", "b"]
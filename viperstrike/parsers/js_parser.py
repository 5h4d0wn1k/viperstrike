"""Regex-based parser for JavaScript/TypeScript MCP servers."""
from __future__ import annotations

import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class JSToolHandler:
    name: str
    pattern_used: str
    line: int
    params: list[str] = field(default_factory=list)


@dataclass
class JSMCPModule:
    path: str
    language: str
    tool_handlers: list[JSToolHandler] = field(default_factory=list)
    has_mcp_import: bool = False
    has_server_instantiation: bool = False
    raw_source: str = ""
    lines: list[str] = field(default_factory=list)


TOOL_DECORATOR_RE = re.compile(
    r"""(?:@\w+\.tool\s*\(|server\.tool\s*\(\s*['"](\w+)['"]|"""
    r"""app\.tool\s*\(\s*['"](\w+)['"]|"""
    r"""\.tool\s*\(\s*['"](\w+)['"])""",
    re.MULTILINE,
)

TOOL_FUNC_RE = re.compile(
    r"""(?:server|app|mcp|fastMcp)\s*\.\s*tool\s*\(\s*['"](\w+)['"]""",
    re.MULTILINE,
)

TOOL_NAME_RE = re.compile(
    r"""@(\w+)\.tool(?:\s*\(\s*['"](\w+)['"]\s*\))?""",
    re.MULTILINE,
)

MCP_JS_IMPORT_RE = re.compile(
    r"""(?:from\s+['"]@?mcp(?:/.*)?['"]|"""
    r"""require\s*\(\s*['"]@?mcp(?:/.*)?['"]|"""
    r"""from\s+['"]@modelcontextprotocol(?:/.*)?['"]|"""
    r"""require\s*\(\s*['"]@modelcontextprotocol(?:/.*)?['"]|"""
    r"""from\s+['"]fastmcp['"]|"""
    r"""require\s*\(\s*['"]fastmcp['"])""",
    re.MULTILINE,
)

SERVER_INIT_RE = re.compile(
    r"""(?:new\s+Server\s*\(|new\s+McpServer\s*\(|"""
    r"""FastMCP\s*\(|new\s+FastMCP\s*\()""",
    re.MULTILINE,
)

PARAM_RE = re.compile(r"""['"](\w+)['"]\s*:\s*\{""")


def parse_js_file(path: str | Path) -> JSMCPModule:
    path = Path(path)
    source = path.read_text(errors="replace")
    lines = source.splitlines()

    lang = "typescript" if path.suffix in (".ts", ".tsx") else "javascript"

    module = JSMCPModule(
        path=str(path),
        language=lang,
        raw_source=source,
        lines=lines,
    )

    module.has_mcp_import = bool(MCP_JS_IMPORT_RE.search(source))
    module.has_server_instantiation = bool(SERVER_INIT_RE.search(source))

    for m in TOOL_NAME_RE.finditer(source):
        line_num = source[:m.start()].count("\n") + 1
        tool_name = m.group(2) or m.group(1)
        module.tool_handlers.append(JSToolHandler(
            name=tool_name,
            pattern_used="decorator",
            line=line_num,
        ))

    for m in TOOL_FUNC_RE.finditer(source):
        line_num = source[:m.start()].count("\n") + 1
        tool_name = m.group(1)
        already = any(h.name == tool_name for h in module.tool_handlers)
        if not already:
            module.tool_handlers.append(JSToolHandler(
                name=tool_name,
                pattern_used="method-call",
                line=line_num,
            ))

    for m in re.finditer(r"""\.tool\s*\(\s*['"](\w+)['"]""", source):
        line_num = source[:m.start()].count("\n") + 1
        tool_name = m.group(1)
        already = any(h.name == tool_name for h in module.tool_handlers)
        if not already:
            module.tool_handlers.append(JSToolHandler(
                name=tool_name,
                pattern_used="chained-call",
                line=line_num,
            ))

    return module

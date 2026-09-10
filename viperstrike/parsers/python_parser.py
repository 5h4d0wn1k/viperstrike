"""Python AST-based parser for MCP server source files."""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class ToolHandler:
    name: str
    decorator_names: list[str]
    params: list[str]
    param_defaults: dict[str, Optional[str]]
    line: int
    column: int
    body_lines: list[int] = field(default_factory=list)
    has_return: bool = False


@dataclass
class MCPModule:
    path: str
    language: str = "python"
    tool_handlers: list[ToolHandler] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    all_function_defs: list[str] = field(default_factory=list)
    all_class_defs: list[str] = field(default_factory=list)
    raw_source: str = ""
    lines: list[str] = field(default_factory=list)
    has_mcp_import: bool = False
    has_server_instantiation: bool = False
    server_variable: Optional[str] = None
    parse_error: Optional[str] = None


MCP_IMPORT_PATTERNS = [
    "from mcp", "import mcp", "from fastmcp", "import fastmcp",
    "from mcp.server", "Server(",
]

MCP_DECORATOR_NAMES = {"tool", "mcp.tool", "server.tool", "app.tool"}
MCP_SERVER_PATTERNS = re.compile(
    r"(?:Server|FastMCP|McpServer|server)\s*\("
)


def _is_mcp_decorator(decorator: ast.expr) -> Optional[str]:
    if isinstance(decorator, ast.Call):
        return _is_mcp_decorator(decorator.func)
    if isinstance(decorator, ast.Name):
        return decorator.id if decorator.id in {"tool"} else None
    if isinstance(decorator, ast.Attribute):
        parts = []
        node: ast.expr = decorator
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value  # type: ignore
        if isinstance(node, ast.Name):
            parts.append(node.id)
        full = ".".join(reversed(parts))
        if full in MCP_DECORATOR_NAMES:
            return full
        if any(full.endswith("." + d) for d in MCP_DECORATOR_NAMES):
            return full
    return None


def parse_python_file(path: str | Path) -> MCPModule:
    path = Path(path)
    source = path.read_text(errors="replace")
    lines = source.splitlines()

    module = MCPModule(
        path=str(path),
        language="python",
        raw_source=source,
        lines=lines,
    )

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("import ") or stripped.startswith("from "):
            module.imports.append(stripped)
            for pat in MCP_IMPORT_PATTERNS:
                if pat in stripped:
                    module.has_mcp_import = True

    if MCP_SERVER_PATTERNS.search(source):
        module.has_server_instantiation = True

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        module.parse_error = f"syntax error: {exc}"
        return module

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            module.all_function_defs.append(node.name)
        elif isinstance(node, ast.ClassDef):
            module.all_class_defs.append(node.name)

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if isinstance(node.value, ast.Call):
                        func = node.value.func
                        if isinstance(func, ast.Name) and func.id == "Server":
                            module.has_server_instantiation = True
                            module.server_variable = target.id
                        elif isinstance(func, ast.Attribute) and func.attr == "Server":
                            module.has_server_instantiation = True
                            module.server_variable = target.id

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        decorators: list[str] = []
        for dec in node.decorator_list:
            name = _is_mcp_decorator(dec)
            if name:
                decorators.append(name)

        params: list[str] = []
        param_defaults: dict[str, Optional[str]] = {}

        args = node.args
        for arg in args.args:
            if arg.arg in ("self", "cls"):
                continue
            params.append(arg.arg)

        num_defaults = len(args.defaults)
        num_args = len(args.args)
        if num_defaults > 0:
            default_args = args.args[num_args - num_defaults:]
            for i, d in enumerate(args.defaults):
                if i >= len(default_args):
                    break
                arg_name = default_args[i].arg
                try:
                    val = ast.dump(d)
                    param_defaults[arg_name] = val
                except Exception:
                    param_defaults[arg_name] = "..."

        body_lines = []
        for child in ast.walk(node):
            if hasattr(child, "lineno"):
                if child.lineno >= node.lineno:
                    body_lines.append(child.lineno)

        has_return = any(
            isinstance(n, ast.Return) for n in ast.walk(node)
        )

        if decorators:
            handler = ToolHandler(
                name=node.name,
                decorator_names=decorators,
                params=params,
                param_defaults=param_defaults,
                line=node.lineno,
                column=node.col_offset,
                body_lines=sorted(set(body_lines)),
                has_return=has_return,
            )
            module.tool_handlers.append(handler)

    return module

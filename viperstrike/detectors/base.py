"""Base classes shared by all detectors."""
from __future__ import annotations

import ast
from typing import Optional

from viperstrike.core import Finding, Location
from viperstrike.rules import Rule
from viperstrike.parsers.python_parser import MCPModule


class Detector:
    """Base class. Each detector maps one or more rule IDs to findings."""

    rule: Rule = None  # type: ignore

    def __init__(self, module: MCPModule):
        self.module = module
        self.tree: Optional[ast.Module] = None
        from viperstrike.parsers.python_parser import MCPModule as _M
        if isinstance(module, _M) and module.raw_source:
            try:
                self.tree = ast.parse(module.raw_source, filename=module.path)
            except SyntaxError:
                self.tree = None

    def detect(self) -> list[Finding]:
        return []

    def loc(self, line: int, column: int = 0) -> Location:
        return Location(file=self.module.path, line=line, column=column)

    def finding(self, message: str, locations: list[Location],
                evidence: str = "", fix_suggestion: str = "") -> Finding:
        return Finding.from_rule(
            self.rule,
            message=message,
            locations=locations,
            evidence=evidence,
            fix_suggestion=fix_suggestion,
        )

    def module_has_mcp_markers(self) -> bool:
        m = self.module
        return bool(m.has_mcp_import or m.has_server_instantiation or m.tool_handlers)

    def tool_handler_function_names(self) -> set[str]:
        return {h.name for h in self.module.tool_handlers}


def function_defs(tree: ast.Module) -> list[ast.FunctionDef]:
    return [n for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def param_names(func: ast.FunctionDef) -> set[str]:
    return {a.arg for a in func.args.args if a.arg not in ("self", "cls")}
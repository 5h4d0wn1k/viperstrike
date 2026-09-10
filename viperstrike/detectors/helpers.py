"""Shared AST helper utilities for detectors."""
from __future__ import annotations

import ast
from typing import Iterable, Optional
from viperstrike.core import Location


def get_source_range(source_lines: list[str], start: int, end: int, limit: int = 3) -> str:
    """Return a snippet of source spanning [start, end] (1-based, inclusive),
    capped to at most `limit` lines."""
    start = max(1, start)
    end = min(len(source_lines), max(start, end))
    end = min(end, start + limit - 1)
    if end < start:
        return ""
    return "\n".join(source_lines[start - 1:end])


def find_calls(tree: ast.AST, func_names: set[str]) -> list[ast.Call]:
    """Find all Call nodes whose callee name matches any in func_names."""
    results = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = resolve_call_name(node)
            if name and name in func_names:
                results.append(node)
    return results


def resolve_call_name(call: ast.Call) -> Optional[str]:
    """Resolve a call to a simple dotted name if possible."""
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts = []
        node: ast.expr = func
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value  # type: ignore
        if isinstance(node, ast.Name):
            parts.append(node.id)
            return ".".join(reversed(parts))
        if isinstance(node, ast.Call):
            return ".".join(reversed(parts))
    return None


def find_attribute_accesses(tree: ast.AST, attr_names: set[str]) -> list[ast.Attribute]:
    results = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in attr_names:
            results.append(node)
    return results


def expr_uses_params(expr: ast.AST, params: set[str]) -> bool:
    for n in ast.walk(expr):
        if isinstance(n, ast.Name) and n.id in params:
            return True
    return False


def call_uses_params(call: ast.Call, params: set[str],
                     param_name_hint: Optional[str] = None) -> bool:
    """
    Determine whether any argument of a call is tainted by a function param.
    - Direct Name reference to a param.
    - f-strings / BinOp that contain a param.
    - Call with a keyword arg using param_name_hint.
    """
    for arg in call.args:
        if expr_uses_params(arg, params):
            return True
    if call.keywords:
        for kw in call.keywords:
            if expr_uses_params(kw.value, params):
                return True
            if param_name_hint and kw.arg == param_name_hint:
                return True
    return False


def is_fstring_constant(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def interpolated_string(node: ast.expr) -> Optional[str]:
    """Returns the rendered string if node is a constant, else None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def is_shell_true_call(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant):
            return bool(kw.value.value)
    return False


def is_subprocess_shell_calls(tree: ast.AST) -> list[tuple[ast.Call, bool]]:
    """Return (call, shell_flag_tainted) for subprocess.{call|Popen|run|check_output|...}"""
    results = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = resolve_call_name(node)
        if not name:
            continue
        if name in ("os.system", "os.popen") or name in (
            "subprocess.call", "subprocess.run", "subprocess.check_output",
            "subprocess.check_call", "subprocess.Popen", "subprocess.getoutput",
            "subprocess.getstatusoutput",
        ):
            shell_flag = is_shell_true_call(node)
            results.append((node, shell_flag))
    return results


def contains_path_traversal(s: str) -> bool:
    return ".." in s or s.startswith("/") or s.startswith("\\\\")


def visits(node: ast.AST) -> Iterable[ast.AST]:
    return ast.walk(node)


def param_names_of(func: object) -> list[str]:
    """Extract param names from a FunctionDef-style object."""
    if hasattr(func, "args") and hasattr(func.args, "args"):
        return [a.arg for a in func.args.args if a.arg not in ("self", "cls")]
    return []
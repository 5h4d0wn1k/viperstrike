"""MCP-004: Path traversal in read handler."""
from __future__ import annotations

import ast

from viperstrike.core import Finding
from viperstrike.detectors.base import Detector, function_defs, param_names
from viperstrike.detectors.helpers import (
    get_source_range,
    find_calls,
    resolve_call_name,
    call_uses_params,
    contains_path_traversal,
    interpolated_string,
)
from viperstrike.rules import RULES

READ_MODES = {"r", "rb", "rt", "r+", "rb+", ""}

READ_CALLS = {
    "open", "builtins.open", "Path.read_text", "Path.read_bytes", "os.read",
    "os.listdir", "os.stat", "os.path.isfile", "os.path.exists",
    "os.path.join", "read_text", "read_bytes", "Path.open",
}


class PathTraversalDetector(Detector):
    rule = RULES["MCP-004"]

    def detect(self) -> list[Finding]:
        findings: list[Finding] = []
        if self.tree is None:
            return findings

        for func in function_defs(self.tree):
            params = param_names(func)
            handler_names = self.tool_handler_function_names()
            body = ast.get_source_segment(self.module.raw_source, func) or ""
            traversal_vars = self._traversal_vars(func)

            for call in find_calls(func, READ_CALLS):
                name = resolve_call_name(call)
                if name is None:
                    continue

                # Skip write-mode opens (those belong to MCP-003)
                if name in ("open", "builtins.open"):
                    mode = "r"
                    if len(call.args) > 1 and isinstance(call.args[1], ast.Constant):
                        mode = str(call.args[1].value)
                    for kw in call.keywords:
                        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                            mode = str(kw.value.value)
                    if mode not in READ_MODES:
                        continue

                args = list(call.args) + [kw.value for kw in call.keywords]

                # Direct traversal constant ("../x") in any argument
                const_traversal = False
                for arg in args:
                    s = interpolated_string(arg)
                    if s and contains_path_traversal(s):
                        const_traversal = True
                        break
                    if isinstance(arg, ast.Name) and arg.id in traversal_vars:
                        const_traversal = True
                        break

                tainted = call_uses_params(call, params)
                handler_ctx = "handler" if func.name in handler_names else "function"

                binop_traversal = any(isinstance(arg, ast.BinOp) for arg in args)

                # Guard mitigation: handler already blocks '..' / absolute escapes
                if self._has_traversal_guard(body, params):
                    continue

                if const_traversal and (func.name in handler_names or tainted):
                    line = getattr(call, "lineno", func.lineno)
                    evidence = get_source_range(
                        self.module.lines, line, line + 2)
                    findings.append(self.finding(
                        message=(f"Read {handler_ctx} '{func.name}' exposes a path "
                                 "containing '..' / absolute components — path "
                                 "traversal can escape the intended base directory."),
                        locations=[self.loc(line)],
                        evidence=evidence.strip(),
                        fix_suggestion=(
                            "Sanitize the resolved path: reject '..' and absolute "
                            "paths, then verify os.path.realpath() stays inside "
                            "the allowlisted base directory."
                        ),
                    ))
                elif tainted and (binop_traversal or func.name in handler_names):
                    line = getattr(call, "lineno", func.lineno)
                    evidence = get_source_range(
                        self.module.lines, line, line + 2)
                    findings.append(self.finding(
                        message=(f"Read {handler_ctx} '{func.name}' opens a path "
                                 "built from a user-supplied argument without "
                                 "traversal protection."),
                        locations=[self.loc(line)],
                        evidence=evidence.strip(),
                        fix_suggestion=(
                            "Validate the user path with an allowlist and "
                            "os.path.realpath() containment check before reading."
                        ),
                    ))
        return findings

    def _traversal_vars(self, func) -> set[str]:
        """Names assigned a traversal-prone string constant."""
        vars_: set[str] = set()
        for n in ast.walk(func):
            if isinstance(n, ast.Assign):
                s = interpolated_string(n.value)
                if s and contains_path_traversal(s):
                    for t in n.targets:
                        if isinstance(t, ast.Name):
                            vars_.add(t.id)
        return vars_

    def _has_traversal_guard(self, body: str, params: set[str]) -> bool:
        if not params:
            return False
        body_lower = body.lower()
        for p in params:
            probes = (
                f"'..' in {p}", f'".." in {p}', f"'{p}' not in", f"'{p}' in",
                f'"..', f"'..'  in {p}",
            )
            for probe in probes:
                if probe in body_lower:
                    return True
        checks = ("startswith('/')", "startswith('/',", "realpath(", "resolve(",)
        if any(c in body for c in checks):
            return True
        for line_pat in ("if '..' in", 'if ".." in', "if '../' in",
                         'if "..\\" in'):
            if line_pat in body_lower:
                return True
        return False
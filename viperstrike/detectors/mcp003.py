"""MCP-003: Arbitrary file write via handler."""
from __future__ import annotations

import ast

from viperstrike.core import Finding
from viperstrike.detectors.base import Detector, function_defs, param_names
from viperstrike.detectors.helpers import (
    get_source_range,
    find_calls,
    resolve_call_name,
    call_uses_params,
    expr_uses_params,
)
from viperstrike.rules import RULES

WRITE_MODES = {"w", "a", "x", "wb", "ab", "xb", "r+", "rb+", "w+", "a+"}
WRITE_METHOD_CALLS = {
    "Path.write_text", "Path.write_bytes", "open", "builtins.open",
    "os.write", "os.fdopen", "shutil.copy", "shutil.copyfile", "shutil.move",
    "to_csv", "to_json", "json.dump", "pickle.dump",
}


class ArbitraryWriteDetector(Detector):
    rule = RULES["MCP-003"]

    def detect(self) -> list[Finding]:
        findings: list[Finding] = []
        if self.tree is None:
            return findings

        for func in function_defs(self.tree):
            params = param_names(func)
            handler_names = self.tool_handler_function_names()
            in_handler = func.name in handler_names

            for call in find_calls(func, WRITE_METHOD_CALLS):
                name = resolve_call_name(call)
                if name is None:
                    continue
                is_write = False
                tainted = call_uses_params(call, params)
                if name in ("open", "builtins.open"):
                    mode = "r"
                    if len(call.args) > 1 and isinstance(call.args[1], ast.Constant):
                        mode = str(call.args[1].value)
                    for kw in call.keywords:
                        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                            mode = str(kw.value.value)
                    is_write = mode in WRITE_MODES
                elif name in ("write_text", "write_bytes", "json.dump",
                              "pickle.dump"):
                    is_write = True
                elif name.startswith("Path.") and name.endswith(("write_text", "write_bytes")):
                    is_write = True
                elif name in ("os.write", "shutil.copy", "shutil.copyfile",
                              "shutil.move"):
                    is_write = True
                elif tainted and any(k in name for k in ("copy", "write", "save", "dump")):
                    is_write = True

                if not is_write:
                    continue

                handler_ctx = "handler" if in_handler else "function"
                if not tainted and in_handler:
                    # taint may be indirect via intermediate variable
                    tainted = self._indirect_taint(call, func, params)
                if not tainted:
                    continue

                line = getattr(call, "lineno", func.lineno)
                evidence = get_source_range(
                    self.module.lines, line, line + 2)
                findings.append(self.finding(
                    message=(f"Tool {handler_ctx} '{func.name}' writes a file at a "
                             "path derived from a user-supplied argument — "
                             "arbitrary file overwrite (CWE-73/CWE-22)."),
                    locations=[self.loc(line)],
                    evidence=evidence.strip(),
                    fix_suggestion=(
                        "Resolve the path against a dedicated data directory and "
                        "reject any path containing '..' or absolute components."
                    ),
                ))
        return findings

    def _indirect_taint(self, call: ast.Call, func: ast.FunctionDef,
                        params: set[str]) -> bool:
        """Heuristic: any variable used in the call was assigned from a param."""
        if self.tree is None:
            return False
        used_names = set()
        for n in ast.walk(call):
            if isinstance(n, ast.Name):
                used_names.add(n.id)
        for assign in [n for n in ast.walk(func) if isinstance(n, ast.Assign)]:
            if expr_uses_params(assign.value, params):
                for t in assign.targets:
                    if isinstance(t, ast.Name) and t.id in used_names:
                        return True
        return False
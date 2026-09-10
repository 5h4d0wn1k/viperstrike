"""MCP-006: eval / exec / compile on user input."""
from __future__ import annotations

import ast

from viperstrike.core import Finding
from viperstrike.detectors.base import Detector, function_defs, param_names
from viperstrike.detectors.helpers import (
    get_source_range,
    find_calls,
    resolve_call_name,
    expr_uses_params,
    interpolated_string,
)
from viperstrike.rules import RULES

CODE_EVAL_CALLS = {
    "eval", "exec", "compile", "builtins.eval", "builtins.exec",
    "builtins.compile", "__import__", "globals", "locals",
}


class CodeExecDetector(Detector):
    rule = RULES["MCP-006"]

    def detect(self) -> list[Finding]:
        findings: list[Finding] = []
        if self.tree is None:
            return findings

        for func in function_defs(self.tree):
            params = param_names(func)
            handler_names = self.tool_handler_function_names()

            for call in find_calls(func, CODE_EVAL_CALLS):
                name = resolve_call_name(call)
                if name is None:
                    continue
                if name in ("__import__", "globals", "locals"):
                    # these are only dangerous when used with dynamic input
                    tainted = False
                    if call.args and expr_uses_params(call.args[0], params):
                        tainted = True
                    if not tainted:
                        continue
                else:
                    if not call.args:
                        continue
                    target = call.args[0]
                    tainted = expr_uses_params(target, params)
                    const = interpolated_string(target)
                    if not tainted and const:
                        # static string is usually benign/constant code — go further
                        continue

                line = getattr(call, "lineno", func.lineno)
                evidence = get_source_range(
                    self.module.lines, line, line + 2)
                handler_ctx = "Tool handler" if func.name in handler_names else "Function"
                findings.append(self.finding(
                    message=(f"{handler_ctx} '{func.name}' passes input to `{name}` — "
                             "arbitrary Python code execution is possible."),
                    locations=[self.loc(line)],
                    evidence=evidence.strip(),
                    fix_suggestion=(
                        "Never eval/exec/compile inputs derived from tool arguments. "
                        "Use an AST-based parser or a safe interpreter instead."
                    ),
                ))
        return findings
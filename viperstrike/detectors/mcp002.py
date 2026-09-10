"""MCP-002: Unsafe subprocess with shell=True or string interpolation."""
from __future__ import annotations

import ast

from viperstrike.core import Finding
from viperstrike.detectors.base import Detector, function_defs, param_names
from viperstrike.detectors.helpers import (
    get_source_range,
    find_calls,
    resolve_call_name,
    call_uses_params,
    is_shell_true_call,
)
from viperstrike.rules import RULES

SUBPROCESS_CALLS = {
    "subprocess.call", "subprocess.run", "subprocess.check_output",
    "subprocess.check_call", "subprocess.Popen", "subprocess.getoutput",
    "subprocess.getstatusoutput",
}


class UnsafeSubprocessDetector(Detector):
    rule = RULES["MCP-002"]

    def detect(self) -> list[Finding]:
        findings: list[Finding] = []
        if self.tree is None:
            return findings
        if not self.module_has_mcp_markers():
            # still scan if module imports subprocess at all
            if not any("subprocess" in i for i in self.module.imports):
                return findings

        for func in function_defs(self.tree):
            params = param_names(func)
            for call in find_calls(func, SUBPROCESS_CALLS):
                name = resolve_call_name(call)
                shell_flag = is_shell_true_call(call)
                tainted = call_uses_params(call, params,
                                           param_name_hint="cmd")
                # Tainted first-arg string (interpolated) is a shell-injection vector
                shell_interp = False
                if call.args:
                    first = call.args[0]
                    if isinstance(first, (ast.JoinedStr, ast.BinOp)) and \
                            any(isinstance(n, ast.Name) and n.id in params
                                for n in ast.walk(first)):
                        shell_interp = True

                if not (shell_flag or shell_interp):
                    continue
                line = getattr(call, "lineno", func.lineno)
                evidence = get_source_range(
                    self.module.lines, line, line + 2)
                flags = []
                if shell_flag:
                    flags.append("shell=True")
                if shell_interp:
                    flags.append("interpolated command string")
                severity = "error" if (shell_flag or tainted) else "warning"
                findings.append(Finding(
                    rule_id=self.rule.rule_id,
                    rule_name=self.rule.name,
                    message=(f"Function '{func.name}' uses `{name}` with "
                             f"{', '.join(flags)} — command injection risk."),
                    severity=severity,
                    confidence="high" if (shell_flag or tainted) else "medium",
                    locations=[self.loc(line)],
                    cwe=self.rule.cwe,
                    evidence=evidence.strip(),
                    fix_suggestion=(
                        "Pass a list of arguments to subprocess with shell=False "
                        "and validate each argument."
                    ),
                ))
        return findings
"""MCP-001: Shell / exec invocation in tool handler."""
from __future__ import annotations

import ast
from typing import Any

from viperstrike.core import Finding
from viperstrike.detectors.base import Detector, function_defs, param_names
from viperstrike.detectors.helpers import (
    get_source_range,
    find_calls,
    resolve_call_name,
    call_uses_params,
)
from viperstrike.parsers.python_parser import MCPModule
from viperstrike.rules import RULES, is_sensitive_tool

SHELL_CALLS = {
    "os.system", "os.popen", "os.execl", "os.execle", "os.execv",
    "os.execve", "os.execlp", "os.spawnv", "os.spawnve", "os.spawnl",
    "commands.getoutput", "commands.getstatusoutput", "popen", "os.system2",
}


class ShellInvocationDetector(Detector):
    rule = RULES["MCP-001"]

    def detect(self) -> list[Finding]:
        findings: list[Finding] = []
        if not self.module_has_mcp_markers() or self.tree is None:
            return findings

        handler_names = self.tool_handler_function_names()

        for func in function_defs(self.tree):
            in_handler = func.name in handler_names
            params = param_names(func)
            for call in find_calls(func, SHELL_CALLS):
                name = resolve_call_name(call)
                if name is None:
                    continue
                tainted = call_uses_params(call, params,
                                           param_name_hint="command")
                if not in_handler and not tainted:
                    continue
                # Constant (non-tainted) shell calls are only reported when the
                # handler is explicitly shell/exec-oriented.
                if not tainted and not is_sensitive_tool(func.name):
                    continue
                line = getattr(call, "lineno", func.lineno)
                evidence = get_source_range(
                    self.module.lines, line, line + 2)
                findings.append(self.finding(
                    message=(f"Tool handler '{func.name}' invokes `{name}` — "
                             "arbitrary shell command execution is possible "
                             "via user-controlled arguments."),
                    locations=[self.loc(line)],
                    evidence=evidence.strip(),
                    fix_suggestion=(
                        f"Replace `{name}` with a parameterized subprocess call "
                        "(no shell=True) and validate/whitelist allowed commands."
                    ),
                ))
        return findings
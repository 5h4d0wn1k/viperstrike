"""MCP-010: Dangerous default — sensitive tool enabled by default."""
from __future__ import annotations

import ast

from viperstrike.core import Finding
from viperstrike.detectors.base import Detector
from viperstrike.detectors.helpers import (
    get_source_range,
    resolve_call_name,
)
from viperstrike.rules import RULES, is_sensitive_tool

ENABLED_DEFAULT_KWS = {"enabled_by_default", "enabled", "default_enabled"}
REGISTER_CALLS = {"Server.tool", "register_tool", "tools"}
LIST_TOOLS_CALLS = {"list_tools", "get_tools"}


class DangerousDefaultDetector(Detector):
    rule = RULES["MCP-010"]

    def detect(self) -> list[Finding]:
        findings: list[Finding] = []
        if self.tree is None:
            return findings

        # 1) explicit enabled_by_default=True on a registration of a sensitive tool
        for func in [
            n for n in ast.walk(self.tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]:
            if is_sensitive_tool(func.name):
                for dec in func.decorator_list:
                    if not isinstance(dec, ast.Call):
                        continue
                    enabled_true = False
                    for kw in dec.keywords:
                        if kw.arg in ENABLED_DEFAULT_KWS and \
                                isinstance(kw.value, ast.Constant):
                            if bool(kw.value.value) is True:
                                enabled_true = True
                    if not enabled_true:
                        continue
                    tool_name = func.name
                    line = getattr(dec, "lineno", func.lineno)
                    evidence = get_source_range(
                        self.module.lines, line, line + 2)
                    findings.append(self.finding(
                        message=(f"Tool '{tool_name}' performs sensitive operations and "
                                 "is registered with enabled_by_default=True — exposed "
                                 "to every connected client without an explicit opt-in."),
                        locations=[self.loc(line)],
                        evidence=evidence.strip(),
                        fix_suggestion=(
                            "Register sensitive tools disabled by default and require "
                            "explicit capability opt-in / approval."
                        ),
                    ))

        # 2) a sensitive handler has an `enabled` default param of True
        for handler in self.module.tool_handlers:
            if not is_sensitive_tool(handler.name):
                continue
            defaults = handler.param_defaults
            for pname in ("enabled", "active", "dangerous"):
                if pname in defaults:
                    if "True" in defaults[pname]:
                        findings.append(self.finding(
                            message=(f"Sensitive tool '{handler.name}' defaults its "
                                     f"'{pname}' parameter to True — enabled by "
                                     "default for all callers."),
                            locations=[self.loc(handler.line)],
                            fix_suggestion=(
                                "Default sensitive switches to False and require "
                                "explicit approval."
                            ),
                        ))
        return findings
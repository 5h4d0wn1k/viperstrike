"""MCP-009: Auth bypass — no auth check on sensitive tool."""
from __future__ import annotations

import ast

from viperstrike.core import Finding
from viperstrike.detectors.base import Detector, function_defs
from viperstrike.detectors.helpers import (
    get_source_range,
    resolve_call_name,
)
from viperstrike.rules import RULES, is_sensitive_tool

AUTH_HINT_TOKENS = (
    "auth", "authorize", "authorized", "permission", "permissions",
    "capab", "role", "require_admin", "require_auth", "oauth",
    "check_access", "api_key", "apikey", "token", "bearer",
    "check_permission", "ensure_authenticated", "identity", "subject",
)


class AuthBypassDetector(Detector):
    rule = RULES["MCP-009"]

    def detect(self) -> list[Finding]:
        findings: list[Finding] = []
        if self.tree is None:
            return findings

        for handler in self.module.tool_handlers:
            if not is_sensitive_tool(handler.name):
                continue

            func = self._find_function(handler.name)
            if func is None:
                continue

            body_src = ast.get_source_segment(self.module.raw_source, func) or ""
            body_lower = body_src.lower()

            has_auth = any(tok in body_lower for tok in AUTH_HINT_TOKENS)
            if has_auth:
                continue

            line = handler.line
            evidence = get_source_range(
                self.module.lines, line, line + 3)
            findings.append(self.finding(
                message=(f"Sensitive tool '{handler.name}' performs file/shell/"
                         "network operations with no authentication or capability "
                         "attestation in its handler — any connected MCP client "
                         "can invoke it."),
                locations=[self.loc(line)],
                evidence=evidence.strip(),
                fix_suggestion=(
                    "Add an authorization gate at the start of the handler "
                    "(session check, capability attestation, role claim) and "
                    "fail closed by default."
                ),
            ))
        return findings

    def _find_function(self, name: str):
        for func in function_defs(self.tree):
            if func.name == name:
                return func
        return None
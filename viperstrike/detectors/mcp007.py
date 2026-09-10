"""MCP-007: Secrets in tool args logged or echoed."""
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
from viperstrike.rules import RULES, is_sensitive_param

LOG_CALL_NAMES = {
    "logging.info", "logging.debug", "logging.warning", "logging.error",
    "logging.exception", "logger.info", "logger.debug", "logger.warning",
    "logger.error", "logger.exception", "logging.log", "self.logger.info",
    "self.logger.debug", "self.logger.warning", "self.logger.error",
    "log.info", "log.debug", "log.warning", "log.error", "print",
    "console.log", "logger.info",
}

ECHO_ATTRS = {"jsonify", "json.dumps", "markdown", "Message", "ToolResult"}


class SecretLoggingDetector(Detector):
    rule = RULES["MCP-007"]

    def detect(self) -> list[Finding]:
        findings: list[Finding] = []
        if self.tree is None:
            return findings

        for func in function_defs(self.tree):
            params = param_names(func)
            sensitive_params = {p for p in params if is_sensitive_param(p)}
            if not sensitive_params:
                continue

            for node in ast.walk(func):
                if not isinstance(node, ast.Call):
                    continue
                name = resolve_call_name(node)
                if name is None:
                    continue

                call_is_log = any(
                    name == lc or (lc.endswith(name.split(".")[-1]) and "." in name)
                    for lc in LOG_CALL_NAMES
                ) or (isinstance(node.func, ast.Attribute) and
                      node.func.attr in ("info", "debug", "warning", "error",
                                         "exception"))

                if not call_is_log:
                    continue

                leaked = {p for p in sensitive_params
                          if expr_uses_params(node, {p})}
                if not leaked:
                    continue

                line = getattr(node, "lineno", func.lineno)
                evidence = get_source_range(
                    self.module.lines, line, line + 2)
                findings.append(self.finding(
                    message=(f"Tool handler '{func.name}' logs or echoes sensitive "
                             f"argument(s) {sorted(leaked)} via `{name}` without "
                             "redaction — secret disclosure in logs/output."),
                    locations=[self.loc(line)],
                    evidence=evidence.strip(),
                    fix_suggestion=(
                        "Never log credential parameters. Redact before printing "
                        "and never include secrets in MCP tool results."
                    ),
                ))

        return findings
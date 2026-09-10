"""MCP-008: Missing input-schema constraints on tool parameters."""
from __future__ import annotations

import ast

from viperstrike.core import Finding
from viperstrike.detectors.base import Detector, function_defs, param_names
from viperstrike.detectors.helpers import get_source_range
from viperstrike.rules import RULES

VALIDATION_HINTS = (
    "isinstance", "assert", "re.match", "re.search", "re.fullmatch",
    "in self.", "in ALLOWLIST", "in ALLOWED", "in allowed", "Enum",
    "validator", "validate", "max_length", "min_length", "pattern",
    "pydantic", "Literal", "TypeError", "ValueError", "raise",
    "if not", "if ", "== ", "!=", "<", ">",
)


class MissingSchemaDetector(Detector):
    rule = RULES["MCP-008"]

    def detect(self) -> list[Finding]:
        findings: list[Finding] = []
        if self.tree is None:
            return findings

        handler_names = self.tool_handler_function_names()

        for func in function_defs(self.tree):
            if func.name not in handler_names:
                continue
            params = param_names(func)
            if len(params) < 2:
                continue

            body = self._body_source(func)
            if body is None:
                continue

            validated = False
            for hint in VALIDATION_HINTS:
                if hint in body:
                    validated = True
                    break

            if validated:
                continue

            line = func.lineno
            evidence = get_source_range(
                self.module.lines, line, line + 3)
            findings.append(self.finding(
                message=(f"Tool handler '{func.name}' declares params "
                         f"{sorted(params)} but performs no schema, type, or "
                         "allowlist validation on them."),
                locations=[self.loc(line)],
                evidence=evidence.strip(),
                fix_suggestion=(
                    "Declare strict input schemas (enum, min/max, format) in the "
                    "MCP tool registration and validate arguments against the "
                    "schema before use."
                ),
            ))
        return findings

    def _body_source(self, func) -> Optional[str]:
        """Return only the body of the function (excludes def line / annotation)."""
        lines = self.module.lines
        if not func.body:
            return ""
        start = func.body[0].lineno
        end = getattr(func, "end_lineno", None) or func.lineno
        if end is None or end < start:
            return ""
        return "\n".join(lines[start - 1:end])
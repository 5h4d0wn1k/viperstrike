"""Detection rules for MCP server vulnerabilities."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "error"
    HIGH = "warning"
    MEDIUM = "note"
    LOW = "note"
    INFO = "note"


class Confidence(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Rule:
    rule_id: str
    name: str
    description: str
    severity: Severity
    confidence: Confidence = Confidence.MEDIUM
    cwe: Optional[str] = None
    tags: list[str] = field(default_factory=list)

    def adapter_js(self, path: str, line: int, description: str):
        """Build a Finding for a JS/TS regex-level hit."""
        from viperstrike.core import Finding, Location
        return Finding(
            rule_id=self.rule_id,
            rule_name=self.name,
            message=f"{description} (JS/TS regex-level scan)",
            severity=self.severity.value,
            confidence="medium" if self.confidence is Confidence.MEDIUM else "low",
            locations=[Location(file=path, line=line, column=0)],
            cwe=self.cwe,
            evidence=f"line {line}: {description}",
            fix_suggestion=self._js_fix_suggestion(),
        )

    def _js_fix_suggestion(self) -> str:
        fixes = {
            "MCP-001": "Avoid shell exec; spawn with argument arrays.",
            "MCP-006": "Never eval untrusted input.",
            "MCP-011": "Use parameterized SQL queries.",
            "MCP-012": "Avoid unsafe deserialization of untrusted data.",
        }
        return fixes.get(self.rule_id, "Validate and constrain tool inputs.")


RULES: dict[str, Rule] = {
    "MCP-001": Rule(
        rule_id="MCP-001",
        name="Shell / exec invocation in tool handler",
        description="Tool handler uses os.system(), os.popen(), exec(), or eval() "
                    "to run shell commands, allowing arbitrary command execution.",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe="CWE-78",
        tags=["rce", "shell", "injection"],
    ),
    "MCP-002": Rule(
        rule_id="MCP-002",
        name="Unsafe subprocess with shell=True or string interpolation",
        description="Tool handler calls subprocess with shell=True or passes an "
                    "interpolated string command, enabling shell injection.",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe="CWE-78",
        tags=["rce", "subprocess", "injection"],
    ),
    "MCP-003": Rule(
        rule_id="MCP-003",
        name="Arbitrary file write via handler",
        description="Tool handler writes to a file path derived from user arguments "
                    "without path validation, enabling arbitrary file overwrite.",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe="CWE-22",
        tags=["path-traversal", "write", "arbitrary-write"],
    ),
    "MCP-004": Rule(
        rule_id="MCP-004",
        name="Path traversal in read handler",
        description="Tool handler reads files using a path from user arguments that "
                    "may contain '..' or absolute paths, escaping the intended directory.",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe="CWE-22",
        tags=["path-traversal", "read", "directory-escape"],
    ),
    "MCP-005": Rule(
        rule_id="MCP-005",
        name="Fetch / SSRF to arbitrary URLs",
        description="Tool handler fetches URLs derived from user input without host "
                    "allowlisting, enabling SSRF against internal services.",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe="CWE-918",
        tags=["ssrf", "fetch", "network"],
    ),
    "MCP-006": Rule(
        rule_id="MCP-006",
        name="eval / exec / compile on user input",
        description="Tool handler passes user-supplied input to eval(), exec(), or "
                    "compile(), enabling arbitrary Python code execution.",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe="CWE-95",
        tags=["rce", "code-injection", "eval"],
    ),
    "MCP-007": Rule(
        rule_id="MCP-007",
        name="Secrets in tool args logged / echoed",
        description="Tool handler logs, prints, or returns sensitive arguments such "
                    "as password, token, or api_key to output without redaction.",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe="CWE-532",
        tags=["info-leak", "logging", "secrets"],
    ),
    "MCP-008": Rule(
        rule_id="MCP-008",
        name="Missing input-schema constraints",
        description="Tool declares parameters but the handler does not validate or "
                    "constrain input (no type checks, no allowlists, no regex).",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        cwe="CWE-20",
        tags=["validation", "input-schema", "missing-constraints"],
    ),
    "MCP-009": Rule(
        rule_id="MCP-009",
        name="Auth bypass — no auth check on sensitive tool",
        description="A sensitive tool handler (file, shell, network access) performs "
                    "no authentication or capability attestation before execution.",
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        cwe="CWE-306",
        tags=["auth", "bypass", "missing-auth"],
    ),
    "MCP-010": Rule(
        rule_id="MCP-010",
        name="Dangerous default — tool enabled by default when sensitive",
        description="Tool is marked enabled_by_default=True or has no explicit gate "
                    "while performing privileged operations (file, shell, network).",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        cwe="CWE-1188",
        tags=["default", "sensitive", "enabled"],
    ),
    "MCP-011": Rule(
        rule_id="MCP-011",
        name="SQL concatenation in database handler",
        description="Tool handler constructs SQL queries via string concatenation or "
                    "f-string interpolation with user input, enabling SQL injection.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe="CWE-89",
        tags=["sqli", "injection", "database"],
    ),
    "MCP-012": Rule(
        rule_id="MCP-012",
        name="Unsafe deserialization (pickle / yaml.load)",
        description="Tool handler deserializes data using pickle.loads(), yaml.load "
                    "without SafeLoader, or similar unsafe deserialization.",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe="CWE-502",
        tags=["deserialization", "pickle", "rce"],
    ),
}

SENSITIVE_TOOL_KEYWORDS = {
    "file", "read", "write", "exec", "shell", "run", "command",
    "system", "process", "download", "fetch", "upload", "network",
    "http", "ssh", "scp", "database", "sql", "query", "eval",
    "execute", "bash", "terminal", "shell_command", "run_command",
    "load", "transfer", "delete", "search", "user", "account",
    "secret", "credential", "record", "blob", "send", "alert",
}

SENSITIVE_PARAM_NAMES = {
    "password", "passwd", "token", "api_key", "apikey", "secret",
    "auth", "credential", "private_key", "access_token", "bearer",
}


def get_rule(rule_id: str) -> Optional[Rule]:
    return RULES.get(rule_id)


def all_rules() -> list[Rule]:
    return list(RULES.values())


def is_sensitive_tool(tool_name: str) -> bool:
    lower = tool_name.lower()
    return any(kw in lower for kw in SENSITIVE_TOOL_KEYWORDS)


def is_sensitive_param(param_name: str) -> bool:
    return param_name.lower() in SENSITIVE_PARAM_NAMES

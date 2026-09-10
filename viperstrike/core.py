"""Core data structures for viperstrike scan results."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

from viperstrike.rules import Rule, Severity, Confidence


@dataclass
class Location:
    file: str
    line: int
    column: int = 0

    def to_dict(self) -> dict:
        return {"file": self.file, "line": self.line, "column": self.column}


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    message: str
    severity: str
    confidence: str
    locations: list[Location]
    cwe: Optional[str] = None
    evidence: str = ""
    fix_suggestion: str = ""
    severity_label: str = "info"

    @classmethod
    def from_rule(cls, rule: Rule, message: str, locations: list[Location],
                  evidence: str = "", fix_suggestion: str = "") -> "Finding":
        return cls(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            message=message,
            severity=rule.severity.value,
            confidence=rule.confidence.value,
            locations=locations,
            cwe=rule.cwe,
            evidence=evidence,
            fix_suggestion=fix_suggestion,
            severity_label=rule.severity.name.lower(),
        )

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "message": self.message,
            "severity": self.severity,
            "severity_label": self.severity_label,
            "confidence": self.confidence,
            "cwe": self.cwe,
            "locations": [loc.to_dict() for loc in self.locations],
            "evidence": self.evidence,
            "fix_suggestion": self.fix_suggestion,
        }


@dataclass
class ScanResult:
    target: str
    files_scanned: int = 0
    lines_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scan_time_ms: float = 0.0

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "files_scanned": self.files_scanned,
            "lines_scanned": self.lines_scanned,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "scan_time_ms": round(self.scan_time_ms, 2),
            "summary": self.summary,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_error(self, msg: str) -> None:
        self.errors.append(msg)

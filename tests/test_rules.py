"""Tests for rule definitions and metadata."""

import pytest

from viperstrike.rules import (
    RULES,
    all_rules,
    get_rule,
    is_sensitive_param,
    is_sensitive_tool,
    Severity,
    Confidence,
)


def test_at_least_twelve_rules():
    assert len(RULES) >= 12


def test_every_rule_id_unique():
    ids = [r.rule_id for r in all_rules()]
    assert len(ids) == len(set(ids))


def test_rule_ids_follow_naming():
    for rid in RULES:
        assert rid.startswith("MCP-"), rid
        number = int(rid.split("-")[1])
        assert 1 <= number <= 999


def test_all_rules_have_names():
    for rid, rule in RULES.items():
        assert rule.name, rid


def test_all_rules_have_descriptions():
    for rid, rule in RULES.items():
        assert len(rule.description) > 10, rid


def test_all_rules_have_severity():
    for rid, rule in RULES.items():
        assert rule.severity in Severity, rid


def test_all_rules_have_confidence():
    for rid, rule in RULES.items():
        assert rule.confidence in Confidence, rid


def test_registered_rules_are_ordered_contiguously():
    numbers = sorted(int(rid.split("-")[1]) for rid in RULES)
    assert numbers == list(range(1, len(numbers) + 1))


def test_get_rule_known():
    assert get_rule("MCP-001").rule_id == "MCP-001"


def test_get_rule_unknown_returns_none():
    assert get_rule("MCP-999") is None


def test_get_rule_none_for_malformed():
    assert get_rule("bogus") is None


def test_cwe_present_for_critical_rules():
    for rid in ("MCP-001", "MCP-002", "MCP-006", "MCP-012"):
        assert RULES[rid].cwe is not None


def test_mcp003_cwe_is_path_traversal():
    assert RULES["MCP-003"].cwe in ("CWE-22", "CWE-73")


def test_mcp005_cwe_is_ssrf():
    assert RULES["MCP-005"].cwe == "CWE-918"


def test_mcp011_cwe_is_sqli():
    assert RULES["MCP-011"].cwe == "CWE-89"


def test_severity_values_are_sarif_valid():
    for rule in all_rules():
        assert rule.severity.value in ("error", "warning", "note")


def test_high_risk_rules_mapped_to_error_level():
    for rid in ("MCP-001", "MCP-002", "MCP-006", "MCP-012"):
        assert RULES[rid].severity == Severity.CRITICAL
        assert RULES[rid].severity.value == "error"


def test_sensitive_param_true_for_password():
    assert is_sensitive_param("password")


def test_sensitive_param_true_for_token():
    assert is_sensitive_param("token")


def test_sensitive_param_true_for_api_key():
    assert is_sensitive_param("api_key")


def test_sensitive_param_case_insensitive():
    assert is_sensitive_param("ApiKey")


def test_sensitive_param_false_for_normal():
    assert not is_sensitive_param("username")


def test_sensitive_param_false_for_empty():
    assert not is_sensitive_param("")


def test_sensitive_tool_positive_shellexec():
    assert is_sensitive_tool("shell_exec")


def test_sensitive_tool_positive_writepath():
    assert is_sensitive_tool("write_file")


def test_sensitive_tool_positive_fetch():
    assert is_sensitive_tool("fetch_url")


def test_sensitive_tool_negative_ping():
    assert not is_sensitive_tool("ping")


def test_sensitive_tool_negative_get_weather():
    assert not is_sensitive_tool("get_weather")


def test_sensitive_tool_handles_none():
    assert not is_sensitive_tool("")


def test_rules_roundtrip_tags():
    assert "rce" in RULES["MCP-001"].tags


def test_all_rule_ids_are_strings_in_expected_set():
    expected_ids = {f"MCP-{i:03d}" for i in range(1, 13)}
    assert set(RULES.keys()) == expected_ids
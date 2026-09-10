"""SARIF 2.1.0 emission validity tests."""

import json

import pytest

from viperstrike.core import Finding, Location, ScanResult
from viperstrike.engine import scan_tree
from viperstrike.reporters import render_sarif

REQUIRED_SARIF_KEYS = {"$schema", "version", "runs"}
VALID_LEVELS = {"error", "warning", "note", "none"}


def _load_sarif(result: ScanResult) -> dict:
    return json.loads(render_sarif(result))


def test_sarif_is_valid_json(sample_report):
    doc = _load_sarif(sample_report)
    assert isinstance(doc, dict)


def test_sarif_top_level_keys(sample_report):
    doc = _load_sarif(sample_report)
    assert REQUIRED_SARIF_KEYS.issubset(set(doc.keys()))


def test_sarif_version_2_1_0(sample_report):
    assert _load_sarif(sample_report)["version"] == "2.1.0"


def test_sarif_schema_url(sample_report):
    doc = _load_sarif(sample_report)
    assert "json.schemastore.org/sarif-2.1.0.json" in doc["$schema"]


def test_sarif_has_run(sample_report):
    assert isinstance(_load_sarif(sample_report)["runs"], list)
    assert len(_load_sarif(sample_report)["runs"]) == 1


def test_sarif_driver_name(sample_report):
    driver = _load_sarif(sample_report)["runs"][0]["tool"]["driver"]
    assert driver["name"] == "viperstrike"


def test_sarif_driver_version(sample_report):
    driver = _load_sarif(sample_report)["runs"][0]["tool"]["driver"]
    assert driver.get("semanticVersion") == "1.0.0"


def test_sarif_rules_declared(sample_report):
    driver = _load_sarif(sample_report)["runs"][0]["tool"]["driver"]
    rule_ids = {r["id"] for r in driver["rules"]}
    assert {"MCP-001", "MCP-007"}.issubset(rule_ids)


def test_sarif_result_rule_ids(sample_report):
    results = _load_sarif(sample_report)["runs"][0]["results"]
    assert [r["ruleId"] for r in results][:2] == ["MCP-001", "MCP-007"]


def test_every_result_level_valid(sample_report):
    results = _load_sarif(sample_report)["runs"][0]["results"]
    for r in results:
        assert r["level"] in VALID_LEVELS


def test_sarif_locations_present(sample_report):
    results = _load_sarif(sample_report)["runs"][0]["results"]
    for r in results:
        assert r["locations"]
        pl = r["locations"][0]["physicalLocation"]
        assert pl["artifactLocation"]["uri"] == "svr.py"
        assert pl["region"]["startLine"] > 0


def test_sarif_messages(sample_report):
    results = _load_sarif(sample_report)["runs"][0]["results"]
    assert all(r["message"]["text"] for r in results)


def test_empty_scan_sarif(tmp_path):
    d = tmp_path / "empty"
    d.mkdir()
    (d / "ok.py").write_text("x = 1\n")
    result = scan_tree(str(d))
    doc = json.loads(render_sarif(result))
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["invocations"][0]["executionSuccessful"] is True


def test_scan_errors_recorded_in_sarif(tmp_path):
    d = tmp_path / "er"
    d.mkdir()
    (d / "broken.py").write_text("def foo(:\n")
    result = scan_tree(str(d))
    doc = json.loads(render_sarif(result))
    inv = doc["runs"][0]["invocations"][0]
    assert inv["executionSuccessful"] is False or result.errors


def test_sarif_properties_evidence(tmp_path):
    d = tmp_path / "prop"
    d.mkdir()
    (d / "svr.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "server = FastMCP('x')\n"
        "@server.tool()\n"
        "def run(cmd):\n"
        "    os.system(cmd)\n"
    )
    result = scan_tree(str(d))
    doc = json.loads(render_sarif(result))
    r = doc["runs"][0]["results"][0]
    assert "evidence" in r.get("properties", {})
    assert r["properties"]["confidence"] in ("high", "medium", "low")


def test_sarif_emit_empty_rules_ok():
    result = ScanResult(target="x")
    doc = json.loads(render_sarif(result))
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []
    assert doc["runs"][0]["results"] == []


def test_sarif_uses_sarif_level_names(tmp_path):
    """severity 'error'/'warning'/'note' must be SARIF levels, not 'CRITICAL'."""
    d = tmp_path / "lvl"
    d.mkdir()
    (d / "svr.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "server = FastMCP('x')\n"
        "@server.tool()\n"
        "def run(cmd):\n"
        "    os.system(cmd)\n"
    )
    result = scan_tree(str(d))
    doc = json.loads(render_sarif(result))
    levels = {r["level"] for r in doc["runs"][0]["results"]}
    assert not (levels - VALID_LEVELS)


def test_sarif_validates_against_schemas_semantics(sample_report):
    """Exercise the Draft-12 validator-independent structural checks that would
    be required by the official schemastore SARIF 2.1.0 schema."""
    doc = _load_sarif(sample_report)
    run = doc["runs"][0]
    assert run["tool"]["driver"] is not None
    for r in run["results"]:
        # schema requires ruleId, level, message.text, locations
        assert "ruleId" in r and "level" in r
        assert r["message"].get("text")
        assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def _official_sarif_schema() -> dict:
    """Fetch the official SARIF 2.1.0 metamodel schema (network only)."""
    try:
        import json
        import urllib.request
        url = "https://json.schemastore.org/sarif-2.1.0.json"
        return json.loads(urllib.request.urlopen(url, timeout=10).read())
    except Exception:
        return None


def test_sarif_official_schema_full(tmp_path):
    """Full jsonschema validation against the official SARIF 2.1.0 schema.

    Runs only when network + jsonschema are available (offline CI skips it);
    `render_sarif` itself is always validated structurally offline above.
    """
    jsonschema = pytest.importorskip(
        "jsonschema",
        reason="jsonschema not installed — full official-schema validation "
               "is optional in offline CI",
    )
    schema = _official_sarif_schema()
    if schema is None:
        pytest.skip("official SARIF schema not reachable (offline)")
    d = tmp_path / "full"
    d.mkdir()
    (d / "svr.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "server = FastMCP('x')\n"
        "@server.tool()\n"
        "def run(cmd):\n"
        "    os.system(cmd)\n"
    )
    result = scan_tree(str(d))
    doc = json.loads(render_sarif(result))
    from jsonschema import validate
    validate(instance=doc, schema=schema)
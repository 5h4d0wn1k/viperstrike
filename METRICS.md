# METRICS — real measured numbers

All figures below were captured on a real local run (Python 3.13.5, Linux) on
2026-09-10 against the `main` tree of this repository. Nothing is fabricated;
rerun the commands listed under "How to reproduce" to verify.

## Source tree size

| Measure | Value |
| --- | --- |
| Python source files (`viperstrike/`, `tests/`, `examples/`) | 41 |
| Total lines of code (those files, `wc -l`) | 5 246 |
| Core package files under `viperstrike/` | 18 |
| Parser modules | 2 (`python_parser`, `js_parser`) |
| Detector modules | 12 (+ shared `helpers.py`, `base.py`) |
| Reporters | 3 formats (JSON, Markdown, SARIF 2.1.0) |
| Detection rules | 12 (MCP-001 .. MCP-012) |

## Test suite

| Measure | Value |
| --- | --- |
| Total tests run | 284 passed, 1 skipped (offline skip of online-only test) |
| Test files | 10 |
| Suite wall time | ~3.3 s |
| Required runtime (per test) | offline, no network, no target writes |

The single skipped test validates the SARIF report against the official OASIS
schema at `json.schemastore.org/sarif-2.1.0.json` and only runs when
`jsonschema` + network are present. Structural SARIF checks (ruleId, level,
message, locations, driver) always run offline in `tests/test_sarif.py`.

## SAST scan time

| Target | Files | Lines | Findings | Time |
| --- | --- | --- | --- | --- |
| Bundled demo server (`examples/sample_mcp_server`) | 1 | 157 | 25 | ~89 ms |
| Whole viperstrike repo (self-audit, sans reports/.venv) | 37 | 5 078 | 25 | ~2 384 ms |

Scan time scales linearly with file count; every finding in the full self-audit
originates from the intentionally vulnerable demo server, i.e. **the tool
reports 0 findings against its own production code**.

## First-scan findings breakdown (demo server, `examples/sample_mcp_server/sample_server.py`)

| Rule ID | Count | Severity |
| --- | --- | --- |
| MCP-001 shell/exec invocation | 1 | error |
| MCP-002 unsafe subprocess shell=True | 1 | error |
| MCP-003 arbitrary file write | 1 | warning |
| MCP-004 path traversal in read handler | 1 | warning |
| MCP-005 fetch / SSRF | 1 | warning |
| MCP-006 eval/exec/compile | 1 | error |
| MCP-007 secrets logged/echoed | 1 | warning |
| MCP-008 missing schema constraints | 5 | note |
| MCP-009 missing auth on sensitive tool | 9 | warning |
| MCP-010 dangerous default enabled | 1 | warning |
| MCP-011 SQL concatenation | 2 | warning |
| MCP-012 unsafe deserialization | 1 | error |
| **Total** | **25** | error=4, warning=14, note=7 |

The bundled demo is deliberately a worst-case server: 12 tool handlers, each a
textbook vulnerability, which is why MCP-008/MCP-009 (absence-based rules) fire
across nearly every handler.

## Demo runtime

`python3 -m viperstrike audit --demo --output reports`

- Exit code: `0`
- Artifacts written: `reports/audit_report.json`, `reports/audit_report.md`,
  `reports/audit_report.sarif`
- The SARIF file validates cleanly against the official 2.1.0 schemastore schema.

`python3 -m viperstrike oracle --demo --yes --output reports`

- Exit code: `0` (demo-exit-0) — no packets emitted, offline-safe.

## How to reproduce

```bash
python3 -m pytest tests/ -q           # test suite
python3 -m viperstrike audit --demo   # demo SAST run
python3 -m viperstrike oracle --demo --yes
```
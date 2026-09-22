> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.
# viperstrike

**MCP (Model Context Protocol) Server Vulnerability Auditor**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://github.com/5h4d0wn1k/viperstrike/actions/workflows/ci.yml/badge.svg)](https://github.com/5h4d0wn1k/viperstrike/actions)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](pyproject.toml)

`viperstrike` statically audits an **MCP server source tree** for vulnerable
tool handlers and produces **SARIF + JSON + Markdown** reports, plus an
optional runtime **oracle** mode that feeds a PoC prompt to a locally run
server (offline-safe: it degrades to a demo exit 0 when the server is
unreachable).

MCP servers are the fastest-growing agentic-AI attack surface: they translate
natural-language agent instructions into calls on real tools — shells, files,
HTTP, databases. Both the **US NSA** guidance (2025-2026) and the **OWASP
Agentic AI Top 10** call out MCP servers as a primary frontier. `viperstrike`
gives defenders (and authorized red teams) a fast, dependency-free way to
inventory that surface before an agent turns a `read_log("../etc/passwd")`
turn of phrase into a breach.

> **Authorized testing only.** Read `## Safety & Authorization` before
> touching this tool. Unauthorized probing is a crime in most jurisdictions.

## Features

- **12 built-in detection rules** (MCP-001..MCP-012) covering RCE via
  shell/subprocess/`eval`, arbitrary file write, path traversal, SSRF, SQL
  injection, unsafe deserialization, secret leakage, missing input-schema
  constraints, missing auth, and dangerous default-enabled tools.
- **Real Python AST analysis** (`ast` module) with light-weight **taint
  tracking** — it follows values from tool-handler arguments to sinks, through
  f-strings, `%`-formatting, `+` concatenation and intermediate variables.
- **MCP framework-aware**: detects handlers registered via
  `@server.tool()`, `@mcp.tool`, `@tool`, `FastMCP`, `Server(...)` so it is
  meaningful even before you tell it what to look for.
- **Minimal JavaScript / TypeScript support** via regex-level scanning of
  `server.tool(...)` / `@tool(...)` decorators and common sinks — enough for a
  first-pass inventory of JS MCP stacks.
- **Standard-library-only core** (Python 3.10+); `requests` is used only in
  optional live oracle mode and is import-guarded so the audit never requires
  it.
- **SARIF 2.1.0 output** that validates cleanly against the official OASIS
  schemastore schema — drop it into CodeQL, GitHub Advanced Security, or your
  favorite SARIF renderer.
- **Human-readable reports**: a Markdown findings table plus per-finding
  detail blocks with evidence snippets, CWE references and concrete fixes.
- **Strictly read-only engine**: `viperstrike` never writes to, executes, or
  modifies its target tree.
- **Offline-safe demo** (`--demo`) that audits a bundled deliberately
  vulnerable sample MCP server and exits 0, writing real reports — ideal for
  CI, education and first-run experience.
- **Safety-gated oracle**: runtime probing only talks to `localhost` /
  `127.0.0.1` / `::1`, requires an interactive approval prompt (`--yes` for
  demo/CI), and never contacts remote hosts.
- **Fast, offline test suite** (280+ tests) covering parsers, every sink,
  taint flows, credential handling, JSON-RPC tool-listing semantics, SARIF
  schema validity and the whole demo pipeline.

## Install

Requirements: **Python 3.10+**. No runtime dependencies for the core.

```bash
# from a checkout
python3 -m pip install -e .

# or vendor the single package directory
pip install viperstrike        # when published
```

The `viperstrike` console script is registered as an entry point. On systems
where the console script is unavailable (e.g. a read-only mount), run it
through the module:

```bash
python3 -m viperstrike --version
```

## Quick Start

Run the self-contained demo on the bundled (deliberately vulnerable) sample
MCP server:

```bash
cd viperstrike
python3 -m viperstrike audit --demo --output reports
```

Expected: exit code `0`, three files in `reports/`
(`audit_report.json`, `audit_report.md`, `audit_report.sarif`) reporting
**25 findings across all 12 rules** against the ~157-line sample server.

Then audit something real of yours (still read-only):

```bash
python3 -m viperstrike audit --target ./path/to/your/mcp/server --output reports
```

## Usage

```
usage: viperstrike [-h] [--version] [--target TARGET] [--output OUTPUT]
                   [--verbose] [--demo] COMMAND ...
```

Global flags (can appear before or after a subcommand):

| Flag | Default | Meaning |
| --- | --- | --- |
| `--target PATH` | bundled demo sample | Source tree/file to audit (or a prior JSON result for `report`/`sarif`) |
| `--output DIR` / `-o` | `./reports` | Where reports are written |
| `--verbose` / `-v` | off | Per-file scan progress |
| `--demo` | off | Self-contained offline demo; exits 0 and writes reports |

### Subcommands

- **`audit`** — static scan. Runs every detector and writes
  `audit_report.{json,md,sarif}`.

  ```bash
  viperstrike audit --target examples/sample_mcp_server -o reports
  ```

- **`oracle`** — runtime probe of a *locally run* MCP server. Applies the
  loopback-only safety gate, requires approval, and when the server is not
  reachable (or `--demo`) writes `oracle_demo.json` and exits 0 — no packets
  ever leave the machine.

  ```bash
  viperstrike oracle --url http://127.0.0.1:8765 --yes -o reports
  viperstrike oracle --demo --yes -o reports        # offline-safe demo
  ```

- **`sarif`** — convert an existing `audit_report.json` back into SARIF 2.1.0.

  ```bash
  viperstrike sarif --target reports/audit_report.json -o reports
  ```

- **`report`** — re-render an existing `audit_report.json` into JSON/MD (and
  SARIF). Useful after a rescan or for redistribution without re-auditing.

## Example Output

Real captured output from a demo run (`viperstrike audit --demo`):

```
[viperstrike] DEMO MODE — auditing bundled sample MCP server (examples/sample_mcp_server)
[viperstrike] demo complete — reports written to reports:
  - reports/audit_report.json
  - reports/audit_report.md
  - reports/audit_report.sarif
[viperstrike] 1 files, 157 lines, 25 findings (error=4 | note=6 | warning=15) in 92.8 ms
```

Report excerpt (`reports/audit_report.md`):

| Rule | Severity | Confidence | Location | Message |
|------|----------|------------|----------|---------|
| MCP-001 | error | high | `examples/sample_mcp_server/sample_server.py:55` | Tool handler 'shell_exec' invokes `os.system` — arbitrary shell command execution is possible via user-controlled arguments. |
| MCP-002 | error | high | `examples/sample_mcp_server/sample_server.py:62` | Function 'run_command' uses `subprocess.run` with shell=True — command injection risk. |
| MCP-005 | warning | medium | `examples/sample_mcp_server/sample_server.py:89` | Function 'fetch_url' fetches a URL derived from a user-supplied argument without a host allowlist — server-side request forgery (SSRF). |
| MCP-006 | error | high | `examples/sample_mcp_server/sample_server.py:97` | Tool handler 'evaluate' passes input to `eval` — arbitrary Python code execution is possible. |
| MCP-011 | warning | medium | `examples/sample_mcp_server/sample_server.py:133` | Handler 'delete_records' executes a SQL query built by string interpolation from user input — SQL injection (CWE-89). |

A full, live-captured example lives in [`METRICS.md`](METRICS.md) and in
`reports/` after any demo run.

## Detectors

Each rule produces findings with a SARIF level
(`error`=critical/high, `warning`=medium, `note`=low), a CWE, an evidence
snippet and a fix suggestion.

| Rule ID | Detector | CWE | Level |
| --- | --- | --- | --- |
| MCP-001 | Shell / exec invocation (`os.system`, `os.popen`, …) in a tool handler | CWE-78 | error |
| MCP-002 | Unsafe subprocess — `shell=True` or an interpolated command string | CWE-78 | error |
| MCP-003 | Arbitrary file write where the path is derived from a user argument | CWE-22 / CWE-73 | warning |
| MCP-004 | Path traversal in a read handler (`..` / absolute path escape) | CWE-22 | warning |
| MCP-005 | Fetch / SSRF to arbitrary URLs without a host allowlist | CWE-918 | warning |
| MCP-006 | `eval` / `exec` / `compile` on user-supplied input | CWE-95 | error |
| MCP-007 | Secret arguments (`password`, `token`, `api_key`, …) logged or echoed | CWE-532 | warning |
| MCP-008 | Tool params declared but never validated against a schema/allowlist | CWE-20 | note |
| MCP-009 | Authentication / capability bypass on sensitive tools (no auth check) | CWE-306 | warning |
| MCP-010 | Dangerous default — sensitive tool enabled by default | CWE-1188 | note |
| MCP-011 | SQL concatenation / interpolation in a database handler | CWE-89 | warning |
| MCP-012 | Unsafe deserialization (`pickle.loads`, `yaml.load`, …) | CWE-502 | error |

## How It Works

1. **Discovery** — a recursive walk of the target tree collects `.py` (and
   `.js/.ts` for the regex scanner), skipping `.git`, `.venv`, `node_modules`,
   caches and `reports/`.
2. **Parsing** — Python files are parsed with the `ast` module. The parser
   recognises MCP framework imports (`from mcp.server…`, `FastMCP`, `Server`),
   isolates `@tool`-decorated handlers and records params, defaults and line
   spans. JS/TS files get a regex-level map of `server.tool(...)` /
   `@tool(...)` registrations and sink keywords.
3. **Taint analysis** — each detector walks the function bodies and follows
   tool-handler arguments into sinks (`exec`, `open`, `urlopen`, `execute`,
   `pickle.loads`, loggers, …) through f-strings, `%`-formatting, string
   concatenation and intermediate assignments.
4. **Reporting** — findings are attached to exact file:line locations, ranked
   by level, and rendered to JSON, Markdown and SARIF 2.1.0 (schema-checked).
   The engine is never `eval`'d on target code and never writes to the target.
5. **Oracle (optional)** — a separate, approval-gated mode that sends a single
   PoC prompt to a user-specified localhost MCP server and records the outcome
   file; on any failure to reach the server it falls back to an offline demo
   report and still exits 0.

## Safety & Authorization

## IMPORTANT: Read before use.

> # IMPORTANT: Read before use.
>
> This is an **authorized security testing and education** tool. It is designed to be
> used exclusively against systems, networks, and hardware that **you own** or for which
> you have **explicit written authorization** to test.
>
> ## Authorization Requirements
>
> - Only test targets you own, your own accounts, or systems you have written permission
>   to assess (scope, duration, and limits in writing).
> - This tool defaults to **offline / simulation mode**. Any action that could affect a
>   real system, emit radio signals, or contact a real network requires an explicit
>   confirmation flag **and** membership of the configured LAB allowlist.
> - The demo/harness functionality runs entirely on localhost, fixtures, or your own lab.
>
> ## Legal Framework
>
> Unauthorized security testing is a crime in most jurisdictions, including:
>
> - **Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030** (US) — unauthorized
>   access to computers is a federal crime, punishable by up to 20 years imprisonment.
> - **Wiretap Act (18 U.S.C. § 2511)** (US) — intercepting electronic communications
>   without consent is illegal.
> - **EU Directive 2013/40/EU on attacks against information systems** — criminalises
>   illegal access and interference.
> - **State / local computer-crime statutes** — nearly all jurisdictions criminalise
>   unauthorised access, data theft, or network disruption.
> - **RF regulatory law** — transmitting on ISM bands without the appropriate
>   authorisation may violate terms of your licence/regulatory regime in your country.
>
> ## Acceptable Use
>
> - Learning and coursework in a controlled lab environment.
> - Authorised penetration testing and red/blue-team exercises with written scope.
> - Security research on systems you own.
> - Building defensive detections and hardening your own infrastructure.
>
> ## Prohibited Use
>
> - **Any** unauthorised access, interception, or disruption.
> - Use against third-party networks, devices, or systems at any time.
> - Removing or weakening the safety gates, allowlists, or legal notices.
> - Any activity that violates applicable law.
>
> ## No Warranty
>
> This software is provided "AS IS", without warranty of any kind, express or
> implied, including but not limited to the warranties of merchantability, fitness
> for a particular purpose, and non-infringement. **In no event shall the authors or
> copyright holders be liable** for any claim, damages or other liability arising
> from, out of, or in connection with the software or the use or other dealings in
> the software. **You are solely responsible for how you use this tool.**
>
> ## Responsible Disclosure
>
> If you discover real vulnerabilities while learning with this tool, follow
> responsible disclosure:
>
> 1. Report privately to the affected vendor/owner.
> 2. Give a reasonable remediation window.
> 3. Do not exploit beyond proof of concept.
> 4. Only publish with the vendor's consent.

Hard guarantees built into the tool:

- The **audit engine cannot modify its target**: it only opens files for
  reading. There is no write, execute or delete code path over a target.
- The **oracle subcommand is loopback-only**: hosts other than
  `localhost/127.0.0.1/::1` are rejected *before* any connection attempt, and
  an interactive approval prompt must be confirmed unless `--yes` is passed.
- The **demo never touches the network**; even the oracle demo performs a
  TCP probe of a *closed* loopback port and degrades cleanly to exit 0.
- There is **no filesystem-wide scanning** and **no external scanning**
  capability. Targets and oracle URLs are always explicit user input.

## Limitations

- **Static analysis is not proof.** A clean report reduces risk; it cannot
  prove a server is secure. Absence-based rules (MCP-008, MCP-009, MCP-010)
  are heuristic and can miss context-dependent controls (e.g. auth enforced
  by a framework middleware or an external gateway).
- **Python AST focus.** JavaScript/TypeScript support is intentionally
  regex-level — expect higher false-positive/noise there. Only Python gets
  taint-aware sinks.
- **Single-function taint depth.** Inter-procedural flows, decorator-level
  registrations in separate files, and dynamic dispatch are approximated, not
  fully resolved. Some sinks reached through helper functions are missed
  unless the helper is inlined.
- **FP/FN trade-offs.** Some detectors fire on middleware-wrapped handlers
  that are externally protected, and a few dangerous but obfuscated patterns
  (e.g. `getattr(__builtins__, 'ev'+'al')`) are below the heuristic floor.
- **No dependency analysis.** Import versions, framework patch levels and the
  goodness of vendored SDK code are out of scope for the core scanner.
- **Oracle probes are non-malicious PoCs only** — they confirm reachability
  and surface obvious misbehavior; they do not perform exploitation.

## Live Lab Test Plan

The following is for an **authorized local lab** to exercise the oracle mode
end-to-end. Requires a second machine or a VM for the "target"; keep host and
target on a private Wi-Fi or wired segment you control.

**Hardware / hosts required**

- Lab host running `viperstrike` (your workstation) and the `mcp` SDK
  (`pip install mcp`), connected to your lab Wi-Fi AP (e.g. an OpenWrt
  device on an isolated SSID) along with:
- A lab target: Raspberry Pi (or any Linux box) running an MCP server you
  control (start `examples/sample_mcp_server/sample_server.py` or your own),
  reachable at `http://<lab-host>:8765` only on the lab segment — **not** on
  your main network.
- A wired console connection to the Wi-Fi access point to capture flows if
  desired (optional; Wireshark on the AP's mirror port).

**Steps + expected results**

| # | Step | Expected result |
| --- | --- | --- |
| 1 | Static audit of your server source tree | `audit_report.sarif` produced; SARIF validates against 2.1.0 schema |
| 2 | Start the target MCP server on the lab box | Listens on `localhost:8765` inside the lab network |
| 3 | `viperstrike oracle --url http://<lab-host>:8765` (answer `n` first) | Aborts cleanly, exit code `2`, no traffic sent |
| 4 | Rerun answering `y` | PoC prompt dispatched once; `oracle_demo.json` written |
| 5 | Stop the server, run `oracle --demo --yes` | **Demo-exit-0**: graceful degradation, offline-safe report, exit code `0` |
| 6 | Point `--url` at `http://8.8.8.8:80` (or any non-loopback) | **Safety gate blocks it**: exit code `2`, error message, nothing sent |
| 7 | Scan Wi-Fi-only target from a different segment | Expected: nothing — viperstrike performs no wireless or external scanning, and cannot reach the server, which is itself the finding for an over-exposed agent stack |

Step 7 doubles as the honest test of the tool's hard boundary: if your agent
stack is reachable from public Wi-Fi, viperstrike will not tell you by
scanning — you must close that surface yourself. Removing or weakening the
loopback/no-scan gates is prohibited by the project's legal notice.

## Testing

The full suite runs **offline** and fast:

```bash
python3 -m pytest tests/ -q
```

Current state: **280+ tests passed** (see `METRICS.md`). Coverage areas:

- Python parser (decorators, params, defaults, malformed input, Unicode)
- JS/TS regex parser (decorator and `.tool()` discovery, imports)
- Sink detection for every rule (MCP-001 .. MCP-012) incl. positive *and*
  negative cases (parameterized SQL not flagged, `SafeLoader` not flagged…)
- Taint flows from tool args into sinks via f-strings / `%` / `+` / variables
- Credential-handler behavior (passwords/tokens/API keys logged or echoed)
- JSON-RPC `tools/list` schema semantics
- SARIF 2.1.0 structural validity plus optional official-schema validation
- Report rendering (JSON/MD/SARIF), engine robustness, CLI exit codes and
  demo mode end-to-end
- Oracle safety gates (loopback-only, approval prompt, offline degradation)

One test (`test_sarif_official_schema_full`) only runs when `jsonschema` and
network are available; it is skipped cleanly in offline CI and everything else
still passes.

## Roadmap

- **v1.1** — inter-procedural taint (follow helpers), decorator-registered
  auth policies, MCP server SDK version fingerprinting.
- **v1.2** — JSON-RPC `tools/list` conformance probing against local dev
  servers; structured `mcp` config-file (`mcp.json`) scanning.
- **v1.3** — stretch: hardened JavaScript/TypeScript parser (Babel-free
  tokenizer), Rust/go MCP server scanning, CWE/CVE correlation feeds.
- **v1.4** — remediation advisor: automatic patch snippets per rule, and
  `--fix` dry-run mode (still read-only) for CI workflows.

## License

MIT License — Copyright (c) 2026 5h4d0wn1k. See [LICENSE](LICENSE).
Additionally: [NOTICE.md](NOTICE.md), [SECURITY.md](SECURITY.md),
[CONTRIBUTING.md](CONTRIBUTING.md), [AUTHORS.md](AUTHORS.md), and real
measurement documentation in [METRICS.md](METRICS.md).

---

*viperstrike — because the fastest-growing agentic-AI attack surface deserves
a fast, honest, offline audit.*
# Security Policy

## Supported Versions

Only the latest release on the `main` branch receives security fixes. Backfilled
fixes are cut as patch releases on PyPI when published.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | Supported          |
| < 1.0   | Not supported      |

## Reporting a Vulnerability

viperstrike is an authorized-testing audit tool; nonetheless any bug that
produces a **false negative** (missing a real vulnerability), a **data leak**,
or an **unsafe action against a real system** is treated as a security issue.

Severity guidance:

- **Critical** — a false negative that hides RCE/SSRF/arbitrary-write in a tool
  handler, or any path that lets `oracle` probe beyond localhost.
- **High** — a false negative for medium-severity rules, or report output that
  leaks sensitive source excerpts unintentionally.
- **Low** — documentation gaps, cosmetic report defects, CI flakiness.

Please report privately to the maintainer (see AUTHORS.md). Do **not** open a
public issue for exploit-worthy findings. Include:

1. The rule / detector affected (if any).
2. A minimal reproduction source snippet (the demo server is a good baseline).
3. Expected vs. actual output.
4. Suggested fix if you have one.

The maintainer aims to triage within 7 days and to ship a fixed release within
30 days of confirmation. If you find a **real-world vulnerability in an MCP
server** with this tool, follow responsible disclosure: report privately to the
vendor, grant a reasonable remediation window, and never exploit beyond PoC.

## Safe-use commitments

- The audit engine is **strictly read-only** against its target tree.
- `oracle` mode only ever contacts `localhost` / `127.0.0.1` / `::1`, requires
  an explicit approval prompt, and degrades to an offline demo (exit 0) when
  the local server is unreachable.
- The project never ships network-scanning features. External MCP servers are
  out of scope by design.
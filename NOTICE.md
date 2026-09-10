NOTICE

viperstrike — MCP (Model Context Protocol) Server Vulnerability Auditor
Copyright (c) 2026 5h4d0wn1k
Licensed under the MIT License; see LICENSE for the full text.

Third-party notices
-------------------
viperstrike is a standard-library-first project. Its core (parsers, detectors,
engine, reporters, CLI) depends only on the Python 3.10+ standard library.

The optional `oracle` runtime mode may import the third-party `requests`
package to talk to a locally run MCP server. `requests` is import-guarded and
is NOT required for the core audit; when it is absent, remote connections are
skipped and oracle mode degrades gracefully to a safe offline demo.

The SARIF report format follows the OASIS SARIF 2.1.0 specification
(https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=sarif) and is
validated against the JSON Schema published at
https://json.schemastore.org/sarif-2.1.0.json.

All bundled test fixtures and the demo server under examples/ are
viperstrike-authored material for authorized, offline testing only.

THIS TOOL IS AUTHORIZED-TESTING ONLY. Misuse against systems you do not own
or have written permission to assess is unlawful and is neither supported nor
condoned.
# Contributing to viperstrike

Thanks for your interest in viperstrike, the MCP Server Vulnerability Auditor.
All contributions must keep the project's core principles intact:

- **Authorized testing only.** This tool audits MCP servers. Unauthorized
  probing is illegal and unwelcome here.
- **Offline, stdlib-first core.** New detectors must not require third-party
  packages in the audit path. The optional `requests` import in oracle mode is
  the only sanctioned exception and must remain import-guarded.
- **Read-only engine.** The audit must never modify its target.
- **No fabricated results.** Reports must reflect real detections with honest
  confidence levels.

## Getting started

1. Fork and clone the repository.
2. Create a branch: `git checkout -b feat/my-detector`.
3. Ensure Python 3.10+ and pytest:

   ```bash
   python3 -m pip install -e .
   python3 -m pytest
   ```

4. The whole suite must pass before opening a PR.

## Adding a detector

Detectors live in `viperstrike/detectors/`. Each rule wires through
`viperstrike/rules.py` (rule ID, severity, CWE, tags). A good detector:

- Uses the AST (`ast` module) against `MCPModule`, not string matching alone.
- Reports a clear `evidence` snippet and a concrete `fix_suggestion`.
- Ships at least a few unit/fixture tests in `tests/test_detectors.py` or a
  dedicated `tests/test_detectors_*.py` module.
- Prefers precise taint analysis over noisy heuristics; a false positive rate
  that buries real findings is a defect, not a feature.

## Coding standards

- Follow the existing style: type hints, dataclasses, `from __future__ import
  annotations`.
- No comments unless illuminating; prefer self-documenting names.
- Keep the tool importable on Python 3.10 with no third-party core deps.
- Update `README.md` `## Detectors` table and `METRICS.md` only with real
  measured numbers.

## Tests

- Tests must run fully offline and quickly.
- New behavior needs coverage; the suite currently targets 100+ tests.
- Run `python3 -m pytest tests/ -q` locally before pushing.
- CI runs the same command on Python 3.11 (see `.github/workflows/ci.yml`).

## Committing

- Follow the repository's commit style (`scaffold`, `core engine`,
  `detectors`, `reporters`, `tests`, `docs`, `ci`).
- Author identity is `5h4d0wn1k <5h4d0wn1k@users.noreply.github.com>`.
- Do not push to `main`; open a pull request instead.

## Contributor License (CLA)

By submitting a pull request, you agree that your contribution is licensed
under the MIT License (see `LICENSE`) and that the project maintainers may use
it in any way consistent with that license. This simple statement serves as
the project's contributor license agreement. If you represent a company and
need a signed corporate CLA, reach out via the issue tracker.
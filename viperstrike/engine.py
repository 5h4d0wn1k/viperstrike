"""Scan engine: orchestrates parsers and detectors over a target tree."""
from __future__ import annotations

import os
import time
from pathlib import Path

from viperstrike.core import ScanResult
from viperstrike.detectors import ALL_DETECTORS
from viperstrike.parsers.python_parser import parse_python_file, MCPModule
from viperstrike.parsers.js_parser import parse_js_file, JSMCPModule

PY_EXTENSIONS = {".py", ".pyw"}
JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}

SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".tox",
    ".mypy_cache", ".pytest_cache", "dist", "build", "env", ".env",
    "reports", ".github", "site-packages",
}

SKIP_FILES = {
    "__init__.py", "setup.py", "setup.cfg", "pyproject.toml", "tox.ini",
}


def _iter_target_files(root: Path, include_js: bool = True) -> list[Path]:
    files: list[Path] = []
    extensions = set(PY_EXTENSIONS)
    if include_js:
        extensions |= JS_EXTENSIONS

    if root.is_file():
        if root.suffix in extensions and root.name not in SKIP_FILES:
            files.append(root)
        return files

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            p = Path(dirpath) / f
            if p.suffix in extensions and f not in SKIP_FILES:
                files.append(p)
    files.sort(key=lambda p: str(p))
    return files


def scan_tree(target: str | Path, verbose: bool = False,
              include_js: bool = True) -> ScanResult:
    """Run the full static audit over a target directory or file."""
    target = Path(target)
    if not target.exists():
        raise FileNotFoundError(f"Target does not exist: {target}")

    start = time.monotonic()
    result = ScanResult(target=str(target))
    files = _iter_target_files(target, include_js=include_js)

    for path in files:
        try:
            if path.suffix in PY_EXTENSIONS:
                module = parse_python_file(path)
                if verbose:
                    print(f"[viperstrike] scanning {path} "
                          f"({len(module.tool_handlers)} handlers)")
                if module.parse_error:
                    result.add_error(f"{path}: {module.parse_error}")
                for detector_cls in ALL_DETECTORS:
                    detector = detector_cls(module)
                    for finding in detector.detect():
                        result.add_finding(finding)
            else:
                module = parse_js_file(path)
                if verbose:
                    print(f"[viperstrike] regex-scan {path} "
                          f"({len(module.tool_handlers)} handlers)")
                _js_heuristics(module, result)
        except FileNotFoundError:
            result.add_error(f"file vanished during scan: {path}")
        except Exception as exc:  # never let one file kill the audit
            result.add_error(f"{path}: {exc}")

    result.files_scanned = len(files)
    result.lines_scanned = sum(
        len(path.read_text(errors="replace").splitlines())
        for path in files if path.suffix in PY_EXTENSIONS
    )
    result.scan_time_ms = (time.monotonic() - start) * 1000.0

    result.findings.sort(key=lambda f: (f.severity, f.rule_id, f.locations[0].line))
    return result


def _js_heuristics(module: JSMCPModule, result: ScanResult) -> None:
    """Minimal regex-level checks for JS/TS MCP servers."""
    import re as _re

    from viperstrike.core import Location
    from viperstrike.rules import get_rule

    patterns = {
        "MCP-001": (
            r"(os\.system|child_process\.exec\s*\(|exec\s*\(\s*[`'\"])",
            "shell / exec invocation in tool handler",
        ),
        "MCP-006": (r"\beval\s*\([^)]*request|__proto__|constructor", "eval on input"),
        "MCP-011": (
            r"(?:db\.query|\.execute)\s*\(\s*[`'\"]",
            "SQL query built from interpolated string",
        ),
        "MCP-012": (r"pickle|node-serialize|JSON\.parse\s*\(\s*source",
                    "unsafe deserialization"),
    }
    source = module.raw_source
    for rule_id, (regex, desc) in patterns.items():
        for m in _re.finditer(regex, source):
            line = source[:m.start()].count("\n") + 1
            rule = get_rule(rule_id)
            if rule is None:
                continue
            result.add_finding(
                rule.adapter_js(module.path, line, desc)
            )
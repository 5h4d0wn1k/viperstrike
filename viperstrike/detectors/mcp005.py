"""MCP-005: Fetch / SSRF to arbitrary URLs."""
from __future__ import annotations

import ast
import re

from viperstrike.core import Finding
from viperstrike.detectors.base import Detector, function_defs, param_names
from viperstrike.detectors.helpers import (
    get_source_range,
    find_calls,
    resolve_call_name,
    call_uses_params,
    interpolated_string,
)
from viperstrike.rules import RULES

FETCH_CALLS = {
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.patch", "requests.head", "requests.request", "requests.getStream",
    "urllib.request.urlopen", "urllib.request.Request", "urllib.urlopen",
    "urlopen", "httpx.get", "httpx.post", "httpx.AsyncClient", "httpx.Client",
    "urlfetch.fetch", "aiohttp.ClientSession", "fetch", "http.request",
    "requests.Session.get", "requests.Session.post",
}

SQLIOWEBSITE_RE = re.compile(r"https?://|ftp://", re.IGNORECASE)


class SSRFDetector(Detector):
    rule = RULES["MCP-005"]

    def detect(self) -> list[Finding]:
        findings: list[Finding] = []
        if self.tree is None:
            return findings

        for func in function_defs(self.tree):
            params = param_names(func)
            handler_names = self.tool_handler_function_names()

            for call in find_calls(func, FETCH_CALLS):
                name = resolve_call_name(call)
                if name is None:
                    continue

                tainted = call_uses_params(call, params,
                                           param_name_hint="url")
                # URL arg constant that references internal host
                url_const = None
                for arg in (call.args or []):
                    s = interpolated_string(arg)
                    if s and SQLIOWEBSITE_RE.search(s):
                        url_const = s
                        break
                for kw in call.keywords:
                    if kw.arg in ("url", "endpoint") and isinstance(kw.value, ast.Constant):
                        url_const = str(kw.value.value)

                internal_host = bool(url_const) and self._is_internal(url_const)

                if tainted and (func.name in handler_names or self.module_has_mcp_markers()):
                    line = getattr(call, "lineno", func.lineno)
                    evidence = get_source_range(
                        self.module.lines, line, line + 2)
                    findings.append(self.finding(
                        message=(f"Function '{func.name}' fetches a URL derived "
                                 "from a user-supplied argument without a host "
                                 "allowlist — server-side request forgery (SSRF)."),
                        locations=[self.loc(line)],
                        evidence=evidence.strip(),
                        fix_suggestion=(
                            "Pin the destination host/port with an explicit "
                            "allowlist and reject internal ranges (127.0.0.0/8, "
                            "169.254.169.254, 10.0.0.0/8, 172.16.0.0/12, "
                            "192.168.0.0/16, metadataservers)."
                        ),
                    ))
                elif internal_host and func.name in handler_names:
                    line = getattr(call, "lineno", func.lineno)
                    evidence = get_source_range(
                        self.module.lines, line, line + 2)
                    findings.append(self.finding(
                        message=(f"Fetch in handler '{func.name}' targets internal "
                                 "host from a hard-coded URL without allowlist."),
                        locations=[self.loc(line)],
                        evidence=evidence.strip(),
                        fix_suggestion="Move the URL to a config allowlist.",
                    ))
        return findings

    def _is_internal(self, url: str) -> bool:
        lowered = url.lower()
        internal_markers = (
            "127.0.0.1", "localhost", "::1", "10.", "192.168.", "172.16.",
            "169.254.169.254", "metadata.google.internal", "0.0.0.0",
            "internal", "private", "test-server",
        )
        return any(m in lowered for m in internal_markers)
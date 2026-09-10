"""MCP-012: Unsafe deserialization (pickle / yaml.load)."""
from __future__ import annotations

import ast

from viperstrike.core import Finding
from viperstrike.detectors.base import Detector, function_defs, param_names
from viperstrike.detectors.helpers import (
    get_source_range,
    find_calls,
    resolve_call_name,
    call_uses_params,
)
from viperstrike.rules import RULES

UNSAFE_DESERIALIZE_CALLS = {
    "pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load",
    "yaml.load", "yaml.unsafe_load", "marshal.loads", "marshal.load",
    "joblib.load", "shelve.open", "torch.load",
}


class DeserializationDetector(Detector):
    rule = RULES["MCP-012"]

    def detect(self) -> list[Finding]:
        findings: list[Finding] = []
        if self.tree is None:
            return findings

        for func in function_defs(self.tree):
            params = param_names(func)
            handler_names = self.tool_handler_function_names()

            for call in find_calls(func, UNSAFE_DESERIALIZE_CALLS):
                name = resolve_call_name(call)
                if name is None:
                    continue

                # yaml.load with explicit SafeLoader is acceptable
                if name == "yaml.load":
                    safe = False
                    for kw in call.keywords:
                        if kw.arg == "Loader":
                            if isinstance(kw.value, ast.Name):
                                safe = "SafeLoader" in kw.value.id
                            elif isinstance(kw.value, ast.Attribute):
                                safe = "SafeLoader" in kw.value.attr
                    if safe:
                        continue

                # numpy.load with allow_pickle=False is acceptable
                if name in ("numpy.load", "np.load"):
                    ok = False
                    for kw in call.keywords:
                        if kw.arg == "allow_pickle" and isinstance(kw.value, ast.Constant):
                            if kw.value.value is False:
                                ok = True
                    if ok:
                        continue

                line = getattr(call, "lineno", func.lineno)
                evidence = get_source_range(
                    self.module.lines, line, line + 2)
                findings.append(self.finding(
                    message=(f"Function '{func.name}' deserializes data via `{name}` "
                             "in a tool handler — unsafe deserialization can "
                             "achieve remote code execution (CWE-502)."),
                    locations=[self.loc(line)],
                    evidence=evidence.strip(),
                    fix_suggestion=(
                        "Never unpickle untrusted input. Use JSON or a safe loader "
                        "and validate the data shape before use."
                    ),
                ))
        return findings
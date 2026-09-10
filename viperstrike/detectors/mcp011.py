"""MCP-011: SQL concatenation in a database handler."""
from __future__ import annotations

import ast

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

EXEC_CALLS = {
    "execute", "executemany", "executescript", "conn.execute", "conn.executemany",
    "cursor.execute", "cursor.executemany", "cur.execute", "db.execute",
    "db.query", "session.execute", "self.conn.execute", "self.cursor.execute",
    "connection.execute", "psycopg2.connect",
}
EXEC_CALL_SUFFIXES = {"execute", "executemany", "executescript", "query"}

SQL_KEYWORDS = ("select", "insert", "update", "delete", "from", "where", "join")

_SEARCH_CALLS = EXEC_CALLS | EXEC_CALL_SUFFIXES


def _sql_call_names() -> set:
    return _SEARCH_CALLS


def _sql_calls(func) -> list[ast.Call]:
    """Return DB-exec calls: known names or `x.<exec-suffix>(...)`."""
    calls = []
    for n in ast.walk(func):
        if not isinstance(n, ast.Call):
            continue
        name = resolve_call_name(n)
        if name in EXEC_CALLS:
            calls.append(n)
            continue
        if isinstance(n.func, ast.Attribute) and n.func.attr in EXEC_CALL_SUFFIXES:
            calls.append(n)
    return calls


class SQLInjectionDetector(Detector):
    rule = RULES["MCP-011"]

    def detect(self) -> list[Finding]:
        findings: list[Finding] = []
        if self.tree is None:
            return findings

        for func in function_defs(self.tree):
            params = param_names(func)
            handler_names = self.tool_handler_function_names()
            tainted_vars = self._tainted_vars(func, params)

            for call in _sql_calls(func):
                name = resolve_call_name(call) or getattr(
                    getattr(call.func, "attr", None), "value", None)

                query_exprs = list(call.args)
                for kw in call.keywords:
                    if kw.arg in ("query", "sql"):
                        query_exprs.append(kw.value)

                # Parameterized queries (values passed via ? placeholders) are safe
                param_supplied = len(call.args) > 1 or any(
                    kw.arg in ("params", "parameters", "args", "parameters_bind")
                    for kw in call.keywords
                )
                if param_supplied:
                    continue

                for expr in query_exprs:
                    tainted = call_uses_params(call, params) or \
                        self._expr_has_param(expr, params) or \
                        self._expr_refs_tainted_var(expr, tainted_vars)
                    sql_like = self._is_sql_string(expr)

                    if not (tainted and sql_like):
                        continue
                    if not (func.name in handler_names or self.module.has_mcp_import):
                        continue

                    line = getattr(call, "lineno", func.lineno)
                    evidence = get_source_range(
                        self.module.lines, line, line + 2)
                    findings.append(self.finding(
                        message=(f"Handler '{func.name}' executes a SQL query built "
                                 "by string interpolation from user input — "
                                 "SQL injection (CWE-89)."),
                        locations=[self.loc(line)],
                        evidence=evidence.strip(),
                        fix_suggestion=(
                            "Use parameterized queries / placeholders exclusively "
                            "and treat every tool argument as untrusted."
                        ),
                    ))
        return findings

    def _expr_has_param(self, expr, params: set[str]) -> bool:
        for n in ast.walk(expr):
            if isinstance(n, ast.Name) and n.id in params:
                return True
        return False

    def _tainted_vars(self, func, params: set[str]) -> set[str]:
        """Names assigned from an expression that references a param."""
        tainted: set[str] = set()
        for n in ast.walk(func):
            if isinstance(n, ast.Assign) and self._expr_has_param(n.value, params):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        tainted.add(t.id)
            if (isinstance(n, ast.AnnAssign) and n.value is not None
                    and self._expr_has_param(n.value, params)
                    and isinstance(n.target, ast.Name)):
                tainted.add(n.target.id)
        return tainted

    def _expr_refs_tainted_var(self, expr, tainted: set[str]) -> bool:
        for n in ast.walk(expr):
            if isinstance(n, ast.Name) and n.id in tainted:
                return True
        return False

    def _is_sql_string(self, expr) -> bool:
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return any(kw in expr.value.lower() for kw in SQL_KEYWORDS)
        if isinstance(expr, ast.JoinedStr):
            joined = "".join(
                v.value for v in expr.values
                if isinstance(v, ast.Constant) and isinstance(v.value, str)
            ).lower()
            return any(kw in joined for kw in SQL_KEYWORDS)
        if isinstance(expr, ast.BinOp):
            return self._is_sql_string(expr.left) or self._is_sql_string(expr.right)
        return True
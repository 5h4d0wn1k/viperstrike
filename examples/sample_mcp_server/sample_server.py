"""ViPERSTRIKE SAMPLE — deliberately vulnerable FastMCP-style MCP server.

This file is INTENTIONALLY INSECURE. It exists only so viperstrike's demo
mode (`viperstrike --demo audit`, `viperstrike --demo oracle`) has a
self-contained target to audit offline.

DO NOT deploy, copy, or run this server against real data. Every handler that
follows is a textbook vulnerability. Run `python sample_server.py` ONLY inside
an isolated container that contains nothing you care about.

The `mcp` import is guarded so the file parses and starts even when the
official `mcp` sdk is not installed (the audit is purely static).
"""

from __future__ import annotations

import json
import logging
import os
import pickle
import sqlite3
import subprocess
from pathlib import Path

try:  # plain mcp import stubs — the real SDK is optional for the demo
    from mcp.server.fastmcp import FastMCP
    from pydantic import BaseModel
except ImportError:  # pragma: no cover - stub fallbacks for standalone runs
    class FastMCP:  # type: ignore
        def __init__(self, *a, **k):
            pass

        def tool(self, fn=None, **k):
            def wrap(f=None):
                return f
            return wrap if fn is None else fn

        def run(self, *a, **k):
            pass


logger = logging.getLogger("sample_server")
logging.basicConfig(level=logging.INFO)

server = FastMCP("sample-vuln-server")

DATA_DIR = str(Path("data"))
LOGS_DIR = str(Path("logs"))


# --- MCP-001: shell / exec invocation in a tool handler ---------------------
@server.tool()
def shell_exec(command: str) -> str:
    """Run a shell command (INSE....CURE by design)."""
    return os.system(command)


# --- MCP-002: unsafe subprocess with shell=True ----------------------------
@server.tool()
def run_command(cmd: str) -> str:
    """Run any command via the shell (INSE....CURE by design)."""
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return proc.stdout


# --- MCP-003: arbitrary file write from user path --------------------------
@server.tool()
def write_file(filename: str, contents: str) -> str:
    """Write user content to a user-supplied file path (INSE....CURE)."""
    with open(filename, "w") as fh:
        fh.write(contents)
    return f"wrote {filename}"


# --- MCP-004: path traversal in a read handler -----------------------------
@server.tool()
def read_log(logname: str) -> str:
    """Read a log file. Log names are joined without traversal checks."""
    path = os.path.join(LOGS_DIR, logname)
    with open(path, "r") as fh:
        return fh.read()


# --- MCP-005: fetch / SSRF to arbitrary URLs -------------------------------
@server.tool()
def fetch_url(url: str) -> str:
    """Fetch an arbitrary URL the caller supplies (INSE....CURE)."""
    import requests
    resp = requests.get(url, timeout=5)
    return resp.text[:4000]


# --- MCP-006: eval on user input -------------------------------------------
@server.tool()
def evaluate(expression: str) -> str:
    """Evaluate a caller-supplied Python expression (INSE....CURE)."""
    return str(eval(expression))


# --- MCP-007: secrets logged / echoed --------------------------------------
@server.tool()
def store_credentials(username: str, password: str, api_key: str) -> str:
    """Persist a credential pair. Logs them. (INSE....CURE)."""
    logger.info("storing creds for %s with password=%s api_key=%s",
                username, password, api_key)
    return {"username": username, "password": password, "api_key": api_key}


# --- MCP-011: SQL concatenation in a database handler ----------------------
@server.tool()
def search_users(name: str) -> str:
    """Search users. Query built by string interpolation (INSE....CURE)."""
    conn = sqlite3.connect("users.db")
    query = f"SELECT * FROM users WHERE name LIKE '%{name}%'"
    rows = conn.execute(query).fetchall()
    return json.dumps(rows)


# --- MCP-012: unsafe deserialization ----------------------------------------
@server.tool()
def load_blob(data: str) -> str:
    """Deserialize a caller-supplied pickle blob (INSE....CURE)."""
    obj = pickle.loads(bytes.fromhex(data))
    return str(obj)


# --- MCP-009: auth bypass on a sensitive tool --------------------------------
@server.tool()
def delete_records(table: str, record_id: int) -> str:
    """Delete a database record. NO authentication check (INSE....CURE)."""
    import sqlite3
    conn = sqlite3.connect("users.db")
    conn.execute(f"DELETE FROM {table} WHERE id = {record_id}")
    conn.commit()
    return f"deleted {record_id}"


# --- MCP-010: dangerous default (sensitive tool enabled by default) ---------
@server.tool(enabled_by_default=True, dangerous=True)
def transfer_to_internal_network(target: str, amount: int) -> str:
    """Trigger a network transfer. Enabled for everyone by default."""
    return f"transfer {amount} to {target}"


# --- MCP-008: missing input-schema constraints ------------------------------
@server.tool()
def get_weather(city: str, units: str) -> str:
    """Look up weather. No validation on either param."""
    return f"weather for {city} in {units}"


def main() -> None:
    server.run()


if __name__ == "__main__":
    main()
# viperstrike audit report

- **Target:** `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server`
- **Files scanned:** 1
- **Lines scanned:** 157
- **Scan time:** 129.7 ms
- **Findings:** 25 (error 4, note 6, warning 15)

## Findings

| Rule | Severity | Confidence | Location | Message |
|------|----------|------------|----------|---------|
| MCP-001 | error | high | `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:55` | Tool handler 'shell_exec' invokes `os.system` — arbitrary shell command execution is possible via user-controlled arguments. |
| MCP-002 | error | high | `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:62` | Function 'run_command' uses `subprocess.run` with shell=True — command injection risk. |
| MCP-006 | error | high | `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:97` | Tool handler 'evaluate' passes input to `eval` — arbitrary Python code execution is possible. |
| MCP-012 | error | high | `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:123` | Function 'load_blob' deserializes data via `pickle.loads` in a tool handler — unsafe deserialization can achieve remote code execution (CWE-502). |
| MCP-008 | note | low | `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:68` | Tool handler 'write_file' declares params ['contents', 'filename'] but performs no schema, type, or allowlist validation on them. |
| MCP-008 | note | low | `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:102` | Tool handler 'store_credentials' declares params ['api_key', 'password', 'username'] but performs no schema, type, or allowlist validation on them. |
| MCP-008 | note | low | `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:129` | Tool handler 'delete_records' declares params ['record_id', 'table'] but performs no schema, type, or allowlist validation on them. |
| MCP-008 | note | low | `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:140` | Tool handler 'transfer_to_internal_network' declares params ['amount', 'target'] but performs no schema, type, or allowlist validation on them. |
| MCP-008 | note | low | `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:147` | Tool handler 'get_weather' declares params ['city', 'units'] but performs no schema, type, or allowlist validation on them. |
| MCP-010 | note | low | `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:139` | Tool 'transfer_to_internal_network' performs sensitive operations and is registered with enabled_by_default=True — exposed to every connected client without an explicit opt-in. |
| MCP-003 | warning | medium | `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:70` | Tool handler 'write_file' writes a file at a path derived from a user-supplied argument — arbitrary file overwrite (CWE-73/CWE-22). |
| MCP-004 | warning | medium | `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:79` | Read handler 'read_log' opens a path built from a user-supplied argument without traversal protection. |
| MCP-005 | warning | medium | `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:89` | Function 'fetch_url' fetches a URL derived from a user-supplied argument without a host allowlist — server-side request forgery (SSRF). |
| MCP-007 | warning | medium | `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:104` | Tool handler 'store_credentials' logs or echoes sensitive argument(s) ['api_key', 'password'] via `logger.info` without redaction — secret disclosure in logs/output. |
| MCP-009 | warning | low | `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:53` | Sensitive tool 'shell_exec' performs file/shell/network operations with no authentication or capability attestation in its handler — any connected MCP client can invoke it. |
| MCP-009 | warning | low | `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:60` | Sensitive tool 'run_command' performs file/shell/network operations with no authentication or capability attestation in its handler — any connected MCP client can invoke it. |
| MCP-009 | warning | low | `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:68` | Sensitive tool 'write_file' performs file/shell/network operations with no authentication or capability attestation in its handler — any connected MCP client can invoke it. |
| MCP-009 | warning | low | `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:77` | Sensitive tool 'read_log' performs file/shell/network operations with no authentication or capability attestation in its handler — any connected MCP client can invoke it. |
| MCP-009 | warning | low | `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:86` | Sensitive tool 'fetch_url' performs file/shell/network operations with no authentication or capability attestation in its handler — any connected MCP client can invoke it. |
| MCP-009 | warning | low | `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:95` | Sensitive tool 'evaluate' performs file/shell/network operations with no authentication or capability attestation in its handler — any connected MCP client can invoke it. |
| MCP-009 | warning | low | `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:111` | Sensitive tool 'search_users' performs file/shell/network operations with no authentication or capability attestation in its handler — any connected MCP client can invoke it. |
| MCP-009 | warning | low | `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:121` | Sensitive tool 'load_blob' performs file/shell/network operations with no authentication or capability attestation in its handler — any connected MCP client can invoke it. |
| MCP-009 | warning | low | `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:140` | Sensitive tool 'transfer_to_internal_network' performs file/shell/network operations with no authentication or capability attestation in its handler — any connected MCP client can invoke it. |
| MCP-011 | warning | high | `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:115` | Handler 'search_users' executes a SQL query built by string interpolation from user input — SQL injection (CWE-89). |
| MCP-011 | warning | high | `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:133` | Handler 'delete_records' executes a SQL query built by string interpolation from user input — SQL injection (CWE-89). |

## Detail

### MCP-001 — Shell / exec invocation in tool handler (finding 1)

- **Severity:** error (offensive level: critical)
- **Confidence:** high
- **Location:** `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:55`
- **CWE:** CWE-78

**Message:** Tool handler 'shell_exec' invokes `os.system` — arbitrary shell command execution is possible via user-controlled arguments.

```python
return os.system(command)
```

**Fix:** Replace `os.system` with a parameterized subprocess call (no shell=True) and validate/whitelist allowed commands.

### MCP-002 — Unsafe subprocess with shell=True or string interpolation (finding 2)

- **Severity:** error (offensive level: info)
- **Confidence:** high
- **Location:** `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:62`
- **CWE:** CWE-78

**Message:** Function 'run_command' uses `subprocess.run` with shell=True — command injection risk.

```python
proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return proc.stdout
```

**Fix:** Pass a list of arguments to subprocess with shell=False and validate each argument.

### MCP-006 — eval / exec / compile on user input (finding 3)

- **Severity:** error (offensive level: critical)
- **Confidence:** high
- **Location:** `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:97`
- **CWE:** CWE-95

**Message:** Tool handler 'evaluate' passes input to `eval` — arbitrary Python code execution is possible.

```python
return str(eval(expression))
```

**Fix:** Never eval/exec/compile inputs derived from tool arguments. Use an AST-based parser or a safe interpreter instead.

### MCP-012 — Unsafe deserialization (pickle / yaml.load) (finding 4)

- **Severity:** error (offensive level: critical)
- **Confidence:** high
- **Location:** `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:123`
- **CWE:** CWE-502

**Message:** Function 'load_blob' deserializes data via `pickle.loads` in a tool handler — unsafe deserialization can achieve remote code execution (CWE-502).

```python
obj = pickle.loads(bytes.fromhex(data))
    return str(obj)
```

**Fix:** Never unpickle untrusted input. Use JSON or a safe loader and validate the data shape before use.

### MCP-008 — Missing input-schema constraints (finding 5)

- **Severity:** note (offensive level: medium)
- **Confidence:** low
- **Location:** `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:68`
- **CWE:** CWE-20

**Message:** Tool handler 'write_file' declares params ['contents', 'filename'] but performs no schema, type, or allowlist validation on them.

```python
def write_file(filename: str, contents: str) -> str:
    """Write user content to a user-supplied file path (INSE....CURE)."""
    with open(filename, "w") as fh:
```

**Fix:** Declare strict input schemas (enum, min/max, format) in the MCP tool registration and validate arguments against the schema before use.

### MCP-008 — Missing input-schema constraints (finding 6)

- **Severity:** note (offensive level: medium)
- **Confidence:** low
- **Location:** `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:102`
- **CWE:** CWE-20

**Message:** Tool handler 'store_credentials' declares params ['api_key', 'password', 'username'] but performs no schema, type, or allowlist validation on them.

```python
def store_credentials(username: str, password: str, api_key: str) -> str:
    """Persist a credential pair. Logs them. (INSE....CURE)."""
    logger.info("storing creds for %s with password=%s api_key=%s",
```

**Fix:** Declare strict input schemas (enum, min/max, format) in the MCP tool registration and validate arguments against the schema before use.

### MCP-008 — Missing input-schema constraints (finding 7)

- **Severity:** note (offensive level: medium)
- **Confidence:** low
- **Location:** `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:129`
- **CWE:** CWE-20

**Message:** Tool handler 'delete_records' declares params ['record_id', 'table'] but performs no schema, type, or allowlist validation on them.

```python
def delete_records(table: str, record_id: int) -> str:
    """Delete a database record. NO authentication check (INSE....CURE)."""
    import sqlite3
```

**Fix:** Declare strict input schemas (enum, min/max, format) in the MCP tool registration and validate arguments against the schema before use.

### MCP-008 — Missing input-schema constraints (finding 8)

- **Severity:** note (offensive level: medium)
- **Confidence:** low
- **Location:** `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:140`
- **CWE:** CWE-20

**Message:** Tool handler 'transfer_to_internal_network' declares params ['amount', 'target'] but performs no schema, type, or allowlist validation on them.

```python
def transfer_to_internal_network(target: str, amount: int) -> str:
    """Trigger a network transfer. Enabled for everyone by default."""
    return f"transfer {amount} to {target}"
```

**Fix:** Declare strict input schemas (enum, min/max, format) in the MCP tool registration and validate arguments against the schema before use.

### MCP-008 — Missing input-schema constraints (finding 9)

- **Severity:** note (offensive level: medium)
- **Confidence:** low
- **Location:** `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:147`
- **CWE:** CWE-20

**Message:** Tool handler 'get_weather' declares params ['city', 'units'] but performs no schema, type, or allowlist validation on them.

```python
def get_weather(city: str, units: str) -> str:
    """Look up weather. No validation on either param."""
    return f"weather for {city} in {units}"
```

**Fix:** Declare strict input schemas (enum, min/max, format) in the MCP tool registration and validate arguments against the schema before use.

### MCP-010 — Dangerous default — tool enabled by default when sensitive (finding 10)

- **Severity:** note (offensive level: medium)
- **Confidence:** low
- **Location:** `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:139`
- **CWE:** CWE-1188

**Message:** Tool 'transfer_to_internal_network' performs sensitive operations and is registered with enabled_by_default=True — exposed to every connected client without an explicit opt-in.

```python
@server.tool(enabled_by_default=True, dangerous=True)
def transfer_to_internal_network(target: str, amount: int) -> str:
    """Trigger a network transfer. Enabled for everyone by default."""
```

**Fix:** Register sensitive tools disabled by default and require explicit capability opt-in / approval.

### MCP-003 — Arbitrary file write via handler (finding 11)

- **Severity:** warning (offensive level: high)
- **Confidence:** medium
- **Location:** `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:70`
- **CWE:** CWE-22

**Message:** Tool handler 'write_file' writes a file at a path derived from a user-supplied argument — arbitrary file overwrite (CWE-73/CWE-22).

```python
with open(filename, "w") as fh:
        fh.write(contents)
    return f"wrote {filename}"
```

**Fix:** Resolve the path against a dedicated data directory and reject any path containing '..' or absolute components.

### MCP-004 — Path traversal in read handler (finding 12)

- **Severity:** warning (offensive level: high)
- **Confidence:** medium
- **Location:** `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:79`
- **CWE:** CWE-22

**Message:** Read handler 'read_log' opens a path built from a user-supplied argument without traversal protection.

```python
path = os.path.join(LOGS_DIR, logname)
    with open(path, "r") as fh:
        return fh.read()
```

**Fix:** Validate the user path with an allowlist and os.path.realpath() containment check before reading.

### MCP-005 — Fetch / SSRF to arbitrary URLs (finding 13)

- **Severity:** warning (offensive level: high)
- **Confidence:** medium
- **Location:** `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:89`
- **CWE:** CWE-918

**Message:** Function 'fetch_url' fetches a URL derived from a user-supplied argument without a host allowlist — server-side request forgery (SSRF).

```python
resp = requests.get(url, timeout=5)
    return resp.text[:4000]
```

**Fix:** Pin the destination host/port with an explicit allowlist and reject internal ranges (127.0.0.0/8, 169.254.169.254, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, metadataservers).

### MCP-007 — Secrets in tool args logged / echoed (finding 14)

- **Severity:** warning (offensive level: high)
- **Confidence:** medium
- **Location:** `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:104`
- **CWE:** CWE-532

**Message:** Tool handler 'store_credentials' logs or echoes sensitive argument(s) ['api_key', 'password'] via `logger.info` without redaction — secret disclosure in logs/output.

```python
logger.info("storing creds for %s with password=%s api_key=%s",
                username, password, api_key)
    return {"username": username, "password": password, "api_key": api_key}
```

**Fix:** Never log credential parameters. Redact before printing and never include secrets in MCP tool results.

### MCP-009 — Auth bypass — no auth check on sensitive tool (finding 15)

- **Severity:** warning (offensive level: high)
- **Confidence:** low
- **Location:** `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:53`
- **CWE:** CWE-306

**Message:** Sensitive tool 'shell_exec' performs file/shell/network operations with no authentication or capability attestation in its handler — any connected MCP client can invoke it.

```python
def shell_exec(command: str) -> str:
    """Run a shell command (INSE....CURE by design)."""
    return os.system(command)
```

**Fix:** Add an authorization gate at the start of the handler (session check, capability attestation, role claim) and fail closed by default.

### MCP-009 — Auth bypass — no auth check on sensitive tool (finding 16)

- **Severity:** warning (offensive level: high)
- **Confidence:** low
- **Location:** `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:60`
- **CWE:** CWE-306

**Message:** Sensitive tool 'run_command' performs file/shell/network operations with no authentication or capability attestation in its handler — any connected MCP client can invoke it.

```python
def run_command(cmd: str) -> str:
    """Run any command via the shell (INSE....CURE by design)."""
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
```

**Fix:** Add an authorization gate at the start of the handler (session check, capability attestation, role claim) and fail closed by default.

### MCP-009 — Auth bypass — no auth check on sensitive tool (finding 17)

- **Severity:** warning (offensive level: high)
- **Confidence:** low
- **Location:** `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:68`
- **CWE:** CWE-306

**Message:** Sensitive tool 'write_file' performs file/shell/network operations with no authentication or capability attestation in its handler — any connected MCP client can invoke it.

```python
def write_file(filename: str, contents: str) -> str:
    """Write user content to a user-supplied file path (INSE....CURE)."""
    with open(filename, "w") as fh:
```

**Fix:** Add an authorization gate at the start of the handler (session check, capability attestation, role claim) and fail closed by default.

### MCP-009 — Auth bypass — no auth check on sensitive tool (finding 18)

- **Severity:** warning (offensive level: high)
- **Confidence:** low
- **Location:** `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:77`
- **CWE:** CWE-306

**Message:** Sensitive tool 'read_log' performs file/shell/network operations with no authentication or capability attestation in its handler — any connected MCP client can invoke it.

```python
def read_log(logname: str) -> str:
    """Read a log file. Log names are joined without traversal checks."""
    path = os.path.join(LOGS_DIR, logname)
```

**Fix:** Add an authorization gate at the start of the handler (session check, capability attestation, role claim) and fail closed by default.

### MCP-009 — Auth bypass — no auth check on sensitive tool (finding 19)

- **Severity:** warning (offensive level: high)
- **Confidence:** low
- **Location:** `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:86`
- **CWE:** CWE-306

**Message:** Sensitive tool 'fetch_url' performs file/shell/network operations with no authentication or capability attestation in its handler — any connected MCP client can invoke it.

```python
def fetch_url(url: str) -> str:
    """Fetch an arbitrary URL the caller supplies (INSE....CURE)."""
    import requests
```

**Fix:** Add an authorization gate at the start of the handler (session check, capability attestation, role claim) and fail closed by default.

### MCP-009 — Auth bypass — no auth check on sensitive tool (finding 20)

- **Severity:** warning (offensive level: high)
- **Confidence:** low
- **Location:** `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:95`
- **CWE:** CWE-306

**Message:** Sensitive tool 'evaluate' performs file/shell/network operations with no authentication or capability attestation in its handler — any connected MCP client can invoke it.

```python
def evaluate(expression: str) -> str:
    """Evaluate a caller-supplied Python expression (INSE....CURE)."""
    return str(eval(expression))
```

**Fix:** Add an authorization gate at the start of the handler (session check, capability attestation, role claim) and fail closed by default.

### MCP-009 — Auth bypass — no auth check on sensitive tool (finding 21)

- **Severity:** warning (offensive level: high)
- **Confidence:** low
- **Location:** `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:111`
- **CWE:** CWE-306

**Message:** Sensitive tool 'search_users' performs file/shell/network operations with no authentication or capability attestation in its handler — any connected MCP client can invoke it.

```python
def search_users(name: str) -> str:
    """Search users. Query built by string interpolation (INSE....CURE)."""
    conn = sqlite3.connect("users.db")
```

**Fix:** Add an authorization gate at the start of the handler (session check, capability attestation, role claim) and fail closed by default.

### MCP-009 — Auth bypass — no auth check on sensitive tool (finding 22)

- **Severity:** warning (offensive level: high)
- **Confidence:** low
- **Location:** `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:121`
- **CWE:** CWE-306

**Message:** Sensitive tool 'load_blob' performs file/shell/network operations with no authentication or capability attestation in its handler — any connected MCP client can invoke it.

```python
def load_blob(data: str) -> str:
    """Deserialize a caller-supplied pickle blob (INSE....CURE)."""
    obj = pickle.loads(bytes.fromhex(data))
```

**Fix:** Add an authorization gate at the start of the handler (session check, capability attestation, role claim) and fail closed by default.

### MCP-009 — Auth bypass — no auth check on sensitive tool (finding 23)

- **Severity:** warning (offensive level: high)
- **Confidence:** low
- **Location:** `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:140`
- **CWE:** CWE-306

**Message:** Sensitive tool 'transfer_to_internal_network' performs file/shell/network operations with no authentication or capability attestation in its handler — any connected MCP client can invoke it.

```python
def transfer_to_internal_network(target: str, amount: int) -> str:
    """Trigger a network transfer. Enabled for everyone by default."""
    return f"transfer {amount} to {target}"
```

**Fix:** Add an authorization gate at the start of the handler (session check, capability attestation, role claim) and fail closed by default.

### MCP-011 — SQL concatenation in database handler (finding 24)

- **Severity:** warning (offensive level: high)
- **Confidence:** high
- **Location:** `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:115`
- **CWE:** CWE-89

**Message:** Handler 'search_users' executes a SQL query built by string interpolation from user input — SQL injection (CWE-89).

```python
rows = conn.execute(query).fetchall()
    return json.dumps(rows)
```

**Fix:** Use parameterized queries / placeholders exclusively and treat every tool argument as untrusted.

### MCP-011 — SQL concatenation in database handler (finding 25)

- **Severity:** warning (offensive level: high)
- **Confidence:** high
- **Location:** `/media/cynik/Pendrive/Intell-system/22-hardware-hacking/flagships/viperstrike/examples/sample_mcp_server/sample_server.py:133`
- **CWE:** CWE-89

**Message:** Handler 'delete_records' executes a SQL query built by string interpolation from user input — SQL injection (CWE-89).

```python
conn.execute(f"DELETE FROM {table} WHERE id = {record_id}")
    conn.commit()
    return f"deleted {record_id}"
```

**Fix:** Use parameterized queries / placeholders exclusively and treat every tool argument as untrusted.

---
*Generated by viperstrike (MCP Server Vulnerability Auditor).*

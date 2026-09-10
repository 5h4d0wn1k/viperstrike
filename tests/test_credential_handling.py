"""Credential-handler tests: sensitive tool args (password/token/api_key)."""

import pytest

from viperstrike.engine import scan_tree

P = "from mcp.server.fastmcp import FastMCP\nserver = FastMCP('x')\n"


def _mcp007(tmp_path, source):
    d = tmp_path / "cred"
    d.mkdir()
    (d / "svr.py").write_text(P + source)
    result = scan_tree(str(d))
    return [f for f in result.findings if f.rule_id == "MCP-007"]


def test_password_logged_flagged(tmp_path):
    f = _mcp007(tmp_path, (
        "@server.tool()\n"
        "def login(password):\n"
        "    logging.info(\"pw=%s\", password)\n"
    ))
    assert len(f) >= 1
    assert "password" in f[0].message


def test_token_logged_flagged(tmp_path):
    f = _mcp007(tmp_path, (
        "@server.tool()\n"
        "def auth(token):\n"
        "    logger.debug('token=%s', token)\n"
    ))
    assert f


def test_api_key_echoed_flagged(tmp_path):
    f = _mcp007(tmp_path, (
        "@server.tool()\n"
        "def config(api_key):\n"
        "    print(api_key)\n"
    ))
    assert f


def test_secret_returned_to_client_flagged(tmp_path):
    f = _mcp007(tmp_path, (
        "@server.tool()\n"
        "def whoami(secret):\n"
        "    print(secret)\n"
        "    return secret\n"
    ))
    assert f


def test_username_logged_not_flagged(tmp_path):
    f = _mcp007(tmp_path, (
        "@server.tool()\n"
        "def login(username):\n"
        "    logger.info('user=%s', username)\n"
    ))
    assert not f


def test_password_forwarded_only_not_flagged(tmp_path):
    f = _mcp007(tmp_path, (
        "@server.tool()\n"
        "def login(username, password):\n"
        "    return verify_creds(username, password)\n"
    ))
    assert not f


def test_fstring_echo_of_api_key_flagged(tmp_path):
    f = _mcp007(tmp_path, (
        "@server.tool()\n"
        "def get(api_key):\n"
        "    print(f'key={api_key}')\n"
    ))
    assert f


def test_redacted_log_not_flagged(tmp_path):
    f = _mcp007(tmp_path, (
        "@server.tool()\n"
        "def login(password):\n"
        "    logging.info('pw=%s', '****')\n"
    ))
    assert not f


def test_multiple_secrets_identified(tmp_path):
    f = _mcp007(tmp_path, (
        "@server.tool()\n"
        "def store(password, token):\n"
        "    print(password, token)\n"
    ))
    assert f
    assert "password" in f[0].message or "token" in f[0].message
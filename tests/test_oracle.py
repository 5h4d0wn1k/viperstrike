"""Oracle-mode tests: safety gates, loopback enforcement, offline demo."""

import json

import pytest

from viperstrike.oracle import (
    _parse_url,
    _ask_approval,
    _build_poc_prompt,
    _tcp_probe,
    LOOPBACK_HOSTS,
    run_oracle,
)


def test_parse_url_loopback_ipv4():
    assert _parse_url("http://127.0.0.1:8765") == "http://127.0.0.1:8765"


def test_parse_url_loopback_hostname():
    assert _parse_url("http://localhost:3000") == "http://localhost:3000"


def test_parse_url_ipv6():
    assert _parse_url("http://[::1]:9000") in ("http://[::1]:9000", "http://[::1]:9000")


def test_parse_url_rejects_remote_domain():
    with pytest.raises(ValueError):
        _parse_url("http://evil.example.com:80")


def test_parse_url_rejects_public_ip():
    with pytest.raises(ValueError):
        _parse_url("http://8.8.8.8:53")


def test_parse_url_rejects_private_lan():
    with pytest.raises(ValueError):
        _parse_url("http://192.168.1.1:8080")


def test_parse_url_rejects_no_scheme_remote():
    with pytest.raises(ValueError):
        _parse_url("10.0.0.5:22")


def test_parse_url_accepts_bare_loopback():
    assert isinstance(_parse_url("localhost:9000"), str)


def test_loopback_hosts_set_contains_expected():
    assert LOOPBACK_HOSTS == {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def test_ask_approval_yes_flag():
    assert _ask_approval("http://127.0.0.1:1", yes=True)


def test_ask_approval_refused_no_input(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *a: "n")
    assert not _ask_approval("http://127.0.0.1:1", yes=False)


def test_ask_approval_accepts_y(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *a: "y")
    assert _ask_approval("http://127.0.0.1:1", yes=False)


def test_ask_approval_accepts_yes(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *a: "yes")
    assert _ask_approval("http://127.0.0.1:1", yes=False)


def test_ask_approval_eof_safe(monkeypatch):
    def raiser(*a):
        raise EOFError()
    monkeypatch.setattr("builtins.input", raiser)
    assert not _ask_approval("http://127.0.0.1:1", yes=False)


def test_ask_approval_interrupt_safe(monkeypatch):
    def raiser(*a):
        raise KeyboardInterrupt()
    monkeypatch.setattr("builtins.input", raiser)
    assert not _ask_approval("http://127.0.0.1:1", yes=False)


def test_build_poc_prompt_is_string():
    assert isinstance(_build_poc_prompt(), str)
    assert len(_build_poc_prompt()) > 0


def test_tcp_probe_closed_port_false():
    assert _tcp_probe("127.0.0.1", 1) is False


def test_tcp_probe_localhost_name():
    assert _tcp_probe("localhost", 1) is False


def test_run_oracle_demo_exits_zero(tmp_path):
    rc = run_oracle("http://127.0.0.1:1", tmp_path, demo=True, yes=False,
                    verbose=False)
    assert rc == 0
    assert (tmp_path / "oracle_demo.json").exists()


def test_run_oracle_demo_writes_marked_demo(tmp_path):
    run_oracle("http://127.0.0.1:1", tmp_path, demo=True, yes=False, verbose=False)
    data = json.loads((tmp_path / "oracle_demo.json").read_text())
    assert data["oracle"]["mode"] == "demo"
    assert data["oracle"]["exits_zero"] is True


def test_run_oracle_demo_never_emits_network(tmp_path):
    # port 1 on loopback is never reachable; demo reports degrade cleanly
    run_oracle("http://127.0.0.1:1", tmp_path, demo=True, yes=False, verbose=False)
    data = json.loads((tmp_path / "oracle_demo.json").read_text())
    assert data["oracle"]["server_reachable"] is False


def test_run_oracle_rejects_external_host(tmp_path):
    rc = run_oracle("http://8.8.8.8:80", tmp_path, demo=True, yes=False,
                    verbose=False)
    assert rc == 2
    assert not (tmp_path / "oracle_demo.json").exists()


def test_run_oracle_refuses_without_approval(tmp_path, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *a: "n")
    rc = run_oracle("http://127.0.0.1:1", tmp_path, demo=False, yes=False,
                    verbose=False)
    assert rc == 2


def test_run_oracle_poc_prompt_recorded(tmp_path):
    rc = run_oracle("http://127.0.0.1:1", tmp_path, demo=True, yes=True,
                    verbose=False)
    assert rc == 0
    data = json.loads((tmp_path / "oracle_demo.json").read_text())
    assert data["oracle"]["poc_prompt"]


def test_run_oracle_report_has_safety_note(tmp_path):
    run_oracle("http://127.0.0.1:1", tmp_path, demo=True, yes=False, verbose=False)
    data = json.loads((tmp_path / "oracle_demo.json").read_text())
    assert "authorization" in data["note"].lower()


def test_run_oracle_creates_output_dir(tmp_path):
    out = tmp_path / "deep" / "nested"
    assert run_oracle("http://127.0.0.1:1", out, demo=True, yes=True,
                      verbose=False) == 0
    assert out.exists()
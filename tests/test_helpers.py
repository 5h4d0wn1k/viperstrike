"""Unit tests for shared AST helper utilities."""

import ast

from viperstrike.detectors.helpers import (
    get_source_range,
    find_calls,
    resolve_call_name,
    find_attribute_accesses,
    expr_uses_params,
    call_uses_params,
    interpolated_string,
    is_shell_true_call,
    contains_path_traversal,
    is_subprocess_shell_calls,
    param_names_of,
)


def _tree(src):
    return ast.parse(src)


def test_get_source_range_basic():
    lines = ["a", "b", "c", "d"]
    assert get_source_range(lines, 2, 3) == "b\nc"


def test_get_source_range_clamps():
    lines = ["a", "b"]
    assert get_source_range(lines, 1, 99) == "a\nb"


def test_get_source_range_empty_lines():
    assert get_source_range([], 1, 2) == ""


def test_find_calls_by_name():
    t = _tree("import os\nos.system('x')\nprint(os.name)\n")
    calls = find_calls(t, {"os.system"})
    assert len(calls) == 1


def test_find_calls_no_match():
    t = _tree("x = 1\n")
    assert find_calls(t, {"os.system"}) == []


def test_resolve_call_name_simple():
    t = _tree("eval('x')\n")
    call = find_calls(t, {"eval"})[0]
    assert resolve_call_name(call) == "eval"


def test_resolve_call_name_dotted():
    t = _tree("subprocess.run(['ls'])\n")
    call = find_calls(t, {"subprocess.run"})[0]
    assert resolve_call_name(call) == "subprocess.run"


def test_resolve_call_name_deep_dotted():
    t = _tree("os.path.join('a', 'b')\n")
    call = find_calls(t, {"os.path.join", "x"})[0]
    assert resolve_call_name(call) == "os.path.join"


def test_find_attribute_accesses():
    t = _tree("import os\nx = os.path\n")
    hits = find_attribute_accesses(t, {"path"})
    assert len(hits) == 1


def test_expr_uses_params_true():
    t = _tree("f'{name}!'")  # type: ignore
    joined = t.body[0].value
    assert expr_uses_params(joined, {"name"})


def test_expr_uses_params_false():
    t = _tree("f'{name}!'")  # type: ignore
    joined = t.body[0].value
    assert not expr_uses_params(joined, {"other"})


def test_call_uses_params_positional():
    t = _tree("os.system(cmd)\n")
    call = find_calls(t, {"os.system"})[0]
    assert call_uses_params(call, {"cmd"})


def test_call_uses_params_keyword():
    t = _tree("requests.get(url=target, timeout=5)\n")
    call = find_calls(t, {"requests.get"})[0]
    assert call_uses_params(call, {"target"})


def test_call_uses_params_false():
    t = _tree("os.system('/bin/date')\n")
    call = find_calls(t, {"os.system"})[0]
    assert not call_uses_params(call, {"cmd"})


def test_interpolated_string_constant():
    t = _tree("x = 'hello'\n")
    assert interpolated_string(t.body[0].value) == "hello"


def test_interpolated_string_none_for_name():
    t = _tree("x = var\n")
    assert interpolated_string(t.body[0].value) is None


def test_is_shell_true():
    t = _tree("subprocess.run(cmd, shell=True)\n")
    call = find_calls(t, {"subprocess.run"})[0]
    assert is_shell_true_call(call)


def test_is_shell_false():
    t = _tree("subprocess.run(cmd, shell=False)\n")
    call = find_calls(t, {"subprocess.run"})[0]
    assert not is_shell_true_call(call)


def test_is_subprocess_shell_calls_detects_popen():
    t = _tree("import subprocess\nsubprocess.Popen(cmd, shell=True)\n")
    hits = is_subprocess_shell_calls(t)
    assert len(hits) == 1
    assert hits[0][1] is True


def test_contains_path_traversal_dotdot():
    assert contains_path_traversal("../secret")


def test_contains_path_traversal_absolute():
    assert contains_path_traversal("/etc/passwd")


def test_contains_path_traversal_negative():
    assert not contains_path_traversal("notes.txt")


def test_param_names_of_func():
    t = _tree("def f(a, b):\n    pass\n")
    func = t.body[0]
    assert param_names_of(func) == ["a", "b"]


def test_param_names_of_skips_self():
    t = _tree("def f(self, a):\n    pass\n")
    func = t.body[0]
    assert param_names_of(func) == ["a"]
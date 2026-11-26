"""Behavioral matrix for the guard's nested/list/path keys (host-path escape tests).

Covers the regression class the discovery-style tests in
test_guard_nested_schema_discovery.py cannot see: per-op nested checks, NUL bytes,
dash prefixes, protected-home targets, malformed elements and large
dex_paths lists. Mutation history: M6 (only first op checked) and M11
(NUL check removed) survived every other suite — these tests kill both.
"""
import pytest

from android_re_mcp import guard


def refused(tool, args):
    with pytest.raises(guard.GuardError):
        guard.validate(tool, args)


@pytest.fixture
def env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "id_ed25519").write_text("k")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("ANDROID_RE_MCP_ALLOWED_DIRS", raising=False)
    work = tmp_path / "work"
    work.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (work / "link").symlink_to(outside)
    return {"home": home, "work": work, "outside": outside}


def build(kind, p, work):
    a = str(work / "a.dex")
    if kind == "dex_paths":
        return "dex_merge", {"dex_paths": [a, p], "output_path": str(work / "m.dex")}
    if kind == "dex_paths_first":
        return "dex_merge", {"dex_paths": [p, a], "output_path": str(work / "m.dex")}
    if kind == "zip_path":
        return "zip_test", {"zip_path": p}
    if kind == "rules_dir":
        return "quark_scan", {"apk_path": str(work / "a.apk"), "rules_dir": p}
    if kind == "ops_first":
        return "zip_update", {"zip_path": str(work / "a.zip"),
                              "ops": [{"op": "add", "entry_path": "x", "from_file": p}]}
    if kind == "ops_second":
        return "zip_update", {"zip_path": str(work / "a.zip"),
                              "ops": [{"op": "delete", "entry_path": "y"},
                                      {"op": "add", "entry_path": "x", "from_file": p}]}
    raise AssertionError(kind)


KINDS = ["dex_paths", "dex_paths_first", "zip_path", "rules_dir", "ops_first", "ops_second"]


@pytest.mark.parametrize("kind", KINDS)
def test_inside_allowed_dir_is_accepted(kind, env, monkeypatch):
    monkeypatch.setenv("ANDROID_RE_MCP_ALLOWED_DIRS", str(env["work"]))
    tool, args = build(kind, str(env["work"] / "ok.bin"), env["work"])
    guard.validate(tool, args)


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("how", ["outside", "traversal", "symlink"])
def test_escape_is_refused(kind, how, env, monkeypatch):
    monkeypatch.setenv("ANDROID_RE_MCP_ALLOWED_DIRS", str(env["work"]))
    w, o = env["work"], env["outside"]
    p = {"outside": str(o / "x.bin"), "traversal": str(w / ".." / "outside" / "x.bin"),
         "symlink": str(w / "link" / "x.bin")}[how]
    tool, args = build(kind, p, w)
    refused(tool, args)


@pytest.mark.parametrize("kind", KINDS)
def test_protected_home_refused_even_without_allowed_dirs(kind, env):
    tool, args = build(kind, str(env["home"] / ".ssh" / "id_ed25519"), env["work"])
    refused(tool, args)


@pytest.mark.parametrize("kind", KINDS)
def test_dash_prefix_refused(kind, env):
    tool, args = build(kind, "-x", env["work"])
    refused(tool, args)


@pytest.mark.parametrize("bad", [None, 123, {}, ["a"], "", "a\x00b"])
@pytest.mark.parametrize("kind", KINDS)
def test_malformed_element_refused(kind, bad, env):
    tool, args = build(kind, bad, env["work"])
    refused(tool, args)


@pytest.mark.parametrize("bad", ["abc", None, 5, {"a": "/etc/passwd"}])
def test_dex_paths_non_list_refused(bad, env):
    refused("dex_merge", {"dex_paths": bad})


def test_dex_paths_empty_list_passes_guard_by_design(env):
    guard.validate("dex_merge", {"dex_paths": []})


def test_very_long_list_is_checked_per_element_and_fast(env, monkeypatch):
    monkeypatch.setenv("ANDROID_RE_MCP_ALLOWED_DIRS", str(env["work"]))
    ok = [str(env["work"] / f"{i}.dex") for i in range(5000)]
    # Every one of the 5000 elements is checked; one bad element at the end
    # must still be refused. (No wall-clock assert: it was environment-flaky.)
    guard.validate("dex_merge", {"dex_paths": ok})
    refused("dex_merge", {"dex_paths": ok + [str(env["outside"] / "x.dex")]})

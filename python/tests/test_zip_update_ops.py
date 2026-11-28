"""Zip_update op-sequence tests (R6-2/T19): streaming paths for rename,
delete and replace.

The expected values below are NOT hand-written from reading the code:
they were generated once by running each sequence on v1.9.0
(git worktree /tmp/v190, PYTHONPATH=/tmp/v190/python/src, generator
recorded in reports/evidence-r6.tar.gz as differential_zip_update.py)
and the same run on the round-5 HEAD produced identical output on all
ten sequences (entry order, per-entry compress_type/CRC/size, result
list, error list). The literals pin the v1.9.0 behavior; the streaming
rewrite must keep it.

Notable pinned facts: a renamed untouched entry is written STORED under
its NEW name; a renamed STORED resources.arsc stays STORED; a replaced
entry is re-stamped (fresh ZipInfo, the archive's default compression =
STORED); a replace with byte-identical content keeps the original
ZipInfo and reports changed=false; a delete-then-add appends at the end
of the entry order.
"""

import zipfile
from pathlib import Path

import pytest

from android_re_mcp.handlers.apkops import ApkOpsHandler

_DATE = (2026, 1, 1, 0, 0, 0)


def _fixture(p: Path) -> Path:
    if p.exists():
        p.unlink()
    with zipfile.ZipFile(p, "w") as z:
        zi = zipfile.ZipInfo("classes.dex", date_time=_DATE); zi.compress_type = zipfile.ZIP_STORED
        z.writestr(zi, b"dex\n035\0" + b"\x01" * 100)
        zi = zipfile.ZipInfo("assets/a.txt", date_time=_DATE); zi.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(zi, b"aaaa" * 50)
        zi = zipfile.ZipInfo("resources.arsc", date_time=_DATE); zi.compress_type = zipfile.ZIP_STORED
        z.writestr(zi, b"arsc" * 20)
        zi = zipfile.ZipInfo("assets/keep.bin", date_time=_DATE); zi.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(zi, bytes(range(256)) * 4)
    return p


CASES = [
    (
        "rename_untouched",
        [{'from': 'assets/a.txt', 'op': 'rename', 'to': 'assets/renamed.txt'}],
        ['classes.dex', 'assets/renamed.txt', 'resources.arsc', 'assets/keep.bin'],
        {'assets/keep.bin': [8, 3070970918, 1024],
 'assets/renamed.txt': [0, 1503326296, 200],
 'classes.dex': [0, 3699026126, 108],
 'resources.arsc': [0, 2868807010, 80]},
        [{'from': 'assets/a.txt', 'ok': True, 'op': 'rename', 'to': 'assets/renamed.txt'}],
        [],
    ),
    (
        "replace_then_rename",
        [{'content': 'NEW CONTENT', 'entry_path': 'assets/a.txt', 'op': 'replace'},
 {'from': 'assets/a.txt', 'op': 'rename', 'to': 'assets/renamed.txt'}],
        ['classes.dex', 'assets/renamed.txt', 'resources.arsc', 'assets/keep.bin'],
        {'assets/keep.bin': [8, 3070970918, 1024],
 'assets/renamed.txt': [0, 612569285, 11],
 'classes.dex': [0, 3699026126, 108],
 'resources.arsc': [0, 2868807010, 80]},
        [{'after_size': 11,
  'before_size': 200,
  'changed': True,
  'entry': 'assets/a.txt',
  'ok': True,
  'op': 'replace'},
 {'from': 'assets/a.txt', 'ok': True, 'op': 'rename', 'to': 'assets/renamed.txt'}],
        [],
    ),
    (
        "rename_then_patch",
        [{'from': 'classes.dex', 'op': 'rename', 'to': 'classes2.dex'},
 {'byte_offset': 8,
  'entry_path': 'classes2.dex',
  'expected_hex': '01',
  'op': 'patch',
  'replacement_hex': 'ff'}],
        ['classes2.dex', 'assets/a.txt', 'resources.arsc', 'assets/keep.bin'],
        {'assets/a.txt': [8, 1503326296, 200],
 'assets/keep.bin': [8, 3070970918, 1024],
 'classes2.dex': [0, 3595359078, 108],
 'resources.arsc': [0, 2868807010, 80]},
        [{'from': 'classes.dex', 'ok': True, 'op': 'rename', 'to': 'classes2.dex'},
 {'after_size': 108,
  'before_size': 108,
  'byte_offset': 8,
  'entry': 'classes2.dex',
  'ok': True,
  'op': 'patch'}],
        [],
    ),
    (
        "delete_then_re_add",
        [{'entry_path': 'assets/a.txt', 'op': 'delete'},
 {'content': 're-added', 'entry_path': 'assets/a.txt', 'op': 'add'}],
        ['classes.dex', 'resources.arsc', 'assets/keep.bin', 'assets/a.txt'],
        {'assets/a.txt': [0, 3832962008, 8],
 'assets/keep.bin': [8, 3070970918, 1024],
 'classes.dex': [0, 3699026126, 108],
 'resources.arsc': [0, 2868807010, 80]},
        [{'entry': 'assets/a.txt', 'ok': True, 'op': 'delete'},
 {'after_size': 8, 'entry': 'assets/a.txt', 'ok': True, 'op': 'add'}],
        [],
    ),
    (
        "rename_then_delete",
        [{'from': 'assets/a.txt', 'op': 'rename', 'to': 'assets/r.txt'},
 {'entry_path': 'assets/r.txt', 'op': 'delete'}],
        ['classes.dex', 'resources.arsc', 'assets/keep.bin'],
        {'assets/keep.bin': [8, 3070970918, 1024],
 'classes.dex': [0, 3699026126, 108],
 'resources.arsc': [0, 2868807010, 80]},
        [{'from': 'assets/a.txt', 'ok': True, 'op': 'rename', 'to': 'assets/r.txt'},
 {'entry': 'assets/r.txt', 'ok': True, 'op': 'delete'}],
        [],
    ),
    (
        "rename_classes_dex",
        [{'from': 'classes.dex', 'op': 'rename', 'to': 'classes2.dex'}],
        ['classes2.dex', 'assets/a.txt', 'resources.arsc', 'assets/keep.bin'],
        {'assets/a.txt': [8, 1503326296, 200],
 'assets/keep.bin': [8, 3070970918, 1024],
 'classes2.dex': [0, 3699026126, 108],
 'resources.arsc': [0, 2868807010, 80]},
        [{'from': 'classes.dex', 'ok': True, 'op': 'rename', 'to': 'classes2.dex'}],
        [],
    ),
    (
        "rename_stored_arsc",
        [{'from': 'resources.arsc', 'op': 'rename', 'to': 'resources2.arsc'}],
        ['classes.dex', 'assets/a.txt', 'resources2.arsc', 'assets/keep.bin'],
        {'assets/a.txt': [8, 1503326296, 200],
 'assets/keep.bin': [8, 3070970918, 1024],
 'classes.dex': [0, 3699026126, 108],
 'resources2.arsc': [0, 2868807010, 80]},
        [{'from': 'resources.arsc', 'ok': True, 'op': 'rename', 'to': 'resources2.arsc'}],
        [],
    ),
    (
        "replace_twice_then_add",
        [{'content': 'one', 'entry_path': 'assets/a.txt', 'op': 'replace'},
 {'content': 'two', 'entry_path': 'assets/a.txt', 'op': 'replace'},
 {'content': 'added', 'entry_path': 'assets/added.txt', 'op': 'add'}],
        ['classes.dex', 'assets/a.txt', 'resources.arsc', 'assets/keep.bin', 'assets/added.txt'],
        {'assets/a.txt': [0, 298486374, 3],
 'assets/added.txt': [0, 3418329323, 5],
 'assets/keep.bin': [8, 3070970918, 1024],
 'classes.dex': [0, 3699026126, 108],
 'resources.arsc': [0, 2868807010, 80]},
        [{'after_size': 3,
  'before_size': 200,
  'changed': True,
  'entry': 'assets/a.txt',
  'ok': True,
  'op': 'replace'},
 {'after_size': 3,
  'before_size': 3,
  'changed': True,
  'entry': 'assets/a.txt',
  'ok': True,
  'op': 'replace'},
 {'after_size': 5, 'entry': 'assets/added.txt', 'ok': True, 'op': 'add'}],
        [],
    ),
    (
        "replace_identical",
        [{'content': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  'entry_path': 'assets/a.txt',
  'op': 'replace'}],
        ['classes.dex', 'assets/a.txt', 'resources.arsc', 'assets/keep.bin'],
        {'assets/a.txt': [8, 1503326296, 200],
 'assets/keep.bin': [8, 3070970918, 1024],
 'classes.dex': [0, 3699026126, 108],
 'resources.arsc': [0, 2868807010, 80]},
        [{'after_size': 200,
  'before_size': 200,
  'changed': False,
  'entry': 'assets/a.txt',
  'ok': True,
  'op': 'replace'}],
        [],
    ),
    (
        "rename_onto_existing",
        [{'from': 'assets/a.txt', 'op': 'rename', 'to': 'assets/keep.bin'}],
        ['classes.dex', 'assets/a.txt', 'resources.arsc', 'assets/keep.bin'],
        {'assets/a.txt': [8, 1503326296, 200],
 'assets/keep.bin': [8, 3070970918, 1024],
 'classes.dex': [0, 3699026126, 108],
 'resources.arsc': [0, 2868807010, 80]},
        [],
        [{'entry': 'assets/a.txt', 'error': 'target entry exists', 'op': 'rename'}],
    ),]



@pytest.mark.parametrize("name,ops,exp_order,exp_listing,exp_results,exp_errors", CASES)
def test_zip_update_op_sequence(name, ops, exp_order, exp_listing, exp_results, exp_errors, tmp_path):
    apk = _fixture(tmp_path / "a.apk")
    out_apk = tmp_path / "out.apk"
    r = ApkOpsHandler().zip_update({"zip_path": str(apk), "ops": ops, "output_apk": str(out_apk)})
    with zipfile.ZipFile(out_apk) as z:
        order = [i.filename for i in z.infolist()]
        listing = {i.filename: [i.compress_type, i.CRC, i.file_size] for i in z.infolist()}
    assert order == exp_order, name
    assert listing == exp_listing, name
    assert r["output"]["results"] == exp_results, name
    assert r["output"].get("errors", []) == exp_errors, name

"""
handlers/dex.py — DEX surgery via the pinned dexfile-cli jar (E-PY-17).

dexfile-cli (https://github.com/FlyPhantomFly/dexfile-cli, MIT) wraps
com.v7878.dex (DexFile v1.7.0) — read, convert, patch, assemble and split
dex files, including dex 041 containers, odex variants, hidden-API flags
and (read-side) cdex inside packer-shuffled blobs. The jar is a pinned
SHA-256 ``--setup`` download into ~/tools, invoked exactly like apktool.

Every call is one subprocess; one JSON object comes back on stdout, with
exit codes 0 ok / 2 usage / 3 not-a-dex / 4 invalid-dex mapped to honest
statuses. List outputs ride the E-PY-15 caps. The dex-patch fast loop is:
dex_extract → dex_patch → zipfile swap → apk_sign (no apktool resource
rebuild); the smali_patch → apk_rebuild_sign loop stays the general path.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path

from android_re_mcp.handlers.caps import cap_items
from android_re_mcp.paths import data_dir, tools_dir

_JAR_NAME = "dexfile-cli.jar"
_TIMEOUT = 600  # dex surgery on huge packs; the CLI itself caps at 1800s reads

_VALID_OPS = ("replace-const-string", "rename", "retarget-invoke", "flip-flags", "replace-method-body")
_VALID_FLAGS = {"PUBLIC", "PRIVATE", "PROTECTED", "STATIC", "FINAL", "SYNCHRONIZED",
                "VOLATILE", "BRIDGE", "TRANSIENT", "VARARGS", "NATIVE", "INTERFACE",
                "ABSTRACT", "STRICT", "SYNTHETIC", "ANNOTATION", "ENUM", "CONSTRUCTOR",
                "DECLARED_SYNCHRONIZED"}
_VALID_VERSIONS = ("035", "036", "037", "038", "039", "040", "041")

_OP_REQUIREMENTS = {
    "replace-const-string": ("old", "new"),
    "rename": ("target", "new_name"),
    "retarget-invoke": ("class", "name", "to_class"),
    "flip-flags": ("class",),
    "replace-method-body": ("class", "method", "smali"),
}


class DexHandler:
    """Stateless dex surgery over the dexfile-cli jar (asyncio.to_thread pool)."""

    # ── plumbing ──────────────────────────────────────────────────────────

    def _require(self, tool: str) -> dict | tuple[str, str]:
        jar = tools_dir() / _JAR_NAME
        java = shutil.which("java")
        if not jar.is_file():
            return {
                "status": "missing_tool",
                "tool": tool,
                "error": "dexfile-cli.jar not found in the tools dir.",
                "hint": "Run android-re-mcp --setup, or install_tool dexfile-cli "
                        "(https://github.com/FlyPhantomFly/dexfile-cli/releases).",
            }
        if java is None:
            return {
                "status": "missing_tool",
                "tool": tool,
                "error": "java not found on PATH (java 17+ required).",
                "hint": "Install a JDK/JRE 17+ (e.g. sudo apt install default-jre).",
            }
        return str(jar), java

    def _run(self, tool: str, cli_args: list[str]) -> dict:
        required = self._require(tool)
        if isinstance(required, dict):
            return required
        jar, java = required
        try:
            proc = subprocess.run(
                [java, "-jar", jar, *cli_args],
                capture_output=True, text=True, timeout=_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            return {"status": "error", "tool": tool,
                    "error": f"dexfile-cli timed out after {_TIMEOUT}s"}
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": tool, "error": str(exc)}

        stdout = proc.stdout.strip()
        try:
            parsed = json.loads(stdout) if stdout else {}
        except json.JSONDecodeError:
            parsed = {"error": (stdout or proc.stderr).strip()[:800]}
        if proc.returncode == 0:
            return {"status": "ok", "tool": tool, "result": parsed}
        kind = parsed.get("kind", "unexpected")
        message = str(parsed.get("error") or (proc.stderr or "jvm error").strip())[:800]
        return {"status": "error", "tool": tool, "error": message, "kind": kind}

    def _default_dir(self, input_path: str, suffix: str) -> str:
        stem = Path(input_path).stem or "dex"
        return str(data_dir() / "dex" / f"{stem}{suffix}")

    # ── dex_info ──────────────────────────────────────────────────────────

    def dex_info(self, args: dict) -> dict:
        """[TOOL] Read-only dex metadata: version, target API, counts."""
        dex_path = args.get("dex_path", "")
        cli_args = ["info", dex_path]
        if args.get("classes"):
            limit = max(1, int(args.get("limit", 200) or 200))
            cli_args += ["--classes", "--limit", str(limit)]
        result = self._run("dex_info", cli_args)
        if result.get("status") != "ok":
            return result
        out = result["result"]
        if isinstance(out.get("classes_list"), list):
            shown, info = cap_items(out["classes_list"], "raise the limit or narrow with dex_extract")
            out["classes_list"] = shown
            out["total"] = out.get("classes_list_total", info["total"])
            if info["truncated"]:
                out["truncated"] = True
                out["hint"] = info["hint"]
        return result

    # ── dex_extract ───────────────────────────────────────────────────────

    def dex_extract(self, args: dict) -> dict:
        """[TOOL] Pull every classes*.dex out of an APK (041 containers split)."""
        input_path = args.get("apk_path") or args.get("dex_path") or ""
        out_dir = args.get("output_dir") or self._default_dir(input_path, "_extract")
        return self._run("dex_extract", ["extract", input_path, "--out", out_dir])

    # ── dex_convert ───────────────────────────────────────────────────────

    def dex_convert(self, args: dict) -> dict:
        """[TOOL] Convert between dex versions (old-ART vdex/cdex → 035 for jadx)."""
        in_path = args.get("in_path") or args.get("dex_path") or ""
        version = args.get("target_version", "035")
        cli_args = ["convert", in_path, "--to", version]
        if args.get("output_path"):
            cli_args += ["--out", args["output_path"]]
        result = self._run("dex_convert", cli_args)
        if result.get("status") == "ok":
            result.setdefault("note", "round-trips re-serialize: semantic content survives, layout does not")
        return result

    # ── dex_patch ─────────────────────────────────────────────────────────

    def dex_patch(self, args: dict) -> dict:
        """[TOOL] Targeted dex-model edits (const-string, rename, flags, method bodies)."""
        dex_path = args.get("dex_path", "")
        ops = args.get("ops")
        error = self._validate_ops(ops)
        if error:
            return {"status": "error", "tool": "dex_patch", "error": error}

        out_path = args.get("output_path")
        # smali_patch discipline: back up the input before an in-place modify
        if out_path is None:
            bak = Path(dex_path + ".bak")
            if not bak.exists() and Path(dex_path).is_file():
                shutil.copy2(dex_path, bak)

        ops_file = None
        try:
            fd, ops_name = tempfile.mkstemp(prefix="dex-ops-", suffix=".json", dir=data_dir())
            ops_file = Path(ops_name)
            with os.fdopen(fd, "w") as fh:
                json.dump(ops, fh)
            cli_args = ["patch", dex_path, "--ops", str(ops_file)]
            if out_path:
                cli_args += ["--out", out_path]
            result = self._run("dex_patch", cli_args)
        finally:
            if ops_file is not None:
                ops_file.unlink(missing_ok=True)
        if result.get("status") == "ok":
            result["result"] = {**result.get("result", {}),
                                "next_step": "zip the patched dex back into an APK copy, then apk_sign"}
        return result

    @staticmethod
    def _validate_ops(ops) -> str | None:
        if not isinstance(ops, list) or not ops:
            return ("ops must be a non-empty JSON array of operations (supported: "
                    + ", ".join(_VALID_OPS) + ")")
        for op in ops:
            if not isinstance(op, dict):
                return "each operation must be a JSON object"
            op_type = op.get("op")
            if op_type not in _VALID_OPS:
                return (f"unknown op '{op_type}' — supported: " + ", ".join(_VALID_OPS))
            for key in _OP_REQUIREMENTS[op_type]:
                if key not in op or op[key] in ("", None):
                    return f"op '{op_type}' is missing required field '{key}'"
            if op_type == "rename" and op.get("target") not in ("class", "method", "field"):
                return "rename op needs target: class|method|field"
            if op_type == "flip-flags":
                for direction in ("set", "clear"):
                    flags = op.get(direction, [])
                    if not isinstance(flags, list):
                        return f"flip-flags '{direction}' must be a list"
                    for flag in flags:
                        name = str(flag).upper()
                        if not (name in _VALID_FLAGS
                                or (name.startswith("0X") and len(name) <= 10
                                    and all(c in "0123456789ABCDEF" for c in name[2:]))):
                            return (f"unknown access flag '{flag}' — use standard dex flag "
                                    f"names or 0x… hex (supported: {', '.join(sorted(_VALID_FLAGS))})")
            if op_type == "replace-method-body" and not str(op.get("smali", "")).strip():
                return "replace-method-body needs non-empty smali text (it must carry .locals and the method body)"
        return None

    # ── dex_assemble ──────────────────────────────────────────────────────

    def dex_assemble(self, args: dict) -> dict:
        """[TOOL] One smali class → dex (SmaliIO)."""
        smali_text = args.get("smali_text", "")
        smali_path = args.get("path", "")
        if not smali_text and not smali_path:
            return {"status": "error", "tool": "dex_assemble",
                    "error": "provide smali_text or path (a .smali file)"}
        out_path = args.get("output_path") or str(
            data_dir() / "dex" / f"assemble-{int(time.time())}.dex")

        cli_args = ["assemble"]
        if smali_path:
            cli_args.append(smali_path)
        else:
            scratch = Path(data_dir())
            fd, tmp_name = tempfile.mkstemp(prefix="dex-assemble-", suffix=".smali", dir=scratch)
            Path(tmp_name).write_text(smali_text, encoding="utf-8")
            cli_args.append(tmp_name)

        try:
            result = self._run("dex_assemble", [*cli_args, "--out", out_path])
        finally:
            if not smali_path:
                Path(cli_args[-1]).unlink(missing_ok=True)
        if result.get("status") == "ok" and isinstance(result.get("result"), dict):
            result["result"]["note"] = ("smali text must carry .locals/.registers and "
                                        ".end method — the Smali grammar requires them")
        return result

    # ── dex_split ─────────────────────────────────────────────────────────

    def dex_split(self, args: dict) -> dict:
        """[TOOL] Shard a class list across dex files under the 64K-reference limit."""
        dex_path = args.get("dex_path", "")
        out_dir = args.get("output_dir") or self._default_dir(dex_path, "_split")
        return self._run("dex_split", ["split", dex_path, "--out", out_dir])

    # ── dex_swap (pure Python — the fast loop's zip step) ─────────────────

    def dex_swap(self, args: dict) -> dict:
        """[TOOL] Swap a patched dex back into an APK copy, other entries intact.

        Pure-Python zipfile rewrite (stdlib only — no jar needed). Sign the
        result afterwards with apk_sign (zipaligns + signs). The first
        in-place swap writes an .apk.bak next to the input, mirroring
        dex_patch's discipline.
        """
        import zipfile

        apk_path = args.get("apk_path", "")
        dex_path = args.get("dex_path", "")
        if not apk_path or not Path(apk_path).is_file():
            return {"status": "error", "tool": "dex_swap", "error": f"apk_path '{apk_path}' not found"}
        if not dex_path or not Path(dex_path).is_file():
            return {"status": "error", "tool": "dex_swap", "error": f"dex_path '{dex_path}' not found"}

        entry = args.get("entry_name") or self._find_dex_entry(apk_path, dex_path)
        if not entry:
            return {"status": "error", "tool": "dex_swap",
                    "error": "could not match the dex to an entry — pass entry_name explicitly "
                             "(e.g. 'classes.dex')"}

        out_path = args.get("output_apk")
        bak_note = None
        if out_path is None:
            out_path = apk_path
            bak = Path(apk_path + ".bak")
            if not bak.exists():
                shutil.copy2(apk_path, bak)
                bak_note = str(bak)

        dex_bytes = Path(dex_path).read_bytes()
        tmp = Path(str(out_path) + ".tmp")
        replaced = False
        try:
            with zipfile.ZipFile(apk_path) as src, \
                    zipfile.ZipFile(tmp, "w") as dst:
                for info in src.infolist():
                    data = src.read(info.filename)
                    if info.filename == entry:
                        data = dex_bytes
                        replaced = True
                    # preserve each entry's original compression — resources.arsc
                    # must stay STORED (uncompressed) or modern Android refuses it
                    dst.writestr(info, data)
            if not replaced:
                with zipfile.ZipFile(tmp, "a") as dst:
                    dst.writestr(entry, dex_bytes)
            tmp.replace(out_path)
        except zipfile.BadZipFile as exc:
            tmp.unlink(missing_ok=True)
            return {"status": "error", "tool": "dex_swap", "error": f"bad zip: {exc}"}
        except Exception as exc:  # noqa: BLE001
            tmp.unlink(missing_ok=True)
            return {"status": "error", "tool": "dex_swap", "error": str(exc)}

        out: dict = {"status": "ok", "tool": "dex_swap", "output": {
            "apk": str(out_path), "entry": entry, "dex_bytes": len(dex_bytes),
            "next_step": "apk_sign (zipaligns + signs), then adb_install",
        }}
        if bak_note:
            out["output"]["backup"] = bak_note
        return out

    @staticmethod
    def _find_dex_entry(apk_path: str, dex_path: str) -> str:
        """Match by identical bytes first (classes*.dex only), then by size."""
        import hashlib

        dex_sha = hashlib.sha256(Path(dex_path).read_bytes()).hexdigest()
        dex_size = Path(dex_path).stat().st_size
        with zipfile.ZipFile(apk_path) as z:
            # only the dex entries are candidates — hashing every entry of a
            # 100 MB APK would be pure waste
            dexes = sorted(n for n in z.namelist()
                           if n.startswith("classes") and n.endswith(".dex"))
            for name in dexes:
                if hashlib.sha256(z.read(name)).hexdigest() == dex_sha:
                    return name
            for name in dexes:
                if len(z.read(name)) == dex_size:
                    return name
            return dexes[0] if dexes else ""


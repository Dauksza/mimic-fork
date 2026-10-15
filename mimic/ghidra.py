"""Invoke an installed Ghidra headless analyzer for a selected Windows executable."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from .windows_capture import WindowsCaptureError, _now


class GhidraError(RuntimeError):
    pass


def find_ghidra_home(configured=None):
    candidates = []
    for value in (configured, os.environ.get("GHIDRA_HOME"), os.environ.get("GHIDRA_INSTALL_DIR")):
        if value:
            candidates.append(Path(value).expanduser())
    for value in (Path.home(), Path("C:/"), Path("C:/Program Files"), Path("C:/Tools")):
        try:
            candidates.extend(value.glob("ghidra*"))
        except OSError:
            pass
    path_exe = shutil.which("analyzeHeadless.bat") or shutil.which("analyzeHeadless")
    if path_exe:
        candidates.append(Path(path_exe).resolve().parent.parent)
    for candidate in candidates:
        try:
            home = candidate.resolve()
            headless = home / "support" / "analyzeHeadless.bat"
            if headless.is_file():
                return home
        except OSError:
            continue
    return None


def process_executable_path(pid):
    """Query the selected process image path through the Windows process API."""
    if os.name != "nt":
        raise GhidraError("Automatic executable discovery is supported on Windows only.")
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not handle:
        raise GhidraError("Windows denied access to inspect the selected process executable.")
    try:
        buffer = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buffer))
        if not kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            raise GhidraError("Could not resolve the selected process executable path.")
        path = Path(buffer.value)
        if not path.is_file():
            raise GhidraError("The selected process executable is not available on disk: " + str(path))
        return str(path.resolve())
    finally:
        kernel32.CloseHandle(handle)


def _safe_project_name(path):
    stem = re.sub(r"[^A-Za-z0-9_-]+", "_", Path(path).stem).strip("_")
    return (stem or "MimicBinary")[:50] + "_Mimic"


def analyze_binary(binary_path, out_dir, ghidra_home=None, timeout=1800, on_status=None):
    """Run real Ghidra analysis on an executable and its adjacent DLL dependencies."""
    status = on_status or (lambda message: None)
    binary = Path(binary_path).expanduser().resolve()
    if not binary.is_file():
        raise GhidraError("The target executable does not exist: " + str(binary))
    if binary.suffix.casefold() not in {".exe", ".dll", ".ocx", ".sys"}:
        raise GhidraError("Ghidra target must be a PE executable or library (.exe, .dll, .ocx, .sys).")
    home = find_ghidra_home(ghidra_home)
    if not home:
        raise GhidraError(
            "Ghidra was not found. Install Ghidra, then set GHIDRA_HOME to its extracted folder "
            "or select that folder in Mimic. Mimic uses Ghidra's support/analyzeHeadless.bat."
        )
    analyzer = home / "support" / "analyzeHeadless.bat"
    out = Path(out_dir).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    scripts_dir = Path(__file__).resolve().parent / "ghidra_scripts"
    script = scripts_dir / "MimicExport.java"
    if not script.is_file():
        raise GhidraError("Mimic's Ghidra export script is missing: " + str(script))
    report_path = out / "ghidra-analysis.json"
    project_dir = out / "ghidra-project"
    project_dir.mkdir(parents=True, exist_ok=True)
    project_name = _safe_project_name(binary)
    command = [
        str(analyzer), str(project_dir), project_name,
        "-scriptPath", str(scripts_dir),
        "-import", str(binary),
        "-postScript", "MimicExport.java", str(report_path),
        "-analysisTimeoutPerFile", "900",
        "-max-cpu", str(max(1, min(4, os.cpu_count() or 2))),
    ]
    status("Ghidra: analyzing " + binary.name + " with headless static analysis…")
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout,
            cwd=str(home), check=False,
            creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0),
        )
    except subprocess.TimeoutExpired as exc:
        raise GhidraError(f"Ghidra analysis exceeded {timeout} seconds. Check its log in {out}.") from exc
    (out / "ghidra-stdout.log").write_text(completed.stdout[-100000:], encoding="utf-8", errors="replace")
    (out / "ghidra-stderr.log").write_text(completed.stderr[-100000:], encoding="utf-8", errors="replace")
    if completed.returncode != 0:
        raise GhidraError(
            "Ghidra exited with code " + str(completed.returncode) +
            ". Review ghidra-stdout.log and ghidra-stderr.log in " + str(out)
        )
    if not report_path.is_file():
        raise GhidraError(
            "Ghidra ran but did not create its analysis report. Review the Ghidra logs in " + str(out)
        )
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GhidraError("Ghidra's export report was not valid JSON.") from exc
    report["analysis_completed_at"] = _now()
    report["ghidra_home"] = str(home)
    report["analyzed_binary"] = str(binary)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    status(
        f"Ghidra finished: {report.get('function_count', 0)} functions, "
        f"{len(report.get('strings', []))} strings extracted."
    )
    return report

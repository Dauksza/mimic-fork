"""Invoke an installed Ghidra headless analyzer for a selected Windows executable."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
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


def analyze_binary(binary_path, out_dir, ghidra_home=None, timeout=7200, max_decompile=1000, per_function_timeout=8, on_status=None):
    """Run Ghidra headless analysis on a PE, ELF, Mach-O, or raw native binary."""
    status = on_status or (lambda message: None)
    binary = Path(binary_path).expanduser().resolve()
    if not binary.is_file():
        raise GhidraError("The target executable does not exist: " + str(binary))
    if binary.suffix.casefold() not in {
        ".exe", ".dll", ".ocx", ".sys", ".so", ".dylib", ".elf", ".o", ".a", ".bin", ".mach-o"
    } and binary.suffix:
        raise GhidraError(
            "Ghidra target must be a supported native executable/library (PE, ELF, Mach-O, or raw binary)."
        )
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
    # Preserve any existing Ghidra project so analysts do not lose labels/bookmarks on a rerun.
    if project_dir.exists() and any(project_dir.iterdir()):
        project_dir = out / ("ghidra-project-" + time.strftime("%Y%m%d_%H%M%S"))
        suffix = 1
        while project_dir.exists():
            project_dir = out / ("ghidra-project-" + time.strftime("%Y%m%d_%H%M%S") + "-" + str(suffix))
            suffix += 1
    project_dir.mkdir(parents=True, exist_ok=True)
    project_name = _safe_project_name(binary)
    command = [
        str(analyzer), str(project_dir), project_name,
        "-scriptPath", str(scripts_dir),
        "-import", str(binary),
        "-postScript", "MimicExport.java", str(report_path), str(max_decompile), str(per_function_timeout),
        "-analysisTimeoutPerFile", "3600",
        "-max-cpu", str(max(1, min(4, os.cpu_count() or 2))),
    ]
    status("Ghidra: analyzing " + binary.name + " with headless static analysis…")
    try:
        if os.name == "nt":
            # analyzeHeadless.bat must be invoked via cmd.exe on Windows.
            command_line = subprocess.list2cmdline(command)
            completed = subprocess.run(
                ["cmd.exe", "/d", "/s", "/c", command_line], capture_output=True, text=True,
                timeout=timeout, cwd=str(home), check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        else:
            raise GhidraError("The desktop Ghidra stage currently targets the Windows analyzeHeadless.bat distribution.")
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



def _pe_metadata(binary_path):
    """Return PE header/import/export metadata used to locate app-local dependencies."""
    binary = Path(binary_path).resolve()
    metadata = {
        "path": str(binary),
        "sha256": None,
        "managed_dotnet": False,
        "imports": [],
        "exports": [],
        "sections": [],
        "parse_warning": None,
    }
    try:
        import hashlib
        digest = hashlib.sha256()
        with binary.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        metadata["sha256"] = digest.hexdigest()
    except OSError:
        pass
    try:
        import pefile
    except ImportError:
        metadata["parse_warning"] = "pefile is not installed. Reinstall Windows dependencies to enable dependency enumeration."
        return metadata

    try:
        pe = pefile.PE(str(binary), fast_load=True)
        wanted = [
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
        ]
        pe.parse_data_directories(directories=wanted)
        metadata.update({
            "machine": hex(pe.FILE_HEADER.Machine),
            "machine_name": {
                0x14c: "x86",
                0x8664: "x64",
                0xaa64: "ARM64",
                0x1c4: "ARM",
            }.get(pe.FILE_HEADER.Machine, "unknown"),
            "subsystem": int(pe.OPTIONAL_HEADER.Subsystem),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "entry_point_rva": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "section_count": len(pe.sections),
        })
        try:
            directory_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
            metadata["managed_dotnet"] = bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[directory_index].VirtualAddress)
        except Exception:
            pass
        for section in pe.sections[:128]:
            name = section.Name.rstrip(b"\\x00").decode("ascii", errors="replace")
            metadata["sections"].append({
                "name": name,
                "virtual_size": int(section.Misc_VirtualSize),
                "raw_size": int(section.SizeOfRawData),
                "entropy": round(section.get_entropy(), 3),
                "characteristics": hex(section.Characteristics),
            })
        import_entries = getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
        for entry in import_entries:
            dll = entry.dll.decode("utf-8", errors="replace") if isinstance(entry.dll, bytes) else str(entry.dll)
            functions = []
            for symbol in entry.imports[:300]:
                name = symbol.name.decode("utf-8", errors="replace") if symbol.name else None
                functions.append({"name": name, "ordinal": symbol.ordinal, "address": hex(symbol.address)})
            metadata["imports"].append({"dll": dll, "symbols": functions, "symbol_count": len(entry.imports)})
        delay_entries = getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", [])
        for entry in delay_entries:
            dll = entry.dll.decode("utf-8", errors="replace") if isinstance(entry.dll, bytes) else str(entry.dll)
            metadata["imports"].append({"dll": dll, "delay_load": True, "symbols": []})
        export_entries = getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", [])
        for item in export_entries[:2000]:
            name = item.name.decode("utf-8", errors="replace") if item.name else None
            metadata["exports"].append({"name": name, "ordinal": item.ordinal, "address_rva": hex(item.address)})
        pe.close()
    except Exception as exc:
        metadata["parse_warning"] = str(exc)[:600]
    return metadata


def _discover_local_dependencies(binary_path, max_modules=16):
    """Follow PE import tables, resolving only DLLs beside the app binaries."""
    primary = Path(binary_path).expanduser().resolve()
    folder = primary.parent
    try:
        import pefile
    except ImportError:
        return [], ["Install pefile to discover app-local DLL dependencies automatically."]
    found = []
    visited = {str(primary).casefold()}
    queue = [primary]
    warnings = []
    while queue and len(found) < max_modules:
        current = queue.pop(0)
        try:
            pe = pefile.PE(str(current), fast_load=True)
            dirs = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            try:
                dirs.append(pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"])
            except Exception:
                pass
            pe.parse_data_directories(directories=dirs)
            entries = list(getattr(pe, "DIRECTORY_ENTRY_IMPORT", []))
            entries += list(getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []))
            for entry in entries:
                raw = entry.dll
                dll_name = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
                if Path(dll_name).name != dll_name:
                    continue
                local = (current.parent / dll_name).resolve()
                key = str(local).casefold()
                if key in visited or not local.is_file() or local.suffix.casefold() != ".dll":
                    continue
                visited.add(key)
                found.append(local)
                queue.append(local)
                if len(found) >= max_modules:
                    break
            pe.close()
        except Exception as exc:
            warnings.append("Dependency enumeration warning for " + current.name + ": " + str(exc)[:180])
    if queue:
        warnings.append("Dependency limit reached; increase max_modules to analyze more app-local DLLs.")
    return found, warnings


def _run_ilspy(binary, output_dir, timeout=900):
    """Optionally decompile managed .NET assemblies if ILSpy command line is installed."""
    command = shutil.which("ilspycmd")
    if not command:
        return {
            "available": False,
            "status": "skipped",
            "note": "A .NET assembly was detected, but ilspycmd was not found. Install it with: dotnet tool install --global ilspycmd",
            "source_dir": None,
            "files": [],
            "source_excerpt": "",
        }
    target = Path(output_dir).resolve()
    if target.exists() and any(target.iterdir()):
        shutil.rmtree(target)
    target.mkdir(parents=True, exist_ok=True)
    try:
        process = subprocess.run(
            [command, "-p", "-o", str(target), str(Path(binary).resolve())],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "available": True, "status": "timeout", "source_dir": str(target),
            "files": [], "source_excerpt": "",
            "note": "ILSpy command-line decompilation timed out. Inspect the module folder for partial output.",
        }
    (target / "ilspy-stdout.log").write_text(process.stdout[-30000:], encoding="utf-8", errors="replace")
    (target / "ilspy-stderr.log").write_text(process.stderr[-30000:], encoding="utf-8", errors="replace")
    source_files = sorted(target.rglob("*.cs"))[:1000]
    excerpt_parts = []
    for path in source_files:
        try:
            relative = str(path.relative_to(target))
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        excerpt_parts.append("// SOURCE FILE: " + relative + "\\n" + text[:12000])
        if sum(map(len, excerpt_parts)) >= 100000:
            break
    return {
        "available": True,
        "status": "ok" if process.returncode == 0 else "error",
        "exit_code": process.returncode,
        "source_dir": str(target),
        "files": [str(p.relative_to(target)) for p in source_files],
        "source_excerpt": "\\n\\n".join(excerpt_parts)[:100000],
        "note": "Managed source was decompiled by ILSpy; inspect source project in this folder.",
    }




def _discover_framework_modules(primary, max_count=8):
    """Find side-by-side managed apphost assemblies and known app-local payloads."""
    path = Path(primary).resolve()
    found = []
    seen = {str(path).casefold()}
    companion = path.with_suffix(".dll")
    if companion.is_file():
        found.append(companion)
        seen.add(str(companion).casefold())
    known_runtime_modules = (
        "GameAssembly.dll", "UnityPlayer.dll", "flutter_windows.dll", "libcef.dll",
        "Qt6Core.dll", "Qt5Core.dll", "WebView2Loader.dll", "mono-2.0-bdwgc.dll",
        "coreclr.dll", "hostfxr.dll", "node.dll", "v8_context_snapshot.bin",
    )
    for name in known_runtime_modules:
        candidate = path.parent / name
        key = str(candidate.resolve()).casefold()
        if candidate.is_file() and key not in seen:
            found.append(candidate.resolve())
            seen.add(key)
            if len(found) >= max_count:
                return found
    search_roots = [path.parent]
    if len(path.parents) > 1:
        search_roots.append(path.parent.parent)
    for root in search_roots:
        try:
            candidates = root.glob("*_Data/Managed/*.dll")
            prioritized = []
            others = []
            for candidate in candidates:
                lowered = candidate.name.casefold()
                if any(term in lowered for term in ("assembly-csharp", "assembly-unityscript", "firstpass", "game")):
                    prioritized.append(candidate)
                else:
                    others.append(candidate)
            for candidate in prioritized + others:
                key = str(candidate.resolve()).casefold()
                if key in seen or not candidate.is_file():
                    continue
                seen.add(key)
                found.append(candidate.resolve())
                if len(found) >= max_count:
                    return found
        except OSError:
            continue
    return found[:max_count]


def _runtime_layout(primary):
    """Collect adjacent engine/package markers without executing the program."""
    path = Path(primary).resolve()
    root = path.parent
    markers = []
    patterns = [
        "resources/app.asar", "resources/app/package.json", "package.json",
        "flutter_windows.dll", "icudtl.dat", "data/app.so", "UnityPlayer.dll",
        "GameAssembly.dll", "global-metadata.dat", "hostfxr.dll", "coreclr.dll",
        "mono-2.0-bdwgc.dll", "libcef.dll", "Qt6Core.dll", "Qt5Core.dll",
        "WebView2Loader.dll",
    ]
    for relative in patterns:
        candidate = root / relative
        if candidate.exists():
            markers.append({"path": str(candidate.relative_to(root)), "kind": "known-runtime-marker"})
    try:
        for candidate in list(root.glob("*.runtimeconfig.json"))[:10]:
            try:
                data = json.loads(candidate.read_text(encoding="utf-8", errors="replace"))
                runtime = data.get("runtimeOptions", {})
                markers.append({
                    "path": candidate.name,
                    "kind": ".NET runtime configuration",
                    "tfm": runtime.get("tfm"),
                    "framework": runtime.get("framework"),
                    "frameworks": runtime.get("frameworks"),
                })
            except (OSError, json.JSONDecodeError):
                markers.append({"path": candidate.name, "kind": ".NET runtime config", "parse": "invalid"})
        for candidate in list(root.glob("*.deps.json"))[:5]:
            try:
                data = json.loads(candidate.read_text(encoding="utf-8", errors="replace"))
                markers.append({
                    "path": candidate.name,
                    "kind": ".NET dependency manifest",
                    "runtime_targets": list(data.get("targets", {}).keys())[:10],
                    "libraries": list(data.get("libraries", {}).keys())[:60],
                })
            except (OSError, json.JSONDecodeError):
                pass
    except OSError:
        pass
    return markers


def analyze_application(binary_path, out_dir, ghidra_home=None, timeout=14400,
                        max_decompile=1000, max_modules=16, on_status=None):
    """Analyze an EXE and its app-local imported DLLs, including managed .NET code when possible."""
    status = on_status or (lambda message: None)
    primary = Path(binary_path).expanduser().resolve()
    if not primary.is_file():
        raise GhidraError("The target executable does not exist: " + str(primary))
    output = Path(out_dir).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    module_paths, dependency_warnings = _discover_local_dependencies(primary, max_modules=max_modules)
    framework_paths = _discover_framework_modules(primary, max_count=min(8, max_modules))
    ordered_modules = []
    seen_paths = {str(primary).casefold()}
    for candidate in framework_paths + module_paths:
        key = str(candidate.resolve()).casefold()
        if key not in seen_paths and candidate.is_file():
            seen_paths.add(key)
            ordered_modules.append(candidate.resolve())
        if len(ordered_modules) >= max_modules:
            break
    binaries = [primary] + ordered_modules
    module_summaries = []
    reports = []
    managed_summaries = []
    for index, binary in enumerate(binaries):
        remaining = timeout - (time.monotonic() - started)
        if remaining < 90:
            dependency_warnings.append("Overall analysis time budget reached; remaining modules were not analyzed.")
            break
        module_key = re.sub(r"[^A-Za-z0-9_.-]+", "_", binary.stem)[:70] or "module"
        module_dir = output / "modules" / (f"{index:02d}_{module_key}")
        metadata = _pe_metadata(binary)
        (module_dir).mkdir(parents=True, exist_ok=True)
        (module_dir / "pe-metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        status(f"Ghidra module {index + 1}/{len(binaries)}: {binary.name} ({metadata.get('machine_name', 'PE')})")
        try:
            report = analyze_binary(
                binary, module_dir, ghidra_home=ghidra_home,
                timeout=int(min(7200 if index == 0 else 2400, remaining)),
                max_decompile=max_decompile if index == 0 else min(max_decompile, 100),
                per_function_timeout=8,
                on_status=status,
            )
        except GhidraError as exc:
            if index == 0:
                raise
            dependency_warnings.append("Ghidra failed for dependency " + binary.name + ": " + str(exc)[:300])
            continue
        reports.append(report)
        module_summaries.append({
            "path": str(binary),
            "module": binary.name,
            "managed_dotnet": metadata.get("managed_dotnet", False),
            "function_count": report.get("function_count", 0),
            "symbol_count": report.get("symbol_count", 0),
            "string_count": report.get("string_count", 0),
            "call_reference_count": report.get("call_reference_count", 0),
            "decompiled_function_count": report.get("decompiled_function_count", 0),
            "pe_metadata_path": str(module_dir / "pe-metadata.json"),
            "ghidra_report_path": str(module_dir / "ghidra-analysis.json"),
        })
        if metadata.get("managed_dotnet"):
            status("Managed .NET assembly detected: " + binary.name)
            ilspy = _run_ilspy(binary, module_dir / "ilspy-source")
            ilspy["module"] = binary.name
            managed_summaries.append(ilspy)
    if not reports:
        raise GhidraError("Ghidra did not complete analysis for any modules.")
    merged = dict(reports[0])
    merged["analyzed_binary"] = str(primary)
    merged["modules"] = module_summaries
    merged["dependency_warnings"] = dependency_warnings
    merged["total_function_count"] = sum(item.get("function_count", 0) for item in module_summaries)
    merged["total_symbol_count"] = sum(item.get("symbol_count", 0) for item in module_summaries)
    merged["total_string_count"] = sum(item.get("string_count", 0) for item in module_summaries)
    merged["total_call_reference_count"] = sum(item.get("call_reference_count", 0) for item in module_summaries)
    merged["managed_decompilation"] = [
        {key: value for key, value in item.items() if key != "source_excerpt"}
        for item in managed_summaries
    ]
    merged["module_functions"] = [
        {"module": report.get("program_name"), "name": function.get("name"),
         "address": function.get("address"), "parameter_count": function.get("parameter_count"),
         "size_bytes": function.get("size_bytes")}
        for report in reports[1:] for function in report.get("functions", [])[:150]
    ][:1200]
    merged["module_strings"] = [
        {"module": report.get("program_name"), "value": item.get("value"), "address": item.get("address")}
        for report in reports[1:] for item in report.get("strings", [])[:150]
    ][:1200]
    merged["module_decompiled_functions"] = [
        {"module": report.get("program_name"), "name": item.get("name"),
         "address": item.get("address"), "code": item.get("code", "")[:1200]}
        for report in reports[1:] for item in report.get("decompiled_functions", [])[:8]
    ][:60]
    merged["ilspy_source_excerpt"] = "\\n\\n".join(
        "MODULE " + item.get("module", "") + "\\n" + item.get("source_excerpt", "")
        for item in managed_summaries if item.get("source_excerpt")
    )[:20000]
    merged["deep_analysis_completed_at"] = _now()
    merged["analysis_elapsed_seconds"] = round(time.monotonic() - started, 2)
    merged["runtime_layout_markers"] = _runtime_layout(primary)
    merged["analysis_notes"] = [
        "Ghidra runs its normal auto-analysis on every successfully analyzed PE module.",
        "Complete function, symbol, string, call-reference, and decompilation inventories remain in module-specific JSONL sidecars.",
        "App-local imported DLLs are recursively discovered from PE imports; side-by-side .NET and Unity Managed DLLs receive priority within max_modules.",
        "Runtime markers detect adjacent Electron ASAR, Unity/IL2CPP, Flutter, WebView2, Qt, and .NET deployment files when present.",
        "Managed .NET code is additionally decompiled with ILSpy when ilspycmd is installed.",
    ] + dependency_warnings
    master_report = output / "ghidra-analysis.json"
    master_report.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    status(
        "Deep analysis complete: " + str(merged["total_function_count"]) + " functions across "
        + str(len(module_summaries)) + " PE modules."
    )
    return merged

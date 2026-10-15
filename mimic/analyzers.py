"""Application-type detection and local, format-specific reverse-engineering orchestration."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import zipfile
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET

from .ollama import Ollama, OllamaError
from .ghidra import (
    GhidraError,
    analyze_application,
    analyze_binary,
    find_ghidra_home,
)

SUPPORTED_ARCHIVES = {".apk", ".aab", ".aar", ".apkm", ".xapk", ".ipa", ".appx", ".msix", ".zip", ".jar"}
ANDROID_TYPES = {".apk", ".aab", ".aar", ".apkm", ".xapk", ".dex", ".smali"}
APPLE_TYPES = {".ipa", ".dylib", ".framework", ".bundle"}
PE_TYPES = {".exe", ".dll", ".ocx", ".sys"}
NATIVE_TYPES = {".so", ".dylib", ".elf", ".o", ".a", ".bin", ".mach-o"}
JS_TYPES = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".html", ".css", ".map"}
MAX_ARCHIVE_MEMBERS = 100_000
MAX_MEMBER_BYTES = 1_500_000_000
MAX_TOTAL_EXTRACT_BYTES = 8_000_000_000


class ReverseEngineeringError(RuntimeError):
    pass


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _hash_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def detect_runtime(path):
    """Classify a path using package markers, file extension, and byte signatures."""
    target = Path(path).expanduser().resolve()
    if not target.exists():
        raise FileNotFoundError("Target path not found: " + str(target))
    ext = target.suffix.casefold()
    facts: dict[str, Any] = {
        "target": str(target),
        "exists": True,
        "is_directory": target.is_dir(),
        "extension": ext,
        "frameworks": [],
        "runtime_signatures": [],
        "confidence": "medium",
    }
    if target.is_dir():
        names = {item.name.casefold() for item in target.iterdir()}
        if "appxmanifest.xml" in names:
            facts["type"] = "windows_package"
            facts["frameworks"].append("UWP/MSIX")
            return facts
        if (target / "resources" / "app.asar").is_file() or (target / "app.asar").is_file():
            facts["type"] = "electron"
            facts["frameworks"].append("Electron")
            return facts
        if "info.plist" in names or target.suffix.casefold() == ".app":
            facts["type"] = "apple_app_bundle"
            facts["frameworks"].append("macOS/iOS bundle")
            return facts
        if (target / "package.json").is_file():
            facts["type"] = "javascript_project"
            try:
                package = json.loads((target / "package.json").read_text(encoding="utf-8", errors="replace"))
                deps = {**package.get("dependencies", {}), **package.get("devDependencies", {})}
                if "electron" in deps:
                    facts["type"] = "electron"
                    facts["frameworks"].append("Electron")
                for name in ("react", "vue", "angular", "svelte", "next", "vite", "react-native", "expo"):
                    if name in deps:
                        facts["frameworks"].append(name)
            except (OSError, json.JSONDecodeError, TypeError):
                pass
            return facts
        if list(target.glob("*.exe")):
            facts["type"] = "windows_application_folder"
            facts["confidence"] = "medium"
            return facts
        if list(target.glob("*.py")):
            facts["type"] = "python_project"
            return facts
        if list(target.glob("*.java")) or list(target.glob("*.kt")):
            facts["type"] = "jvm_project"
            return facts
        if list(target.glob("*.cs")) or list(target.glob("*.csproj")) or list(target.glob("*.sln")):
            facts["type"] = "dotnet_project"
            facts["frameworks"].append(".NET")
            return facts
        facts["type"] = "directory"
        facts["confidence"] = "low"
        return facts

    if ext in ANDROID_TYPES:
        facts["type"] = "android_package" if ext in {".apk", ".aab", ".apkm", ".xapk"} else "jvm_bytecode"
        facts["frameworks"].append("Android/Dalvik" if facts["type"] == "android_package" else "JVM/Dalvik")
        return facts
    if ext in APPLE_TYPES:
        facts["type"] = "apple_binary_or_package"
        return facts
    if ext in {".jar", ".class", ".war"}:
        facts["type"] = "jvm_bytecode"
        return facts
    if ext in {".appx", ".msix", ".msixbundle", ".appxbundle"}:
        facts["type"] = "windows_package"
        return facts
    if ext in {".msi", ".msp", ".msm"}:
        facts["type"] = "windows_installer"
        return facts
    if ext in {".csproj", ".sln"}:
        facts["type"] = "dotnet_project"
        facts["frameworks"].append(".NET")
        return facts
    if ext == ".asar":
        facts["type"] = "electron"
        return facts
    if ext == ".zip":
        try:
            with zipfile.ZipFile(target) as archive:
                names = {item.filename.replace("\\\\", "/").casefold() for item in archive.infolist()[:MAX_ARCHIVE_MEMBERS]}
            if any(name.endswith("androidmanifest.xml") for name in names) and any("/classes" in name and name.endswith(".dex") for name in names):
                facts["type"] = "android_package"
                facts["frameworks"].append("Android/Dalvik")
            elif any("/payload/" in name and name.endswith("/info.plist") for name in names):
                facts["type"] = "apple_binary_or_package"
                facts["frameworks"].append("iOS IPA-like archive")
            elif any(name.endswith("app.asar") for name in names):
                facts["type"] = "electron"
                facts["frameworks"].append("Electron")
            else:
                facts["type"] = "source_archive"
        except (zipfile.BadZipFile, OSError):
            facts["type"] = "unknown"
            facts["confidence"] = "low"
        return facts
    if ext in {".py", ".pyw", ".pyc", ".pyo", ".pyz"}:
        facts["type"] = "python"
        facts["frameworks"].append("Python")
        return facts
    if ext in JS_TYPES:
        facts["type"] = "javascript_source"
        return facts
    if ext in PE_TYPES or ext in NATIVE_TYPES or not ext:
        signature = b""
        with target.open("rb") as stream:
            signature = stream.read(65536)
        if b"PyInstaller" in signature or b"pyi-windows-manifest-filename" in signature:
            facts["frameworks"].append("PyInstaller")
        if b"MSIL" in signature or b".NET" in signature:
            facts["frameworks"].append(".NET (possible)")
        if b"flutter_windows.dll" in signature or b"Dart" in signature:
            facts["frameworks"].append("Flutter/Dart (possible)")
        if b"Go build ID:" in signature or b"runtime.main" in signature:
            facts["frameworks"].append("Go (possible)")
        if b"Rust" in signature:
            facts["frameworks"].append("Rust (possible)")
        if any(marker in signature for marker in (b"Inno Setup", b"Nullsoft Install System", b"InstallShield", b"WiX Toolset", b"Advanced Installer")):
            facts["type"] = "windows_installer"
            facts["frameworks"].append("Windows installer bundle")
            facts["confidence"] = "medium"
            return facts
        if "PyInstaller" in facts["frameworks"]:
            facts["type"] = "python_frozen"
            facts["confidence"] = "high"
            return facts
        if ext in PE_TYPES:
            facts["type"] = "windows_binary"
            facts["confidence"] = "high"
        else:
            facts["type"] = "native_binary"
            facts["confidence"] = "medium"
        return facts
    if ext in SUPPORTED_ARCHIVES:
        facts["type"] = "archive"
        return facts
    facts["type"] = "unknown"
    facts["confidence"] = "low"
    return facts


def _run_tool(command, log_path, timeout, cwd=None):
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    run_command = list(command)
    if os.name == "nt" and str(command[0]).casefold().endswith((".bat", ".cmd")):
        run_command = ["cmd.exe", "/d", "/s", "/c", subprocess.list2cmdline(command)]

    def as_text(value):
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value or "")

    try:
        result = subprocess.run(
            run_command, capture_output=True, text=True, timeout=timeout,
            cwd=cwd, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
        )
    except FileNotFoundError:
        return {"available": False, "status": "missing", "command": command[0], "exit_code": None}
    except subprocess.TimeoutExpired as exc:
        path.write_text(
            as_text(exc.stdout)[-50000:] + "\n[TIMEOUT]\n" + as_text(exc.stderr)[-50000:],
            encoding="utf-8", errors="replace",
        )
        return {"available": True, "status": "timeout", "command": command[0], "exit_code": None, "log": str(path)}
    output = (result.stdout or "")[-100000:] + "\n--- STDERR ---\n" + (result.stderr or "")[-50000:]
    path.write_text(output, encoding="utf-8", errors="replace")
    return {
        "available": True,
        "status": "ok" if result.returncode == 0 else "error",
        "command": command[0],
        "exit_code": result.returncode,
        "log": str(path),
        "stdout_excerpt": (result.stdout or "")[-12000:],
        "stderr_excerpt": (result.stderr or "")[-6000:],
    }


def _safe_extract_members(archive_path, out_dir, predicate, max_members=MAX_ARCHIVE_MEMBERS,
                          max_total=MAX_TOTAL_EXTRACT_BYTES):
    """Extract selected archive members while rejecting traversal and oversized entries."""
    dest = Path(out_dir).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    extracted = []
    total, count = 0, 0
    try:
        with zipfile.ZipFile(archive_path) as archive:
            infos = archive.infolist()
            if len(infos) > max_members:
                raise ReverseEngineeringError(f"Archive has {len(infos)} entries, exceeding the safety limit.")
            for info in infos:
                if info.is_dir() or not predicate(info.filename):
                    continue
                normalized = info.filename.replace("\\", "/")
                parts = Path(normalized).parts
                if normalized.startswith("/") or ".." in parts:
                    continue
                if info.file_size > MAX_MEMBER_BYTES:
                    continue
                total += info.file_size
                count += 1
                if count > max_members or total > max_total:
                    raise ReverseEngineeringError("Archive extraction limit reached; reduce package size or choose a smaller artifact.")
                output = (dest / Path(*parts)).resolve()
                if dest not in output.parents:
                    continue
                output.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, output.open("wb") as target:
                    shutil.copyfileobj(source, target)
                extracted.append(str(output))
    except zipfile.BadZipFile as exc:
        raise ReverseEngineeringError("File is not a readable ZIP-based package: " + str(archive_path)) from exc
    return extracted


def _archive_inventory(path):
    items = []
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist()[:MAX_ARCHIVE_MEMBERS]:
            name = info.filename.replace("\\", "/")
            if name.endswith("/"):
                continue
            suffix = Path(name).suffix.casefold()
            if suffix in {".dex", ".so", ".dll", ".dylib", ".exe", ".jar", ".class", ".pyc", ".js", ".mjs", ".wasm", ".json", ".xml", ".plist", ".asar", ".pak", ".dat"}:
                items.append({
                    "path": name[:350],
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                    "type": suffix or "file",
                })
    return items[:12000]


def _source_inventory(root, max_files=4000):
    base = Path(root).resolve()
    result, snippets = [], []
    ignore = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", ".venv", "venv", "obj", "bin"}
    code_suffixes = {".py", ".pyx", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".html", ".css", ".json", ".xml", ".java", ".kt", ".cs", ".cpp", ".c", ".h", ".hpp", ".go", ".rs", ".swift", ".dart", ".sql", ".ps1", ".bat", ".sh"}
    count = 0
    for path in base.rglob("*"):
        if not path.is_file() or any(part in ignore for part in path.parts):
            continue
        if path.suffix.casefold() not in code_suffixes:
            continue
        count += 1
        if count > max_files:
            break
        try:
            size = path.stat().st_size
            if size > 2_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        relative = str(path.relative_to(base))
        digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
        classes = re.findall(r"\b(?:class|interface|enum|struct|record)\s+([A-Za-z_$][\w$]*)", text)[:60]
        functions = re.findall(r"\b(?:function\s+([A-Za-z_$][\w$]*)|(?:def|fn|func)\s+([A-Za-z_$][\w$]*))", text)[:80]
        functions = [a or b for a, b in functions]
        result.append({
            "path": relative,
            "size": size,
            "sha256": digest,
            "classes": classes,
            "functions": functions,
            "line_count": text.count("\n") + 1,
        })
        if len(snippets) < 80 and any(term in relative.casefold() for term in (
            "main", "app", "route", "view", "screen", "controller", "service", "api", "manifest", "electron"
        )):
            snippets.append({"path": relative, "content": text[:4000]})
    report_path = base / "mimic-source-inventory.json"
    report_path.write_text(json.dumps({"root": str(base), "file_count_scanned": count,
                                       "files": result, "priority_source_samples": snippets}, indent=2),
                           encoding="utf-8")
    return {"file_count": len(result), "files": result, "priority_source_samples": snippets,
            "report_path": str(report_path)}


def _run_jadx(target, output, timeout=3600, status=None):
    tool = shutil.which("jadx") or shutil.which("jadx.bat") or shutil.which("jadx.cmd")
    if not tool:
        return {"available": False, "status": "missing", "note": "Install JADX and put jadx.bat/bin on PATH to analyze APK/DEX/JAR/AAB files."}
    status = status or (lambda message: None)
    status("JADX: decompiling managed/mobile bytecode and decoding available resources…")
    out = Path(output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    result = _run_tool([tool, "--show-bad-code", "-d", str(out), str(Path(target).resolve())],
                       out.parent / "jadx.log", timeout)
    result["output_dir"] = str(out)
    if result.get("status") == "ok":
        result["source_inventory"] = _source_inventory(out, max_files=8000)
    return result


def _run_apktool(target, output, timeout=2400):
    tool = shutil.which("apktool") or shutil.which("apktool.bat")
    if not tool:
        return {"available": False, "status": "missing", "note": "Install Apktool to decode Android resources and smali. JADX is a separate decoder."}
    out = Path(output).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    result = _run_tool([tool, "d", "-f", str(Path(target).resolve()), "-o", str(out)],
                       out.parent / "apktool.log", timeout)
    result["output_dir"] = str(out)
    if out.is_dir():
        result["resource_inventory"] = _source_inventory(out, max_files=8000)
    return result


def _analyze_archive_native(archive_path, out_dir, ghidra_home, status, max_modules=8):
    extracted_dir = Path(out_dir) / "native-libraries"
    extracted = _safe_extract_members(
        archive_path, extracted_dir,
        lambda name: Path(name).suffix.casefold() in {".so", ".dylib", ".dll", ".exe"},
        max_members=max_modules,
        max_total=2_000_000_000,
    )
    results = []
    for index, filename in enumerate(extracted[:max_modules]):
        binary = Path(filename)
        directory = Path(out_dir) / "native-analysis" / f"{index:02d}_{binary.stem[:60]}"
        try:
            if status:
                status("Ghidra native module " + str(index + 1) + "/" + str(len(extracted)) + ": " + binary.name)
            results.append(analyze_binary(
                str(binary), str(directory), ghidra_home=ghidra_home,
                timeout=1800, max_decompile=80, per_function_timeout=8, on_status=status,
            ))
        except GhidraError as exc:
            results.append({"analyzed_binary": str(binary), "status": "error", "error": str(exc)})
    return results


def _read_manifest_xml(path):
    try:
        root = ET.parse(path).getroot()
        return {
            "root_tag": root.tag,
            "attributes": dict(root.attrib),
            "child_tags": [child.tag for child in list(root)[:250]],
            "xml_excerpt": Path(path).read_text(encoding="utf-8", errors="replace")[:20000],
        }
    except (OSError, ET.ParseError):
        return {"path": str(path), "parse_status": "unavailable"}


def _analyze_android(target, out_dir, ghidra_home, status):
    output = Path(out_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    inventory = _archive_inventory(target)
    (output / "package-inventory.json").write_text(json.dumps(inventory, indent=2), encoding="utf-8")
    report: dict[str, Any] = {
        "type": "android_package",
        "target": str(target),
        "package_inventory": str(output / "package-inventory.json"),
        "package_files": inventory,
        "tools": {},
        "native_modules": [],
        "warnings": [],
    }
    report["tools"]["jadx"] = _run_jadx(target, output / "jadx-output", status=status)
    report["tools"]["apktool"] = _run_apktool(target, output / "apktool-output")
    if target.suffix.casefold() in {".apk", ".xapk", ".apkm"}:
        try:
            report["native_modules"] = _analyze_archive_native(target, output, ghidra_home, status)
        except (zipfile.BadZipFile, ReverseEngineeringError, OSError) as exc:
            report["warnings"].append("Could not extract native libraries: " + str(exc))
    elif target.suffix.casefold() in {".aab", ".aar"}:
        try:
            report["native_modules"] = _analyze_archive_native(target, output, ghidra_home, status, max_modules=4)
        except (zipfile.BadZipFile, ReverseEngineeringError, OSError) as exc:
            report["warnings"].append("Could not extract native libraries: " + str(exc))
    decoded = output / "apktool-output" / "AndroidManifest.xml"
    if decoded.is_file():
        report["manifest"] = _read_manifest_xml(decoded)
    return report


def _analyze_apple(target, out_dir, ghidra_home, status):
    output = Path(out_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {"type": "apple_package", "target": str(target), "warnings": []}
    candidate = Path(target)
    if candidate.is_file() and candidate.suffix.casefold() == ".ipa":
        bundle_dir = output / "ipa-extracted"
        extracted = _safe_extract_members(
            candidate, bundle_dir,
            lambda name: name.startswith("Payload/") and (
                name.endswith("/Info.plist") or
                name.endswith("/PkgInfo") or
                Path(name).suffix.casefold() in {".dylib", ".framework", ".bundle"}
            ),
        )
        plists = [Path(name) for name in extracted if Path(name).name == "Info.plist"]
        if plists:
            import plistlib
            try:
                with plists[0].open("rb") as stream:
                    info = plistlib.load(stream)
                executable = info.get("CFBundleExecutable")
                report["bundle_identifier"] = info.get("CFBundleIdentifier")
                report["bundle_name"] = info.get("CFBundleName") or info.get("CFBundleDisplayName")
                binary = plists[0].parent / executable if executable else None
                # Extract the app executable separately, using a path derived only from the plist's basename.
                if binary and not binary.is_file():
                    path_inside = str(plists[0].relative_to(bundle_dir).parent / executable).replace("\\", "/")
                    extracted_exec = _safe_extract_members(
                        candidate, bundle_dir,
                        lambda name: name == path_inside,
                        max_members=1, max_total=2_000_000_000,
                    )
                    binary = Path(extracted_exec[0]) if extracted_exec else None
                if binary and binary.is_file():
                    report["executable_path"] = str(binary)
                    try:
                        report["native_analysis"] = analyze_binary(
                            str(binary), str(output / "ghidra-native"), ghidra_home=ghidra_home,
                            max_decompile=150, on_status=status,
                        )
                    except GhidraError as exc:
                        report["warnings"].append("Ghidra could not analyze iOS Mach-O in this environment: " + str(exc))
            except (OSError, ValueError, Exception) as exc:
                report["warnings"].append("Could not fully analyze IPA bundle metadata: " + str(exc)[:400])
        report["package_inventory"] = _archive_inventory(candidate)
        return report
    if candidate.is_dir():
        plist = candidate / "Contents" / "Info.plist"
        if not plist.is_file():
            plist = candidate / "Info.plist"
        if plist.is_file():
            import plistlib
            try:
                info = plistlib.loads(plist.read_bytes())
                report["bundle_identifier"] = info.get("CFBundleIdentifier")
                report["bundle_name"] = info.get("CFBundleName")
            except Exception as exc:
                report["warnings"].append(str(exc)[:200])
    if candidate.is_file() and candidate.suffix.casefold() in {".dylib", ".so"}:
        report["native_analysis"] = analyze_binary(str(candidate), str(output / "ghidra-native"), ghidra_home=ghidra_home, max_decompile=150, on_status=status)
    report["source_inventory"] = _source_inventory(candidate, max_files=8000) if candidate.is_dir() else None
    return report


def _find_asar(target):
    candidate = Path(target).resolve()
    if candidate.is_file() and candidate.name.casefold() == "app.asar":
        return candidate
    if candidate.is_dir():
        possible = [candidate / "resources" / "app.asar", candidate / "app.asar"]
    else:
        possible = [candidate.parent / "resources" / "app.asar", candidate.parent / "app.asar"]
        for parent in list(candidate.parents)[:5]:
            possible.append(parent / "resources" / "app.asar")
    for path in possible:
        if path.is_file():
            return path
    return None


def _analyze_electron(target, out_dir, status):
    output = Path(out_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    archive = _find_asar(target)
    report: dict[str, Any] = {"type": "electron", "target": str(target), "asar_path": str(archive) if archive else None, "warnings": []}
    if not archive:
        if Path(target).is_dir():
            report["source_inventory"] = _source_inventory(target)
            package_file = Path(target) / "package.json"
            if package_file.is_file():
                report["package_json"] = json.loads(package_file.read_text(encoding="utf-8", errors="replace"))
        else:
            report["warnings"].append("Electron app.asar was not located. Select the installed app folder or resources/app.asar.")
        return report
    asar_tool = shutil.which("asar") or shutil.which("asar.cmd") or shutil.which("asar.bat")
    if not asar_tool:
        report["warnings"].append("Install the Electron asar CLI locally and put it on PATH to unpack app.asar; Mimic will not download tools automatically.")
        return report
    status("Electron: unpacking app.asar using the installed local asar tool…")
    extracted = output / "asar-source"
    result = _run_tool([asar_tool, "extract", str(archive), str(extracted)], output / "asar.log", 1200)
    report["asar_tool"] = result
    if result.get("status") == "ok" and extracted.is_dir():
        report["source_inventory"] = _source_inventory(extracted, max_files=15000)
        package_file = extracted / "package.json"
        if package_file.is_file():
            try:
                report["package_json"] = json.loads(package_file.read_text(encoding="utf-8", errors="replace"))
            except json.JSONDecodeError:
                report["warnings"].append("Extracted Electron package.json is invalid JSON.")
    return report


def _analyze_jvm(target, out_dir, status):
    output = Path(out_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = {"type": "jvm_bytecode", "target": str(target), "tools": {}, "warnings": []}
    report["tools"]["jadx"] = _run_jadx(target, output / "jadx-output", timeout=3600, status=status)
    if Path(target).suffix.casefold() == ".jar":
        javap = shutil.which("javap") or shutil.which("javap.exe")
        if javap:
            classes = []
            try:
                with zipfile.ZipFile(target) as archive:
                    for info in archive.infolist():
                        name = info.filename
                        if name.endswith(".class") and not name.startswith("META-INF/versions/"):
                            classname = name[:-6].replace("/", ".").replace("\\", ".")
                            if not classname.endswith(("module-info", "package-info")):
                                classes.append(classname)
                        if len(classes) >= 30:
                            break
            except (OSError, zipfile.BadZipFile):
                classes = []
            class_reports = []
            for classname in classes[:25]:
                item = _run_tool(
                    [javap, "-classpath", str(Path(target).resolve()), "-private", "-c", "-s", classname],
                    output / "javap" / (re.sub(r"[^A-Za-z0-9_.-]+", "_", classname)[:100] + ".log"),
                    180,
                )
                item["class"] = classname
                class_reports.append(item)
            report["tools"]["javap"] = {
                "available": True,
                "status": "ok" if any(item.get("status") == "ok" for item in class_reports) else "error",
                "class_count_attempted": len(class_reports),
                "classes": class_reports,
            }
        else:
            report["warnings"].append("javap not found; install a JDK for additional JVM bytecode and descriptor output.")
    return report


def _disassemble_pyc(path, output_dir):
    import dis
    import importlib.util
    import marshal
    import types

    source = Path(path)
    data = source.read_bytes()
    if len(data) < 16:
        return {"status": "error", "note": "File is too small to be a standard modern Python .pyc."}
    if data[:4] != importlib.util.MAGIC_NUMBER:
        return {
            "status": "incompatible_python_version",
            "note": "The pyc magic number does not match the current interpreter. Use a matching Python runtime or a version-independent decompiler.",
            "magic_hex": data[:4].hex(),
        }
    try:
        code = marshal.loads(data[16:])
    except (ValueError, EOFError, TypeError) as exc:
        return {"status": "error", "note": "Bytecode could not be unmarshalled: " + str(exc)[:240]}
    if not isinstance(code, types.CodeType):
        return {"status": "error", "note": "PYC did not contain a code object."}
    dest = Path(output_dir)
    dest.mkdir(parents=True, exist_ok=True)
    output = dest / (source.stem + ".dis.txt")
    with output.open("w", encoding="utf-8", errors="replace") as stream:
        stream.write("Python bytecode disassembly for " + str(source) + "\n")
        dis.dis(code, file=stream, depth=None)
    return {"status": "ok", "magic_hex": data[:4].hex(), "python_version": sys.version,
            "disassembly": str(output), "note": "Disassembly only; this is not equivalent to recovered source code."}


def _analyze_python(target, out_dir):
    output = Path(out_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    path = Path(target).resolve()
    report: dict[str, Any] = {"type": "python", "target": str(path), "tools": {}, "warnings": []}
    if path.is_dir() or path.suffix.casefold() in {".py", ".pyw"}:
        root = path if path.is_dir() else path.parent
        report["source_inventory"] = _source_inventory(root, max_files=12000)
    if path.suffix.casefold() == ".pyz":
        extracted = _safe_extract_members(
            path, output / "pyz-extracted",
            lambda name: Path(name).suffix.casefold() in {".py", ".pyc", ".pyo", ".json", ".toml", ".txt", ".so", ".pyd", ".dll"},
            max_members=15000,
            max_total=2_000_000_000,
        )
        report["pyz_extracted_file_count"] = len(extracted)
        report["source_inventory"] = _source_inventory(output / "pyz-extracted", max_files=15000)
    if path.suffix.casefold() in {".pyc", ".pyo"}:
        report["bytecode"] = _disassemble_pyc(path, output / "disassembly")
        report["tools"]["uncompyle6"] = {"available": bool(shutil.which("uncompyle6")), "path": shutil.which("uncompyle6")}
        report["tools"]["decompyle3"] = {"available": bool(shutil.which("decompyle3")), "path": shutil.which("decompyle3")}
        report["tools"]["pycdc"] = {"available": bool(shutil.which("pycdc")), "path": shutil.which("pycdc")}
        if report["bytecode"].get("status") == "incompatible_python_version":
            report["warnings"].append("Current Python cannot disassemble this bytecode version; use a matching Python version or pyinstxtractor-ng plus a compatible decompiler.")
    if path.suffix.casefold() == ".exe":
        extractor = shutil.which("pyinstxtractor-ng") or shutil.which("pyinstxtractor-ng.exe") or shutil.which("pyinstxtractor")
        if extractor:
            extracted_result = _run_tool([extractor, str(path)], output / "pyinstxtractor.log", 1800, cwd=str(output))
            report["tools"]["pyinstxtractor-ng"] = extracted_result
            candidates = list(output.glob(path.name + "_extracted")) + list(output.glob(path.stem + "_extracted"))
            if candidates and candidates[0].is_dir():
                tree = candidates[0]
                report["extracted_dir"] = str(tree)
                report["source_inventory"] = _source_inventory(tree, max_files=15000)
                pyc_files = list(tree.rglob("*.pyc"))[:50]
                decompiler = shutil.which("decompyle3") or shutil.which("uncompyle6")
                if decompiler and pyc_files:
                    result = _run_tool([decompiler, "-o", str(output / "decompiled-source"), *map(str, pyc_files)],
                                       output / "python-decompiler.log", 1800, cwd=str(tree))
                    report["tools"]["python_decompiler"] = result
        else:
            report["warnings"].append("No pyinstxtractor-ng found. If this is a PyInstaller EXE, install pyinstxtractor-ng locally to unpack embedded Python modules; Mimic will not download tools automatically.")
    return report


def _analyze_source(target, out_dir):
    output = Path(out_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    path = Path(target).resolve()
    if path.is_dir():
        root = path
    else:
        root = path.parent
        inventory = output / "source-input"
        inventory.mkdir(exist_ok=True)
        copied = inventory / path.name
        if copied.resolve() != path:
            shutil.copy2(path, copied)
        root = inventory
    result = _source_inventory(root, max_files=15000)
    return {"type": "source_project", "target": str(path), "source_inventory": result}


def reverse_engineer(target, out_dir, *, ghidra_home=None, on_status=None):
    """Choose local analyzers for common desktop/mobile/archive/source formats."""
    status = on_status or (lambda message: None)
    start = time.monotonic()
    target_path = Path(target).expanduser().resolve()
    output = Path(out_dir).expanduser().resolve()
    if output.exists() and any(output.iterdir()):
        # It is safe to reuse our own report tree, but never overwrite arbitrary user content.
        marker = output / "mimic-analysis-manifest.json"
        if not marker.is_file():
            raise FileExistsError("Analysis output directory is not empty and has no Mimic manifest: " + str(output))
    output.mkdir(parents=True, exist_ok=True)
    detection = detect_runtime(target_path)
    status("Detected application type: " + detection["type"] + " (" + str(detection.get("frameworks") or []) + ")")
    report: dict[str, Any] = {
        "schema_version": 1,
        "analyzer": "Mimic local reverse-engineering orchestrator",
        "created_at": _now(),
        "target": str(target_path),
        "detection": detection,
        "analysis": {},
        "warnings": [],
        "tool_availability": {},
    }
    if target_path.is_file():
        report["sha256"] = _hash_file(target_path)
    ext = target_path.suffix.casefold()
    try:
        if detection["type"] in {"windows_binary"}:
            report["analysis"] = analyze_application(str(target_path), str(output / "native-analysis"),
                                                     ghidra_home=ghidra_home, on_status=status)
            # Detect and analyze Electron resources colocated with the executable.
            if _find_asar(target_path):
                report["analysis"]["electron"] = _analyze_electron(target_path, output / "electron-analysis", status)
        elif detection["type"] == "native_binary":
            if ext == ".pyc":
                report["analysis"] = _analyze_python(target_path, output / "python-analysis")
            else:
                report["analysis"] = {
                    "native_analysis": analyze_binary(
                        str(target_path), str(output / "native-analysis"),
                        ghidra_home=ghidra_home, max_decompile=350, on_status=status,
                    )
                }
        elif detection["type"] == "android_package":
            report["analysis"] = _analyze_android(target_path, output / "android-analysis", ghidra_home, status)
        elif detection["type"] == "jvm_bytecode":
            report["analysis"] = _analyze_jvm(target_path, output / "jvm-analysis", status)
        elif detection["type"] == "apple_binary_or_package":
            report["analysis"] = _analyze_apple(target_path, output / "apple-analysis", ghidra_home, status)
        elif detection["type"] == "electron":
            report["analysis"] = _analyze_electron(target_path, output / "electron-analysis", status)
        elif detection["type"] in {"javascript_project", "python_project", "jvm_project", "directory"}:
            report["analysis"] = _analyze_source(target_path, output / "source-analysis")
        elif detection["type"] == "javascript_source":
            report["analysis"] = _analyze_source(target_path, output / "source-analysis")
        elif detection["type"] == "python":
            report["analysis"] = _analyze_python(target_path, output / "python-analysis")
        elif detection["type"] == "windows_package":
            extracted = _safe_extract_members(
                target_path, output / "package-extracted",
                lambda name: Path(name).suffix.casefold() in {".exe", ".dll", ".ocx", ".sys", ".xml", ".json", ".config", ".manifest"},
            )
            report["analysis"] = {"type": "windows_package", "extracted_file_count": len(extracted), "files": extracted[:1000]}
            manifests = [p for p in extracted if Path(p).name.casefold() in {"appxmanifest.xml", "package.json"}]
            report["analysis"]["manifests"] = [_read_manifest_xml(p) if Path(p).suffix.casefold() == ".xml" else json.loads(Path(p).read_text(encoding="utf-8", errors="replace")) for p in manifests[:20]]
            binaries = [p for p in extracted if Path(p).suffix.casefold() in PE_TYPES]
            for index, binary in enumerate(binaries[:16]):
                try:
                    report["analysis"].setdefault("binary_reports", []).append(analyze_application(
                        binary, str(output / "package-binaries" / f"{index:02d}_{Path(binary).stem[:50]}"),
                        ghidra_home=ghidra_home, max_modules=4, max_decompile=100, on_status=status,
                    ))
                except GhidraError as exc:
                    report["warnings"].append(str(exc))
        elif ext in {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".html", ".css"}:
            report["analysis"] = _analyze_source(target_path, output / "source-analysis")
        else:
            report["warnings"].append("No specific analyzer was selected for this file type. Try selecting the application folder or its main executable.")
    except (GhidraError, ReverseEngineeringError, OSError, ValueError, json.JSONDecodeError) as exc:
        report["warnings"].append(str(exc))
        report["analysis_error"] = str(exc)
    report["analysis_elapsed_seconds"] = round(time.monotonic() - start, 2)
    manifest_path = output / "mimic-analysis-manifest.json"
    manifest_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    report["manifest_path"] = str(manifest_path)
    return report

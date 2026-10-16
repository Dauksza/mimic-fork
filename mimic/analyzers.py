"""Application-type detection and local, format-specific reverse-engineering orchestration."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
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

SUPPORTED_ARCHIVES = {".apk", ".aab", ".aar", ".apkm", ".apks", ".xapk", ".ipa", ".appx", ".msix", ".zip", ".jar"}
ANDROID_TYPES = {".apk", ".aab", ".aar", ".apkm", ".apks", ".xapk", ".dex", ".smali"}
APPLE_TYPES = {".ipa", ".dylib", ".framework", ".bundle"}
PE_TYPES = {".exe", ".dll", ".ocx", ".sys"}
NATIVE_TYPES = {".so", ".dylib", ".elf", ".o", ".a", ".bin", ".mach-o"}
WASM_TYPES = {".wasm", ".wat"}
SYSTEM_PACKAGE_TYPES = {".deb", ".rpm", ".appimage", ".flatpak", ".snap", ".dmg", ".pkg", ".tar", ".tgz", ".tbz", ".txz"}
PACKAGE_MEMBER_SUFFIXES = {".py", ".pyw", ".pyc", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".html", ".css", ".json", ".xml", ".plist", ".java", ".kt", ".cs", ".cpp", ".c", ".h", ".hpp", ".go", ".rs", ".swift", ".dart", ".sql", ".ps1", ".bat", ".sh", ".toml", ".yaml", ".yml", ".so", ".dylib", ".dll", ".exe", ".jar", ".wasm", ".config", ".manifest", ".md", ".properties"}
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
            facts["confidence"] = "high"
            return facts
        # Many installers place the actual application one directory below a
        # vendor folder (for example, Vendor\\Product Name\\app.exe). Treat
        # that common selection mistake as an application folder instead of
        # falling through to a generic source inventory.
        nested_executable_dirs = sorted({
            executable.parent.resolve()
            for executable in target.glob("*/*.exe")
            if executable.is_file()
        }, key=lambda item: str(item).casefold())
        if nested_executable_dirs:
            facts["type"] = "windows_application_folder"
            facts["confidence"] = "medium"
            facts["application_root_candidates"] = [
                str(item) for item in nested_executable_dirs[:20]
            ]
            facts["frameworks"].append("Windows application in nested folder")
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
        facts["type"] = "android_package" if ext in {".apk", ".aab", ".apkm", ".apks", ".xapk"} else "jvm_bytecode"
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
    if ext in SYSTEM_PACKAGE_TYPES or target.name.casefold().endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
        facts["type"] = "system_package"
        if ext in {".dmg", ".pkg"}:
            facts["frameworks"].append("macOS installer/container")
        elif ext in {".deb", ".rpm", ".appimage", ".flatpak", ".snap"}:
            facts["frameworks"].append("Linux package")
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
            if any(name.endswith("androidmanifest.xml") for name in names) and any(name.endswith(".dex") and (name.rsplit("/", 1)[-1] == "classes.dex" or (name.rsplit("/", 1)[-1].startswith("classes") and name.rsplit("/", 1)[-1][7:-4].isdigit())) for name in names):
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
    if ext in WASM_TYPES:
        facts["type"] = "wasm_binary" if ext == ".wasm" else "wasm_text"
        facts["frameworks"].append("WebAssembly")
        return facts
    if ext in PE_TYPES or ext in NATIVE_TYPES or not ext:
        with target.open("rb") as stream:
            head = stream.read(1_048_576)
            size = target.stat().st_size
            if size > 1_048_576:
                stream.seek(max(0, size - 4_194_304))
                tail = stream.read(4_194_304)
            else:
                tail = b""
        signature = head + b"\n" + tail
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
            if len(infos) > MAX_ARCHIVE_MEMBERS:
                raise ReverseEngineeringError(f"Archive has {len(infos)} entries, exceeding the safety limit.")
            for info in infos:
                if count >= max_members:
                    break
                if info.is_dir() or not predicate(info.filename):
                    continue
                normalized = info.filename.replace("\\", "/")
                parts = Path(normalized).parts
                if normalized.startswith("/") or ".." in parts:
                    continue
                if info.file_size > MAX_MEMBER_BYTES:
                    continue
                if total + info.file_size > max_total:
                    raise ReverseEngineeringError("Archive extraction size limit reached; choose a smaller artifact.")
                total += info.file_size
                count += 1
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


def _source_inventory(root, max_files=4000, report_path=None):
    import os

    base = Path(root).resolve()
    result, snippets = [], []
    ignore = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", ".venv", "venv", "obj", "bin"}
    code_suffixes = {".py", ".pyx", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".html", ".css", ".json", ".xml", ".java", ".kt", ".cs", ".cpp", ".c", ".h", ".hpp", ".go", ".rs", ".swift", ".dart", ".sql", ".ps1", ".bat", ".sh", ".toml", ".yaml", ".yml", ".plist"}
    count = 0
    for directory, dirnames, filenames in os.walk(base, followlinks=False):
        dirnames[:] = [
            name for name in dirnames
            if name.casefold() not in ignore and not (Path(directory) / name).is_symlink()
        ]
        for filename in filenames:
            path = Path(directory) / filename
            if path.suffix.casefold() not in code_suffixes or path.is_symlink():
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
                "main", "app", "route", "view", "screen", "controller", "service", "api", "manifest", "electron",
                "auth", "model", "database", "network", "storage",
            )):
                snippets.append({"path": relative, "content": text[:4000]})
        if count > max_files:
            break
    # By default keep backward compatibility for callers inventorying a generated
    # tree. Callers scanning a user's installation/source directory must pass an
    # explicit report_path under Mimic's output directory, never into the target.
    report_destination = (
        Path(report_path).expanduser().resolve()
        if report_path is not None
        else base / "mimic-source-inventory.json"
    )
    report_destination.parent.mkdir(parents=True, exist_ok=True)
    report_destination.write_text(
        json.dumps({"root": str(base), "file_count_scanned": count,
                    "files": result, "priority_source_samples": snippets}, indent=2),
        encoding="utf-8",
    )
    return {"file_count": len(result), "file_count_scanned": count, "files": result, "priority_source_samples": snippets,
            "report_path": str(report_destination)}


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


def _analyze_archive_native(archive_path, out_dir, ghidra_home, status, max_modules=8, max_decompile=1000):
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
                timeout=2400, max_decompile=max(40, min(250, max_decompile // max(1, min(max_modules, 8)))), per_function_timeout=8, on_status=status,
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


def _analyze_android(target, out_dir, ghidra_home, status, max_decompile=1000):
    output = Path(out_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    inventory = _archive_inventory(target)
    (output / "package-inventory.json").write_text(json.dumps(inventory, indent=2), encoding="utf-8")
    nested_summaries = []
    if Path(target).suffix.casefold() in {".apks", ".apkm", ".xapk"}:
        try:
            nested_apks = _safe_extract_members(target, output / "split-apks", lambda name: Path(name).suffix.casefold() == ".apk", max_members=12, max_total=MAX_TOTAL_EXTRACT_BYTES)
        except (ReverseEngineeringError, zipfile.BadZipFile, OSError) as exc:
            nested_summaries.append({"error": "Could not extract nested APKs: " + str(exc)[:300]})
            nested_apks = []
        for index, nested_apk in enumerate(nested_apks[:12]):
            status("Analyzing embedded Android APK " + str(index + 1) + "/" + str(len(nested_apks)))
            try:
                child = _analyze_android(
                    nested_apk,
                    output / "nested-apk" / (str(index).zfill(2) + "_" + Path(nested_apk).stem[:50]),
                    ghidra_home, status,
                    max_decompile=max(40, min(250, max_decompile // max(1, len(nested_apks)))),
                )
                nested_summaries.append({
                    "apk": str(nested_apk),
                    "package_files": child.get("package_files", [])[:400],
                    "tools": child.get("tools", {}),
                    "native_modules": child.get("native_modules", []),
                    "manifest": child.get("manifest"),
                    "warnings": child.get("warnings", []),
                })
            except (ReverseEngineeringError, GhidraError, OSError, ValueError, zipfile.BadZipFile) as exc:
                nested_summaries.append({"apk": str(nested_apk), "error": str(exc)[:300]})
    report: dict[str, Any] = {
        "type": "android_package",
        "target": str(target),
        "package_inventory": str(output / "package-inventory.json"),
        "package_files": inventory,
        "tools": {},
        "native_modules": [],
        "nested_apks": nested_summaries,
        "warnings": [],
    }
    report["tools"]["jadx"] = _run_jadx(target, output / "jadx-output", status=status)
    report["tools"]["apktool"] = _run_apktool(target, output / "apktool-output")
    if target.suffix.casefold() in {".apk", ".xapk", ".apkm"}:
        try:
            report["native_modules"] = _analyze_archive_native(target, output, ghidra_home, status, max_decompile=max_decompile)
        except (zipfile.BadZipFile, ReverseEngineeringError, OSError) as exc:
            report["warnings"].append("Could not extract native libraries: " + str(exc))
    elif target.suffix.casefold() in {".aab", ".aar"}:
        try:
            report["native_modules"] = _analyze_archive_native(target, output, ghidra_home, status, max_modules=4, max_decompile=max_decompile)
        except (zipfile.BadZipFile, ReverseEngineeringError, OSError) as exc:
            report["warnings"].append("Could not extract native libraries: " + str(exc))
    decoded = output / "apktool-output" / "AndroidManifest.xml"
    if decoded.is_file():
        report["manifest"] = _read_manifest_xml(decoded)
    return report


def _analyze_apple(target, out_dir, ghidra_home, status, max_decompile=1000):
    output = Path(out_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {"type": "apple_package", "target": str(target), "warnings": []}
    candidate = Path(target).expanduser().resolve()
    if candidate.is_file() and candidate.suffix.casefold() == ".ipa":
        bundle_dir = output / "ipa-extracted"

        def apple_member(name):
            normalized = name.replace("\\", "/")
            if not normalized.startswith("Payload/"):
                return False
            basename = normalized.rsplit("/", 1)[-1]
            suffix = Path(basename).suffix.casefold()
            if basename == "Info.plist" or basename == "PkgInfo":
                return True
            if suffix in {".dylib", ".plist", ".strings", ".storyboardc", ".nib", ".car", ".metallib"}:
                return True
            if "/Frameworks/" in normalized and "." not in basename and basename not in {"_CodeSignature"}:
                return True
            return False

        extracted = _safe_extract_members(candidate, bundle_dir, apple_member, max_total=MAX_TOTAL_EXTRACT_BYTES)
        plists = [Path(name) for name in extracted if Path(name).name == "Info.plist"]
        primary_binary = None
        if plists:
            import plistlib
            try:
                with plists[0].open("rb") as stream:
                    info = plistlib.load(stream)
                executable = info.get("CFBundleExecutable")
                report["bundle_identifier"] = info.get("CFBundleIdentifier")
                report["bundle_name"] = info.get("CFBundleName") or info.get("CFBundleDisplayName")
                relative_root = plists[0].relative_to(bundle_dir).parent
                relative_binary = relative_root / executable if executable else None
                if relative_binary:
                    primary_binary = bundle_dir / relative_binary
                    if not primary_binary.is_file():
                        name_inside_archive = str(relative_binary).replace("\\", "/")
                        items = _safe_extract_members(
                            candidate, bundle_dir, lambda name: name == name_inside_archive,
                            max_members=1, max_total=2_000_000_000,
                        )
                        if items:
                            primary_binary = Path(items[0])
                if primary_binary and primary_binary.is_file():
                    report["executable_path"] = str(primary_binary)
                    try:
                        report["native_analysis"] = analyze_binary(
                            str(primary_binary), str(output / "ghidra-native"),
                            ghidra_home=ghidra_home, max_decompile=max_decompile, on_status=status,
                        )
                    except GhidraError as exc:
                        report["warnings"].append("Ghidra could not analyze the main Mach-O executable: " + str(exc))
            except Exception as exc:
                report["warnings"].append("Could not fully analyze IPA bundle metadata: " + str(exc)[:400])
        native_binaries = [
            Path(name) for name in extracted
            if Path(name).is_file()
            and "/Frameworks/" in str(Path(name)).replace("\\", "/")
            and (Path(name).suffix.casefold() == ".dylib" or "." not in Path(name).name)
            and (primary_binary is None or Path(name).resolve() != primary_binary.resolve())
        ]
        native_reports = []
        if find_ghidra_home(ghidra_home):
            for index, binary in enumerate(native_binaries[:12]):
                try:
                    native_reports.append(analyze_binary(
                        str(binary), str(output / "ghidra-frameworks" / f"{index:02d}_{binary.stem[:50]}"),
                        ghidra_home=ghidra_home, max_decompile=max(40, min(200, max_decompile // max(1, min(len(native_binaries), 12)))), on_status=status,
                    ))
                except GhidraError as exc:
                    report["warnings"].append("Framework binary analysis failed for " + binary.name + ": " + str(exc)[:200])
        report["framework_binary_count"] = len(native_binaries)
        report["framework_analyses"] = [
            {"program_name": item.get("program_name"), "function_count": item.get("function_count"),
             "string_count": item.get("string_count"), "decompiled_function_count": item.get("decompiled_function_count")}
            for item in native_reports
        ]
        report["package_inventory"] = _archive_inventory(candidate)
        return report
    if candidate.is_dir():
        plist_paths = [
            candidate / "Contents" / "Info.plist",
            candidate / "Info.plist",
            candidate / "Resources" / "Info.plist",
        ]
        plist = next((path for path in plist_paths if path.is_file()), None)
        if plist:
            import plistlib
            try:
                info = plistlib.loads(plist.read_bytes())
                report["bundle_identifier"] = info.get("CFBundleIdentifier")
                report["bundle_name"] = info.get("CFBundleName") or info.get("CFBundleDisplayName")
                executable = info.get("CFBundleExecutable")
                executable_candidates = [
                    plist.parent / "MacOS" / executable,
                    plist.parent.parent / "MacOS" / executable,
                    candidate / executable,
                ] if executable else []
                binary = next((path for path in executable_candidates if path and path.is_file()), None)
                if binary:
                    report["executable_path"] = str(binary)
                    report["native_analysis"] = analyze_binary(
                        str(binary), str(output / "ghidra-native"), ghidra_home=ghidra_home,
                        max_decompile=250, on_status=status,
                    )
            except Exception as exc:
                report["warnings"].append("Bundle plist or binary analysis failed: " + str(exc)[:400])
        dylibs = [path for path in candidate.rglob("*") if path.is_file() and path.suffix.casefold() in {".dylib", ".so"}][:12]
        if dylibs and find_ghidra_home(ghidra_home):
            report["framework_analyses"] = []
            for index, binary in enumerate(dylibs):
                try:
                    result = analyze_binary(str(binary), str(output / "ghidra-frameworks" / f"{index:02d}_{binary.stem[:50]}"),
                                            ghidra_home=ghidra_home, max_decompile=max(40, min(150, max_decompile // max(1, min(len(dylibs), 12)))), on_status=status)
                    report["framework_analyses"].append({
                        "binary": str(binary), "function_count": result.get("function_count"),
                        "string_count": result.get("string_count"),
                    })
                except GhidraError as exc:
                    report["warnings"].append("Framework analysis failed for " + binary.name + ": " + str(exc)[:250])
        report["source_inventory"] = _source_inventory(
            candidate, max_files=10000, report_path=output / "mimic-source-inventory.json"
        )
        return report
    if candidate.is_file() and (candidate.suffix.casefold() in {".dylib", ".so"} or not candidate.suffix):
        report["native_analysis"] = analyze_binary(
            str(candidate), str(output / "ghidra-native"), ghidra_home=ghidra_home,
            max_decompile=250, on_status=status,
        )
    report["source_inventory"] = None
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
            report["source_inventory"] = _source_inventory(
                target, report_path=output / "mimic-source-inventory.json"
            )
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



def _analyze_wasm(target, out_dir):
    output = Path(out_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    path = Path(target).resolve()
    report = {"type": "webassembly", "target": str(path), "tools": {}, "warnings": []}
    if path.suffix.casefold() != ".wasm":
        text = path.read_text(encoding="utf-8", errors="replace")
        report["text_excerpt"] = text[:20000]
        report["line_count"] = text.count("\n") + 1
        return report
    candidates = [
        ("wasm-tools", ["wasm-tools", "print", str(path)], output / "wasm-tools-print.log"),
        ("wasm-objdump", ["wasm-objdump", "-x", "-d", str(path)], output / "wasm-objdump.log"),
    ]
    for name, command, log_path in candidates:
        executable = shutil.which(name) or shutil.which(name + ".exe")
        if not executable:
            report["tools"][name] = {"available": False, "status": "missing"}
            continue
        command[0] = executable
        report["tools"][name] = _run_tool(command, log_path, 1800)
    wasm2wat = shutil.which("wasm2wat") or shutil.which("wasm2wat.exe")
    if wasm2wat:
        wat_out = output / (path.stem + ".wat")
        report["tools"]["wasm2wat"] = _run_tool(
            [wasm2wat, str(path), "-o", str(wat_out)], output / "wasm2wat.log", 1800
        )
    decompiler = shutil.which("wasm-decompile") or shutil.which("wasm-decompile.exe")
    if decompiler:
        decompile_out = output / (path.stem + ".decompiled.txt")
        report["tools"]["wasm-decompile"] = _run_tool(
            [decompiler, str(path), "-o", str(decompile_out)], output / "wasm-decompile.log", 1800
        )
    completed = [name for name, item in report["tools"].items() if item.get("status") == "ok"]
    if not completed:
        report["warnings"].append(
            "No WebAssembly tool completed. Install wasm-tools, WABT (wasm2wat/wasm-objdump), or wasm-decompile locally and put it on PATH."
        )
    report["analysis_note"] = (
        "Static Wasm imports, exports, names and instructions are analyzed where tools are installed. "
        "Original high-level source cannot be recovered if source maps/debug info were not shipped."
    )
    return report


def _analyze_python(target, out_dir):
    output = Path(out_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    path = Path(target).resolve()
    report: dict[str, Any] = {"type": "python", "target": str(path), "tools": {}, "warnings": []}
    if path.is_dir() or path.suffix.casefold() in {".py", ".pyw"}:
        root = path if path.is_dir() else path.parent
        report["source_inventory"] = _source_inventory(
            root, max_files=12000, report_path=output / "mimic-source-inventory.json"
        )
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
    result = _source_inventory(
        root, max_files=15000, report_path=output / "mimic-source-inventory.json"
    )
    return {"type": "source_project", "target": str(path), "source_inventory": result}



def _analyze_source_archive(target, out_dir, ghidra_home, status, max_decompile=1000):
    output = Path(out_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    inventory = _archive_inventory(target)
    (output / "package-inventory.json").write_text(json.dumps(inventory, indent=2), encoding="utf-8")
    extracted = _safe_extract_members(
        target, output / "source-extracted",
        lambda name: Path(name).suffix.casefold() in {
            ".py", ".pyw", ".pyc", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
            ".html", ".css", ".json", ".xml", ".plist", ".java", ".kt", ".cs",
            ".cpp", ".c", ".h", ".hpp", ".go", ".rs", ".swift", ".dart", ".sql",
            ".ps1", ".bat", ".sh", ".php", ".rb", ".toml", ".yaml", ".yml", ".md",
            ".asar", ".exe", ".dll", ".so", ".dylib", ".jar", ".wasm",
        } or Path(name).name.casefold() in {
            "package.json", "appxmanifest.xml", "requirements.txt", "pyproject.toml",
            "cargo.toml", "go.mod", "pom.xml", "build.gradle", "build.gradle.kts",
        },
        max_members=MAX_ARCHIVE_MEMBERS,
        max_total=MAX_TOTAL_EXTRACT_BYTES,
    )
    root = output / "source-extracted"
    report = {
        "type": "source_archive",
        "target": str(target),
        "package_inventory": str(output / "package-inventory.json"),
        "extracted_file_count": len(extracted),
        "source_inventory": _source_inventory(root, max_files=15000),
        "warnings": [],
    }
    asar = next(root.rglob("app.asar"), None)
    if asar:
        report["electron"] = _analyze_electron(asar, output / "electron-analysis", status)
    binaries = [Path(name) for name in extracted if Path(name).suffix.casefold() in PE_TYPES]
    if binaries and find_ghidra_home(ghidra_home):
        reports = []
        for index, binary in enumerate(binaries[:8]):
            try:
                reports.append(analyze_application(
                    str(binary), str(output / "binary-analysis" / f"{index:02d}_{binary.stem[:60]}"),
                    ghidra_home=ghidra_home, max_modules=4, max_decompile=max(40, min(200, max_decompile // max(1, min(len(binaries), 8)))), on_status=status,
                ))
            except GhidraError as exc:
                report["warnings"].append(str(exc))
        report["binary_reports"] = reports
    if len(extracted) >= MAX_ARCHIVE_MEMBERS:
        report["warnings"].append("Extraction member limit reached. Some source files may not have been inspected.")
    return report





def _safe_extract_tar(archive_path, out_dir, *, max_members=20000, max_total=MAX_TOTAL_EXTRACT_BYTES):
    """Extract regular source/config/binary files; never extract links or special files."""
    destination = Path(out_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    extracted = []
    total = 0
    count = 0
    allowed = PACKAGE_MEMBER_SUFFIXES | {".txt", ".cfg", ".ini", ".properties"}
    with tarfile.open(archive_path, mode="r:*") as archive:
        for member in archive:
            if count >= max_members:
                break
            if not member.isfile() or member.issym() or member.islnk() or member.size < 0 or member.size > MAX_MEMBER_BYTES:
                continue
            name = member.name.replace("\\", "/")
            parts = Path(name).parts
            if not name or name.startswith("/") or ".." in parts or Path(name).is_absolute():
                continue
            if Path(name).suffix.casefold() not in allowed and Path(name).name.casefold() not in {
                "package.json", "pyproject.toml", "requirements.txt", "cargo.toml", "go.mod",
                "pom.xml", "build.gradle", "build.gradle.kts", "appxmanifest.xml",
            }:
                continue
            if total + member.size > max_total:
                break
            output = (destination / Path(*parts)).resolve()
            if destination not in output.parents:
                continue
            stream = archive.extractfile(member)
            if stream is None:
                continue
            output.parent.mkdir(parents=True, exist_ok=True)
            with stream, output.open("wb") as target:
                shutil.copyfileobj(stream, target)
            total += member.size
            count += 1
            extracted.append(str(output))
    return extracted


def _analyze_system_package(target, out_dir, ghidra_home, status, max_decompile=1000):
    output = Path(out_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    path = Path(target).resolve()
    suffix = path.suffix.casefold()
    report = {"type": "system_package", "target": str(path), "tools": {}, "warnings": []}
    extracted_root = output / "extracted"
    archive_name = path.name.casefold()

    if suffix in {".tar", ".tgz", ".tbz", ".txz"} or archive_name.endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
        try:
            files = _safe_extract_tar(path, extracted_root)
            report["extracted_file_count"] = len(files)
        except (tarfile.TarError, OSError, ReverseEngineeringError) as exc:
            report["warnings"].append("Safe source-file extraction from tar failed: " + str(exc)[:400])
            files = []
    else:
        command = None
        tool_name = None
        dpkg_deb = shutil.which("dpkg-deb") or shutil.which("dpkg-deb.exe")
        unsquashfs = shutil.which("unsquashfs") or shutil.which("unsquashfs.exe")
        pkgutil = shutil.which("pkgutil") or shutil.which("pkgutil.exe")
        xar = shutil.which("xar") or shutil.which("xar.exe")
        bsdtar = shutil.which("bsdtar") or shutil.which("bsdtar.exe")
        seven_zip = shutil.which("7z") or shutil.which("7z.exe") or shutil.which("7zz") or shutil.which("7zz.exe")

        if suffix == ".deb" and dpkg_deb:
            tool_name, command = "dpkg-deb", [dpkg_deb, "-x", str(path), str(extracted_root)]
        elif suffix == ".snap" and unsquashfs:
            tool_name, command = "unsquashfs", [unsquashfs, "-d", str(extracted_root), str(path)]
        elif suffix == ".pkg" and pkgutil and os.name == "darwin":
            tool_name, command = "pkgutil", ["--expand-full", str(path), str(extracted_root)]
        elif suffix == ".pkg" and xar:
            tool_name, command = "xar", [xar, "-xf", str(path), "-C", str(extracted_root)]
        elif bsdtar:
            tool_name, command = "bsdtar", [bsdtar, "-xf", str(path), "-C", str(extracted_root)]
        elif seven_zip:
            tool_name, command = "7-Zip", [seven_zip, "x", str(path), "-o" + str(extracted_root), "-y"]

        if command:
            extracted_root.mkdir(parents=True, exist_ok=True)
            status("Package extraction: using " + str(tool_name) + " without launching the target application…")
            report["tools"]["extractor"] = _run_tool(command, output / "extractor.log", 2400, cwd=str(output))
            if report["tools"]["extractor"].get("status") != "ok":
                report["warnings"].append("The selected package extractor failed; review extractor.log.")
        else:
            report["warnings"].append(
                "No compatible local package extractor was found. Install dpkg-deb for Debian packages, unsquashfs for Snap, pkgutil/xar for macOS PKG, or bsdtar/7-Zip for supported containers."
            )
        files = []
        if extracted_root.is_dir():
            files = [str(p) for p in extracted_root.rglob("*") if p.is_file() and not p.is_symlink()][:MAX_ARCHIVE_MEMBERS]
        report["extracted_file_count"] = len(files)

    if extracted_root.is_dir():
        report["source_inventory"] = _source_inventory(extracted_root, max_files=20000)
        binaries = [
            Path(name) for name in files
            if Path(name).suffix.casefold() in {".exe", ".dll", ".ocx", ".sys", ".so", ".dylib", ".elf", ".bin"}
        ][:24]
        report["payload_binaries_found"] = len(binaries)
        report["binary_reports"] = []
        if binaries and find_ghidra_home(ghidra_home):
            for index, binary in enumerate(binaries):
                try:
                    report["binary_reports"].append(analyze_binary(
                        str(binary), str(output / "binary-analysis" / (str(index).zfill(2) + "_" + binary.stem[:55])),
                        ghidra_home=ghidra_home,
                        max_decompile=max(40, min(300, max_decompile // max(1, min(len(binaries), 24)))),
                        on_status=status,
                    ))
                except GhidraError as exc:
                    report["warnings"].append("Native analysis failed for " + binary.name + ": " + str(exc)[:250])
        elif binaries:
            report["warnings"].append("Payload binaries were cataloged but Ghidra is not installed/configured.")
    return report


def _analyze_installer(target, out_dir, ghidra_home, status, max_decompile=1000):
    output = Path(out_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    target_path = Path(target).resolve()
    ext = target_path.suffix.casefold()
    report: dict[str, Any] = {"type": "windows_installer", "target": str(target_path), "tools": {}, "warnings": []}
    extractor = None
    command = None
    if ext in {".msi", ".msp", ".msm"}:
        lessmsi = shutil.which("lessmsi") or shutil.which("lessmsi.exe")
        if lessmsi:
            extractor = "lessmsi"
            command = [lessmsi, "x", str(target_path), str(output / "extracted")]
    elif ext == ".exe":
        inno = shutil.which("innoextract") or shutil.which("innoextract.exe")
        seven_zip = shutil.which("7z") or shutil.which("7z.exe") or shutil.which("7zz.exe")
        if inno:
            extractor = "innoextract"
            command = [inno, "-d", str(output / "extracted"), str(target_path)]
        elif seven_zip:
            extractor = "7-Zip"
            command = [seven_zip, "x", str(target_path), "-o" + str(output / "extracted"), "-y"]
    if command:
        status("Installer: statically extracting the package payload with " + extractor + "…")
        report["tools"]["extractor"] = _run_tool(command, output / "extractor.log", 2400, cwd=str(output))
    else:
        report["warnings"].append(
            "No suitable local installer extractor found. Install lessmsi for MSI files, innoextract for Inno Setup, or 7-Zip for supported installer payloads."
        )
    extracted_root = output / "extracted"
    if extracted_root.is_dir():
        report["source_inventory"] = _source_inventory(extracted_root, max_files=15000)
        binaries = [p for p in extracted_root.rglob("*") if p.is_file() and p.suffix.casefold() in PE_TYPES]
        reports = []
        for index, binary in enumerate(binaries[:12]):
            if not find_ghidra_home(ghidra_home):
                report["warnings"].append("Ghidra was not found; extracted binaries were cataloged but not decompiled.")
                break
            try:
                reports.append(analyze_application(
                    str(binary), str(output / "binary-analysis" / f"{index:02d}_{binary.stem[:55]}"),
                    ghidra_home=ghidra_home, max_modules=3, max_decompile=max(40, min(160, max_decompile // max(1, min(len(binaries), 12)))), on_status=status,
                ))
            except GhidraError as exc:
                report["warnings"].append(str(exc))
        report["binary_reports"] = reports
        report["payload_binaries_found"] = len(binaries)
    return report


def _analyze_windows_folder(target, out_dir, ghidra_home, status, max_decompile=1000):
    root = Path(target).resolve()
    output = Path(out_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = {
        "type": "windows_application_folder",
        "target": str(root),
        "source_inventory": _source_inventory(
            root, max_files=15000, report_path=output / "mimic-source-inventory.json"
        ),
        "warnings": [],
        "binary_reports": [],
    }
    executables = sorted(
        p for p in root.rglob("*.exe")
        if not any(part.casefold() in {"uninstall", "uninstaller", "crashreporter", "update"} for part in p.parts)
    )
    for index, binary in enumerate(executables[:10]):
        if not find_ghidra_home(ghidra_home):
            report["warnings"].append("Ghidra is not installed/configured; executable files are listed but not decompiled.")
            break
        try:
            report["binary_reports"].append(analyze_application(
                str(binary), str(output / "binaries" / f"{index:02d}_{binary.stem[:60]}"),
                ghidra_home=ghidra_home, max_modules=6, max_decompile=max(50, min(250, max_decompile // max(1, min(len(executables), 10)))), on_status=status,
            ))
        except GhidraError as exc:
            error_text = str(exc)
            report["warnings"].append(
                "Analysis of " + binary.name + " failed: " + error_text[:1800]
            )
            if "Ghidra exited with code 255" in error_text:
                report["warnings"].append(
                    "Stopped the folder batch after the first Ghidra exit code 255. "
                    "This is likely a shared launcher/runtime failure; inspect that binary's "
                    "ghidra-stdout.log, ghidra-stderr.log, ghidra-app.log, and ghidra-script.log "
                    "before retrying the other executables."
                )
                break
    report["executables_found"] = len(executables)
    return report





def _collect_tool_availability(value, result=None):
    if result is None:
        result = {}
    if isinstance(value, dict):
        tools = value.get("tools")
        if isinstance(tools, dict):
            for name, item in tools.items():
                if isinstance(item, dict):
                    status = item.get("status", "available" if item.get("available") else "unknown")
                    entry = {
                        "status": status,
                        "available": item.get("available"),
                    }
                    if item.get("note"):
                        entry["note"] = str(item["note"])[:400]
                    if item.get("exit_code") is not None:
                        entry["exit_code"] = item["exit_code"]
                    result[name] = entry
                else:
                    result[name] = {"status": "reported", "value": str(item)[:200]}
        if isinstance(value.get("extractor"), dict):
            extractor = value["extractor"]
            result["package_extractor"] = {
                "status": extractor.get("status", "unknown"),
                "available": extractor.get("available"),
                "exit_code": extractor.get("exit_code"),
            }
        if value.get("program_name") and "function_count" in value:
            result["ghidra"] = {"status": "ok", "available": True}
        for child in value.values():
            if isinstance(child, (dict, list)):
                _collect_tool_availability(child, result)
    elif isinstance(value, list):
        for child in value[:100]:
            if isinstance(child, (dict, list)):
                _collect_tool_availability(child, result)
    return result


def _collect_nested_warnings(value, result=None):
    """Collect warnings from nested analyzer reports without duplicating entries."""
    if result is None:
        result = []
    if isinstance(value, dict):
        warnings = value.get("warnings", [])
        if isinstance(warnings, list):
            for warning in warnings:
                if isinstance(warning, str) and warning.strip() and warning not in result:
                    result.append(warning)
        for key, child in value.items():
            if key != "warnings" and isinstance(child, (dict, list)):
                _collect_nested_warnings(child, result)
    elif isinstance(value, list):
        for child in value:
            if isinstance(child, (dict, list)):
                _collect_nested_warnings(child, result)
    return result


def reverse_engineer(target, out_dir, *, ghidra_home=None, max_decompile=1000, on_status=None):
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
                                                     ghidra_home=ghidra_home, max_decompile=max_decompile, on_status=status)
            # Detect and analyze Electron resources colocated with the executable.
            if _find_asar(target_path):
                report["analysis"]["electron"] = _analyze_electron(target_path, output / "electron-analysis", status)
        elif detection["type"] == "native_binary":
            report["analysis"] = {
                "native_analysis": analyze_binary(
                    str(target_path), str(output / "native-analysis"),
                    ghidra_home=ghidra_home, max_decompile=max_decompile, on_status=status,
                )
            }
        elif detection["type"] == "python_frozen":
            report["analysis"] = _analyze_python(target_path, output / "python-analysis")
            if find_ghidra_home(ghidra_home):
                try:
                    report["analysis"]["native_analysis"] = analyze_application(
                        str(target_path), str(output / "native-analysis"), ghidra_home=ghidra_home,
                        max_modules=8, max_decompile=max_decompile, on_status=status,
                    )
                except GhidraError as exc:
                    report["warnings"].append("Native container analysis failed: " + str(exc))
        elif detection["type"] == "android_package":
            report["analysis"] = _analyze_android(target_path, output / "android-analysis", ghidra_home, status, max_decompile=max_decompile)
        elif detection["type"] == "jvm_bytecode":
            report["analysis"] = _analyze_jvm(target_path, output / "jvm-analysis", status)
        elif detection["type"] == "apple_binary_or_package":
            report["analysis"] = _analyze_apple(target_path, output / "apple-analysis", ghidra_home, status, max_decompile=max_decompile)
        elif detection["type"] == "electron":
            report["analysis"] = _analyze_electron(target_path, output / "electron-analysis", status)
        elif detection["type"] in {"javascript_project", "python_project", "jvm_project", "dotnet_project", "directory"}:
            report["analysis"] = _analyze_source(target_path, output / "source-analysis")
            if detection["type"] == "dotnet_project" and shutil.which("dotnet"):
                report["analysis"]["dotnet_sdk"] = _run_tool(
                    [shutil.which("dotnet"), "--info"], output / "dotnet-info.log", 120
                )
        elif detection["type"] == "javascript_source":
            report["analysis"] = _analyze_source(target_path, output / "source-analysis")
        elif detection["type"] == "python":
            report["analysis"] = _analyze_python(target_path, output / "python-analysis")
        elif detection["type"] in {"wasm_binary", "wasm_text"}:
            report["analysis"] = _analyze_wasm(target_path, output / "wasm-analysis")
        elif detection["type"] == "windows_application_folder":
            report["analysis"] = _analyze_windows_folder(target_path, output / "folder-analysis", ghidra_home, status, max_decompile=max_decompile)
        elif detection["type"] == "source_archive":
            report["analysis"] = _analyze_source_archive(target_path, output / "archive-analysis", ghidra_home, status, max_decompile=max_decompile)
        elif detection["type"] == "windows_installer":
            report["analysis"] = _analyze_installer(target_path, output / "installer-analysis", ghidra_home, status, max_decompile=max_decompile)
        elif detection["type"] == "system_package":
            report["analysis"] = _analyze_system_package(target_path, output / "system-package-analysis", ghidra_home, status, max_decompile=max_decompile)
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
                        ghidra_home=ghidra_home, max_modules=4, max_decompile=max(40, min(180, max_decompile // max(1, min(len(binaries), 16)))), on_status=status,
                    ))
                except GhidraError as exc:
                    report["warnings"].append(str(exc))
        elif ext in {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".html", ".css"}:
            report["analysis"] = _analyze_source(target_path, output / "source-analysis")
        else:
            report["warnings"].append("No format-specific analyzer was selected. Try the application installation folder, package archive, or main executable.")
    except (GhidraError, ReverseEngineeringError, OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile, TypeError) as exc:
        report["warnings"].append(str(exc))
        report["analysis_error"] = str(exc)
    nested_warnings = _collect_nested_warnings(report.get("analysis", {}))
    for warning in nested_warnings:
        if warning not in report["warnings"]:
            report["warnings"].append(warning)
    report["analysis_elapsed_seconds"] = round(time.monotonic() - start, 2)
    report["tool_availability"] = _collect_tool_availability(report.get("analysis", {}))
    if ghidra_home or find_ghidra_home():
        report["tool_availability"].setdefault("ghidra", {"status": "installed", "available": True})
    analysis_result = report.get("analysis", {})
    if detection.get("type") == "windows_application_folder" and isinstance(analysis_result, dict):
        attempted = min(int(analysis_result.get("executables_found", 0) or 0), 10)
        successful = len(analysis_result.get("binary_reports", []))
        if attempted:
            status = "ok" if successful >= attempted else ("failed" if successful == 0 else "partial")
            report["tool_availability"]["ghidra"] = {
                "status": status,
                "available": bool(ghidra_home or find_ghidra_home()),
                "binaries_attempted": attempted,
                "binaries_analyzed": successful,
            }
    manifest_path = output / "mimic-analysis-manifest.json"
    manifest_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    report["manifest_path"] = str(manifest_path)
    return report



def _redact_analysis_text(text, limit=4000):
    text = str(text or "")
    text = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", text)
    text = re.sub(r"(?i)((?:access_?token|refresh_?token|password|passwd|secret|api.?key|authorization|cookie|client_secret)\s*[:=]\s*)[^\s,;]+", r"\1[REDACTED]", text)
    return text[:limit]


def _compact_inventory(value, source_limit=10):
    if not isinstance(value, dict):
        return value
    compact = {
        key: value.get(key)
        for key in ("file_count", "file_count_scanned", "report_path", "root")
        if key in value
    }
    files = value.get("files")
    if isinstance(files, list):
        priority_terms = ("main", "app", "entry", "route", "view", "screen", "controller", "service", "api", "auth", "model", "database", "store", "network")
        ranked = sorted(
            files,
            key=lambda item: (
                not any(term in str(item.get("path", "")).casefold() for term in priority_terms),
                len(item.get("classes", [])) + len(item.get("functions", [])),
            ),
            reverse=False,
        )
        compact["key_source_files"] = [
            {
                "path": item.get("path"),
                "size": item.get("size"),
                "line_count": item.get("line_count"),
                "classes": item.get("classes", [])[:20],
                "functions": item.get("functions", [])[:25],
            }
            for item in ranked[:60]
        ]
    samples = value.get("priority_source_samples")
    if isinstance(samples, list):
        compact["priority_source_samples"] = [
            {"path": sample.get("path"), "content": _redact_analysis_text(sample.get("content"), 2200)}
            for sample in samples[:source_limit]
        ]
    return compact


def _compact_analysis(manifest):
    detection = manifest.get("detection", {})
    analysis = manifest.get("analysis", {})
    compact: dict[str, Any] = {
        "target_name": Path(str(manifest.get("target", "unknown"))).name,
        "sha256": manifest.get("sha256"),
        "detection": {
            key: detection.get(key)
            for key in ("type", "extension", "frameworks", "confidence", "runtime_signatures")
            if key in detection
        },
        "warnings": manifest.get("warnings", [])[:30],
        "analysis_elapsed_seconds": manifest.get("analysis_elapsed_seconds"),
        "tool_availability": manifest.get("tool_availability", {}),
        "evidence": {},
    }

    def pull_ghidra(report, key_prefix=""):
        if not isinstance(report, dict):
            return None
        return {
            "module": report.get("program_name") or Path(str(report.get("analyzed_binary", ""))).name,
            "language": report.get("language"),
            "compiler": report.get("compiler"),
            "function_count": report.get("function_count"),
            "symbol_count": report.get("symbol_count"),
            "external_symbol_count": report.get("external_symbol_count"),
            "string_count": report.get("string_count"),
            "reference_count": report.get("reference_count"),
            "call_reference_count": report.get("call_reference_count"),
            "decompiled_function_count": report.get("decompiled_function_count"),
            "functions": [
                {"name": item.get("name"), "address": item.get("address"),
                 "parameter_count": item.get("parameter_count"), "size_bytes": item.get("size_bytes")}
                for item in report.get("functions", [])[:100]
            ],
            "symbols": [
                {"name": item.get("name"), "type": item.get("type"), "address": item.get("address")}
                for item in report.get("symbols", [])[:50]
            ],
            "strings": [
                {"value": _redact_analysis_text(item.get("value"), 220), "address": item.get("address")}
                for item in report.get("strings", [])[:80]
            ],
            "decompiled_functions": [
                {"name": item.get("name"), "address": item.get("address"),
                 "code": _redact_analysis_text(item.get("code"), 1300)}
                for item in report.get("decompiled_functions", [])[:8]
            ],
            "modules": report.get("modules", [])[:24],
            "dependency_warnings": report.get("dependency_warnings", [])[:20],
            "managed_decompilation": report.get("managed_decompilation", [])[:8],
        }

    if not isinstance(analysis, dict):
        analysis = {}
    for key in ("function_count", "symbol_count", "string_count", "call_reference_count",
                "total_function_count", "total_symbol_count", "total_string_count", "total_call_reference_count"):
        if key in analysis:
            compact["evidence"][key] = analysis[key]
    ghidra = pull_ghidra(analysis)
    if ghidra and any(value is not None for key, value in ghidra.items() if key not in {"functions", "symbols", "strings"}):
        compact["evidence"]["ghidra"] = ghidra
    if "native_analysis" in analysis:
        compact["evidence"]["native_analysis"] = pull_ghidra(analysis.get("native_analysis"))
    modules = analysis.get("modules")
    if isinstance(modules, list):
        compact["evidence"]["modules"] = modules[:30]
    for key in ("source_inventory", "resource_inventory"):
        if key in analysis:
            compact["evidence"][key] = _compact_inventory(analysis[key])
    for key in ("tools", "manifest", "package_json", "bundle_identifier", "bundle_name",
                "managed_decompilation", "ilspy_source_excerpt", "runtime_layout_markers", "payload_binaries_found", "executables_found",
                "extracted_file_count", "package_files", "native_modules", "binary_reports",
                "module_functions", "module_strings", "module_decompiled_functions"):
        if key in analysis:
            value = analysis[key]
            if key == "tools" and isinstance(value, dict):
                tool_summaries = {}
                for name, item in list(value.items())[:20]:
                    if not isinstance(item, dict):
                        tool_summaries[name] = item
                        continue
                    summary = {
                        k: v for k, v in item.items()
                        if k not in {"stdout_excerpt", "stderr_excerpt", "source_inventory", "resource_inventory"}
                        and k not in {"source_excerpt"}
                    }
                    if isinstance(item.get("source_inventory"), dict):
                        summary["source_inventory"] = _compact_inventory(item["source_inventory"], source_limit=6)
                    tool_summaries[name] = summary
                compact["evidence"][key] = tool_summaries
            elif key in {"package_files", "module_functions", "module_strings", "module_decompiled_functions"} and isinstance(value, list):
                compact["evidence"][key] = value[:70]
            elif key == "binary_reports" and isinstance(value, list):
                compact["evidence"][key] = [
                    {
                        "analyzed_binary": item.get("analyzed_binary"),
                        "total_function_count": item.get("total_function_count"),
                        "total_symbol_count": item.get("total_symbol_count"),
                        "total_string_count": item.get("total_string_count"),
                        "modules": item.get("modules", [])[:10],
                        "managed_decompilation": item.get("managed_decompilation", [])[:5],
                    } for item in value[:12] if isinstance(item, dict)
                ]
            elif key == "native_modules" and isinstance(value, list):
                compact["evidence"][key] = [
                    {
                        "program_name": item.get("program_name"),
                        "function_count": item.get("function_count"),
                        "symbol_count": item.get("symbol_count"),
                        "string_count": item.get("string_count"),
                        "decompiled_function_count": item.get("decompiled_function_count"),
                        "status": item.get("status"),
                        "error": item.get("error"),
                    } for item in value[:16] if isinstance(item, dict)
                ]
            else:
                text_value = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
                limit = 22000 if key == "ilspy_source_excerpt" else 8000
                compact["evidence"][key] = _redact_analysis_text(text_value, limit)
    # Preserve a bounded set of native-module code excerpts without passing all artifacts at once.
    decompiled = []
    if isinstance(analysis.get("module_decompiled_functions"), list):
        decompiled.extend(analysis["module_decompiled_functions"][:10])
    if ghidra:
        decompiled.extend(ghidra.get("decompiled_functions", [])[:8])
    if decompiled:
        compact["evidence"]["selected_decompilation"] = decompiled[:16]
    return compact


def summarize_analysis_manifest(manifest_path, model=None, base_url=None):
    """Use local Ollama to create an evidence-grounded report without loading full artifacts."""
    path = Path(manifest_path).expanduser().resolve()
    manifest = json.loads(path.read_text(encoding="utf-8"))
    compact = _compact_analysis(manifest)
    client = Ollama(base_url=base_url, model=model)
    available = client.models()
    if client.model not in available:
        raise OllamaError("Summary model is not installed: " + client.model + ". Run: ollama pull " + client.model)
    prompt = (
        "Analyze the supplied static-analysis and application-observation evidence. Produce a rigorous reverse-engineering report for software the user owns or is authorized to inspect. "
        "Do not claim full source recovery, do not confuse symbol names or strings with verified behavior, do not assert a vulnerability without evidence, and separate observed facts from hypotheses. "
        "Prefer concrete function names, UI frameworks, manifests, imports, storage clues, API/network libraries, and high-value next experiments. "
        "Return JSON only with these keys: executive_summary (string), application_type (string), architecture (array of {component, evidence, confidence}), "
        "entry_points (array of {name, evidence, confidence}), feature_map (array of {feature, evidence, confidence}), "
        "network_and_ipc (array of {finding, evidence, confidence}), storage_and_config (array of {finding, evidence, confidence}), "
        "security_observations (array of {finding, evidence, confidence}), high_value_functions (array of {name, reason, evidence}), "
        "analysis_gaps (array of strings), next_experiments (array of strings), confidence (low|medium|high). "
        "All claims must be tied to the supplied evidence. Keep arrays prioritized and do not pad them with generic guesses.\n\n"
        "Evidence:\n" + json.dumps(compact, ensure_ascii=False)[:52000]
    )
    raw = client.chat(
        [{"role": "system", "content": "You are a senior reverse engineer. Evidence-driven. Return well-formed JSON only."},
         {"role": "user", "content": prompt}],
        format="json", temperature=0.1, num_ctx=16384,
    )
    try:
        summary = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise OllamaError("Ollama did not return valid JSON for the analysis summary.") from exc
    if not isinstance(summary, dict) or not isinstance(summary.get("executive_summary"), str):
        raise OllamaError("Ollama analysis summary is missing its executive_summary.")
    output_dir = path.parent
    json_path = output_dir / "ollama-analysis-summary.json"
    json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    md = [
        "# Mimic Reverse-Engineering Report",
        "",
        "**Target:** " + str(compact.get("target_name")),
        "**Detected type:** " + str(compact.get("detection", {}).get("type")),
        "**Local model:** " + client.model,
        "**Confidence:** " + str(summary.get("confidence", "unspecified")),
        "",
        "## Executive summary",
        "",
        summary["executive_summary"],
    ]
    for key, heading, field, value_field in [
        ("architecture", "Architecture", "component", "evidence"),
        ("entry_points", "Entry points", "name", "evidence"),
        ("feature_map", "Observed or inferred feature map", "feature", "evidence"),
        ("network_and_ipc", "Networking and inter-process communication", "finding", "evidence"),
        ("storage_and_config", "Storage and configuration", "finding", "evidence"),
        ("security_observations", "Security observations", "finding", "evidence"),
        ("high_value_functions", "High-value functions", "name", "reason"),
    ]:
        values = summary.get(key, [])
        md.extend(["", "## " + heading, ""])
        if not values:
            md.append("No evidence-grounded findings were returned.")
        for item in values[:20] if isinstance(values, list) else []:
            if isinstance(item, dict):
                evidence_text = item.get(field, "")
                explanation = item.get(value_field, "")
                confidence = item.get("confidence", "")
                md.append("- **" + str(evidence_text) + "** — " + str(explanation) + ((" _(confidence: " + str(confidence) + ")_") if confidence else ""))
            else:
                md.append("- " + str(item))
    for key, heading in [("analysis_gaps", "Analysis gaps"), ("next_experiments", "Recommended next experiments")]:
        md.extend(["", "## " + heading, ""])
        values = summary.get(key, [])
        if isinstance(values, list) and values:
            md.extend("- " + str(item) for item in values[:30])
        else:
            md.append("None listed.")
    markdown_path = output_dir / "ollama-analysis-summary.md"
    markdown_path.write_text("\n".join(md).rstrip() + "\n", encoding="utf-8")
    return {"json": str(json_path), "markdown": str(markdown_path), "summary": summary}

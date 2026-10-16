import json
import zipfile
from pathlib import Path

import pytest

from mimic.analyzers import (
    ReverseEngineeringError,
    _compact_analysis,
    _collect_nested_warnings,
    _safe_extract_members,
    _safe_extract_tar,
    _source_inventory,
    _analyze_wasm,
    detect_runtime,
    reverse_engineer,
)
from mimic.runtime_trace import _redact_windows_user_path
from mimic.windows_reconstruct import read_runtime_events


def test_detect_runtime_recognizes_common_package_types(tmp_path):
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"not decoded by this classification test")
    assert detect_runtime(apk)["type"] == "android_package"

    jar = tmp_path / "app.jar"
    jar.write_bytes(b"")
    assert detect_runtime(jar)["type"] == "jvm_bytecode"

    pyc = tmp_path / "module.pyc"
    pyc.write_bytes(b"")
    assert detect_runtime(pyc)["type"] == "python"

    wasm = tmp_path / "module.wasm"
    wasm.write_bytes(b"\x00asm")
    assert detect_runtime(wasm)["type"] == "wasm_binary"

    package = tmp_path / "sample.deb"
    package.write_bytes(b"not extracted by this classification test")
    assert detect_runtime(package)["type"] == "system_package"

    archive = tmp_path / "source.tar.gz"
    archive.write_bytes(b"not extracted by this classification test")
    assert detect_runtime(archive)["type"] == "system_package"


def test_detect_runtime_recognizes_windows_application_folder_nested_one_level(tmp_path):
    vendor_root = tmp_path / "THINKCAR"
    app_root = vendor_root / "Product Updata Tool"
    app_root.mkdir(parents=True)
    (app_root / "ProductUpdataTool.exe").write_bytes(b"MZ")
    (app_root / "helper.dll").write_bytes(b"MZ")

    detection = detect_runtime(vendor_root)

    assert detection["type"] == "windows_application_folder"
    assert detection["confidence"] == "medium"
    assert str(app_root.resolve()) in detection["application_root_candidates"]


def test_detect_runtime_identifies_android_zip_from_members(tmp_path):
    package = tmp_path / "android-like.zip"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("AndroidManifest.xml", "<manifest />")
        archive.writestr("classes.dex", b"dex")
        archive.writestr("classes2.dex", b"dex")
    detection = detect_runtime(package)
    assert detection["type"] == "android_package"
    assert "Android/Dalvik" in detection["frameworks"]


def test_safe_archive_extractor_blocks_traversal_and_applies_member_limit(tmp_path):
    archive_path = tmp_path / "input.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../outside.txt", "unsafe")
        archive.writestr("assets/one.txt", "one")
        archive.writestr("assets/two.txt", "two")
    output = tmp_path / "extracted"
    files = _safe_extract_members(
        archive_path, output, lambda name: name.endswith(".txt"), max_members=1
    )
    assert len(files) == 1
    assert Path(files[0]).read_text(encoding="utf-8") in {"one", "two"}
    assert not (tmp_path / "outside.txt").exists()


def test_source_inventory_skips_build_dependency_directories(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "App.jsx").write_text("export function App() { return null; }", encoding="utf-8")
    (tmp_path / "node_modules" / "vendor").mkdir(parents=True)
    (tmp_path / "node_modules" / "vendor" / "malware.js").write_text("function ignored() {}", encoding="utf-8")
    report = _source_inventory(tmp_path, max_files=100)
    paths = {row["path"].replace("\\", "/") for row in report["files"]}
    assert any(path.endswith("App.jsx") for path in paths)
    assert not any("node_modules" in path for path in paths)


def test_wat_text_analysis_does_not_need_external_tools(tmp_path):
    path = tmp_path / "module.wat"
    path.write_text('(module (func (export "entry") (result i32) i32.const 7))', encoding="utf-8")
    report = _analyze_wasm(path, tmp_path / "wasm")
    assert report["type"] == "webassembly"
    assert "entry" in report["text_excerpt"]


def test_source_inventory_does_not_write_into_target_directory(tmp_path):
    target = tmp_path / "THINKCAR"
    target.mkdir()
    (target / "reset32.bat").write_text("@echo off\n", encoding="utf-8")
    output = tmp_path / "analysis"

    report = reverse_engineer(target, output)

    assert report["detection"]["type"] == "directory"
    assert not (target / "mimic-source-inventory.json").exists()
    inventory_path = Path(report["analysis"]["source_inventory"]["report_path"])
    assert inventory_path == (output / "source-analysis" / "mimic-source-inventory.json").resolve()
    assert inventory_path.is_file()


def test_reverse_engineer_source_file_writes_a_manifest(tmp_path):
    source = tmp_path / "main.js"
    source.write_text("export function start() { return true; }", encoding="utf-8")
    output = tmp_path / "analysis"
    report = reverse_engineer(source, output)
    assert report["detection"]["type"] == "javascript_source"
    manifest = json.loads((output / "mimic-analysis-manifest.json").read_text(encoding="utf-8"))
    assert manifest["target"] == str(source.resolve())
    assert report["manifest_path"]


def test_compact_analysis_keeps_evidence_bounded_and_removes_tool_output():
    manifest = {
        "target": "app.exe",
        "detection": {"type": "windows_binary", "frameworks": ["native"]},
        "analysis": {
            "tools": {"scanner": {"status": "ok", "stdout_excerpt": "X" * 20000, "source_inventory": {"files": []}}},
            "decompiled_functions": [{"name": "entry", "code": "return 1;"}],
            "function_count": 987,
        },
        "warnings": [],
    }
    compact = _compact_analysis(manifest)
    encoded = json.dumps(compact)
    assert len(encoded) < 50000
    assert "X" * 1000 not in encoded
    assert compact["evidence"]["function_count"] == 987


def test_runtime_user_path_redaction():
    value = r"C:\Users\Chris\AppData\Roaming\app.dat"
    assert r"\Users\Chris" not in _redact_windows_user_path(value)
    assert r"\Users\[USER]" in _redact_windows_user_path(value)


def test_runtime_events_are_filtered_and_username_redacted(tmp_path):
    capture = tmp_path / "capture"
    capture.mkdir()
    (capture / "runtime-events.jsonl").write_text(
        "\n".join([
            json.dumps({"type": "module_load", "name": "app.dll", "path": r"C:\Users\Chris\app.dll"}),
            json.dumps({"type": "irrelevant_event", "data": "not used"}),
        ]) + "\n",
        encoding="utf-8",
    )
    events = read_runtime_events(capture)
    assert len(events) == 1
    assert events[0]["type"] == "module_load"
    assert r"\Users\Chris" not in events[0]["path"]



def test_safe_tar_extraction_skips_traversal_links_and_non_source_data(tmp_path):
    import io
    import tarfile

    archive_path = tmp_path / "source.tar"
    with tarfile.open(archive_path, "w") as archive:
        source = b"def valid_source(): return True\n"
        info = tarfile.TarInfo("src/app.py")
        info.size = len(source)
        archive.addfile(info, io.BytesIO(source))
        unsafe = b"unsafe"
        info = tarfile.TarInfo("../outside.py")
        info.size = len(unsafe)
        archive.addfile(info, io.BytesIO(unsafe))
        ignored = b"binary blob"
        info = tarfile.TarInfo("data/opaque.blob")
        info.size = len(ignored)
        archive.addfile(info, io.BytesIO(ignored))
        link = tarfile.TarInfo("src/linked.py")
        link.type = tarfile.SYMTYPE
        link.linkname = "../outside.py"
        archive.addfile(link)

    output = tmp_path / "extracted"
    files = _safe_extract_tar(archive_path, output)
    assert len(files) == 1
    assert Path(files[0]).read_text(encoding="utf-8") == "def valid_source(): return True\n"
    assert not (tmp_path / "outside.py").exists()
    assert not (output / "src" / "linked.py").exists()


def test_runtime_trace_script_covers_winsock_destinations_without_payload_capture():
    from mimic.runtime_trace import FRIDA_SCRIPT

    assert "'getaddrinfo'" in FRIDA_SCRIPT
    assert "'GetAddrInfoW'" in FRIDA_SCRIPT
    assert "'connect'" in FRIDA_SCRIPT
    assert "network_destination" in FRIDA_SCRIPT
    assert "network_lookup" in FRIDA_SCRIPT
    # Runtime tracing must stay metadata-only: no socket payload or keystroke hooks.
    assert "sendto" not in FRIDA_SCRIPT
    assert "recvfrom" not in FRIDA_SCRIPT
    assert "GetAsyncKeyState" not in FRIDA_SCRIPT


def test_compact_analysis_preserves_managed_decompilation_evidence():
    manifest = {
        "target": "app.exe",
        "detection": {"type": "windows_binary"},
        "analysis": {
            "ilspy_source_excerpt": "public class App { public void Start() {} }",
            "runtime_layout_markers": ["hostfxr.dll"],
        },
        "warnings": [],
    }
    compact = _compact_analysis(manifest)
    assert "ilspy_source_excerpt" in compact["evidence"]
    assert "public class App" in compact["evidence"]["ilspy_source_excerpt"]
    assert "hostfxr.dll" in compact["evidence"]["runtime_layout_markers"]


def test_collect_nested_warnings_propagates_folder_binary_failures_without_duplicates():
    report = {
        "warnings": ["top-level warning"],
        "analysis": {
            "warnings": ["Ghidra failed on target.exe"],
            "binary_reports": [],
            "source_inventory": {"warnings": ["optional parser unavailable"]},
        },
    }
    collected = _collect_nested_warnings(report)
    assert collected == [
        "top-level warning",
        "Ghidra failed on target.exe",
        "optional parser unavailable",
    ]

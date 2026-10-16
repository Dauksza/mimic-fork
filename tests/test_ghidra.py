from pathlib import Path

from mimic.ghidra import _windows_batch_invocation, find_ghidra_home


def test_finds_ghidra_nested_inside_downloaded_archive_folder(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    install = (
        tmp_path
        / "Downloads"
        / "ghidra_12.1.4_PUBLIC_20260921"
        / "ghidra_12.1.4_PUBLIC"
    )
    support = install / "support"
    support.mkdir(parents=True)
    # Both names exist across Ghidra platform layouts; CI can exercise the path
    # discovery logic without actually launching Ghidra or requiring Java.
    (support / "analyzeHeadless").write_text("#!/bin/sh\n", encoding="utf-8")
    (support / "analyzeHeadless.bat").write_text("@echo off\r\n", encoding="utf-8")

    assert find_ghidra_home() == install.resolve()


def test_windows_batch_invocation_preserves_nested_quotes_and_paths_with_spaces():
    command = [
        r"C:\Ghidra 12.1.4\support\analyzeHeadless.bat",
        r"C:\Users\Chris\MimicProjects\Analyses\Product Updata Tool-analysis\project",
        "Product_Updata_Tool_Mimic",
        "-import",
        r"C:\Program Files (x86)\THINKCAR\Product Updata Tool\Product Updata Tool.exe",
        "-postScript",
        "MimicExport.java",
        r"C:\Users\Chris\MimicProjects\Analyses\Product Updata Tool-analysis\ghidra-analysis.json",
        "250",
        "8",
    ]
    invocation = _windows_batch_invocation(command, r"C:\Windows\System32\cmd.exe")

    # /s /c needs an outer quote pair around the full command string while
    # retaining the argument quotes that subprocess.list2cmdline generated.
    assert ' /d /s /c ""C:\\Ghidra 12.1.4\\support\\analyzeHeadless.bat"' in invocation
    assert '"C:\\Program Files (x86)\\THINKCAR\\Product Updata Tool\\Product Updata Tool.exe"' in invocation
    assert invocation.endswith(' 8"')

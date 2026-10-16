from pathlib import Path

from mimic.ghidra import _windows_batch_invocation, _write_windows_batch_wrapper, find_ghidra_home


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


def test_windows_batch_invocation_hides_parentheses_in_initial_cmd_line(tmp_path):
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
    wrapper_dir = tmp_path / "temp folder"
    wrapper_dir.mkdir()
    wrapper = _write_windows_batch_wrapper(command, wrapper_dir)
    try:
        invocation = _windows_batch_invocation([str(wrapper)], r"C:\Windows\System32\cmd.exe")
        wrapper_text = wrapper.read_text(encoding="utf-8")

        # The first cmd.exe command line contains only the wrapper path;
        # the troublesome Program Files (x86) argument stays inside the .cmd.
        assert "Program Files (x86)" not in invocation
        assert ' /d /c call "' in invocation
        assert "Program Files (x86)" in wrapper_text
        assert '"C:\\Program Files (x86)\\THINKCAR\\Product Updata Tool\\Product Updata Tool.exe"' in wrapper_text
        assert wrapper_text.startswith("@echo off\n")
        assert wrapper_text.endswith("exit /b %ERRORLEVEL%\n")
    finally:
        wrapper.unlink(missing_ok=True)

def test_analysis_timeout_is_configurable_and_bounded(monkeypatch):
    from mimic.ghidra import _analysis_timeout_seconds

    monkeypatch.setenv("MIMIC_GHIDRA_ANALYSIS_TIMEOUT", "21600")
    assert _analysis_timeout_seconds() == 21600
    assert _analysis_timeout_seconds("999999") == 86400
    assert _analysis_timeout_seconds("invalid") == 14400


def test_mimic_export_imports_data_from_ghidra_listing_package():
    script = (
        Path(__file__).resolve().parents[1]
        / "mimic"
        / "ghidra_scripts"
        / "MimicExport.java"
    ).read_text(encoding="utf-8")

    assert "import ghidra.program.model.listing.Data;" in script
    assert "import ghidra.program.model.data.Data;" not in script

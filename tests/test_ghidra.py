from pathlib import Path

from mimic.ghidra import find_ghidra_home


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

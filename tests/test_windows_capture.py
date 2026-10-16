import json
import sys
import types

import mimic.windows_capture as windows_capture
from mimic.windows_capture import count_capture_states


def test_count_capture_states_ignores_empty_and_invalid_events(tmp_path):
    events = tmp_path / "events.jsonl"
    rows = [
        {"sequence": 1, "windows": []},
        {"sequence": 2, "windows": [{"title": "Example", "controls": []}]},
    ]
    events.write_text(
        "not json\n"
        + "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )
    assert count_capture_states(tmp_path) == 1


def test_count_capture_states_returns_zero_for_empty_capture(tmp_path):
    (tmp_path / "events.jsonl").write_text("", encoding="utf-8")
    assert count_capture_states(tmp_path) == 0


def test_count_capture_states_returns_zero_when_file_is_missing(tmp_path):
    assert count_capture_states(tmp_path) == 0


def test_list_windows_uses_win32_fallback_when_uia_returns_no_rows(monkeypatch):
    class EmptyDesktop:
        def __init__(self, backend):
            assert backend == "uia"

        def windows(self, visible_only=True, enabled_only=False):
            assert visible_only is True
            return []

    fake_pywinauto = types.ModuleType("pywinauto")
    fake_pywinauto.Desktop = EmptyDesktop
    monkeypatch.setitem(sys.modules, "pywinauto", fake_pywinauto)
    monkeypatch.setattr(windows_capture, "require_windows_dependencies", lambda: None)
    fallback_row = {
        "hwnd": 1234,
        "pid": 5678,
        "executable_path": r"C:\Program Files\Example\example.exe",
        "title": "Example App",
        "class_name": "MainWindow",
        "rect": [10, 20, 900, 600],
        "enumeration_backend": "win32",
    }
    monkeypatch.setattr(
        windows_capture, "_list_windows_native",
        lambda exclude_pid=None: [fallback_row],
    )

    assert windows_capture.list_windows(exclude_pid=9999) == [fallback_row]


def test_list_windows_uses_win32_fallback_when_uia_throws(monkeypatch):
    class BrokenDesktop:
        def __init__(self, backend):
            pass

        def windows(self, **kwargs):
            raise RuntimeError("UIA provider did not respond")

    fake_pywinauto = types.ModuleType("pywinauto")
    fake_pywinauto.Desktop = BrokenDesktop
    monkeypatch.setitem(sys.modules, "pywinauto", fake_pywinauto)
    monkeypatch.setattr(windows_capture, "require_windows_dependencies", lambda: None)
    fallback_row = {
        "hwnd": 3456,
        "pid": 7890,
        "executable_path": None,
        "title": "Protected or elevated app",
        "class_name": "WinWindow",
        "rect": [0, 0, 1024, 768],
        "enumeration_backend": "win32",
    }
    monkeypatch.setattr(
        windows_capture, "_list_windows_native",
        lambda exclude_pid=None: [fallback_row],
    )

    assert windows_capture.list_windows() == [fallback_row]

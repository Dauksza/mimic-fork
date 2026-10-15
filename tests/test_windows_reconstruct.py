import json
import sys

import pytest

from mimic.windows_capture import _safe_text, require_windows_dependencies, WindowsCaptureError
from mimic.windows_reconstruct import parse_project, read_session
from mimic.ollama import OllamaError


def test_safe_text_redacts_bearer_and_secret_values():
    cleaned = _safe_text("Bearer abc.def token=secret123 hello")
    assert "abc.def" not in cleaned
    assert "secret123" not in cleaned


def test_windows_capture_dependency_guard_is_clear_on_non_windows():
    if sys.platform != "win32":
        with pytest.raises(WindowsCaptureError, match="only on Windows"):
            require_windows_dependencies()


def test_parse_project_requires_complete_pyside6_project():
    files = {
        "main.py": "from PySide6.QtWidgets import QApplication, QMainWindow\n",
        "requirements.txt": "PySide6>=6.6\n",
        "README.md": "# Generated desktop project\n",
    }
    assert parse_project(json.dumps({"files": files})) == files


def test_parse_project_rejects_invalid_python():
    files = {
        "main.py": "def broken(:\n",
        "requirements.txt": "PySide6>=6.6\n",
        "README.md": "# Desktop app",
    }
    with pytest.raises(OllamaError, match="syntax error"):
        parse_project(json.dumps({"files": files}))


def test_parse_project_rejects_missing_file():
    with pytest.raises(OllamaError, match="missing"):
        parse_project(json.dumps({"files": {"main.py": "pass"}}))


def test_read_session_samples_ui_states(tmp_path):
    (tmp_path / "session.json").write_text(json.dumps({
        "target_pid": 123,
        "target_title": "Calculator",
        "started_at": "2026-01-01T00:00:00+00:00",
    }), encoding="utf-8")
    states = [
        {"sequence": i, "timestamp": f"t{i}", "windows": [{
            "title": "Calculator",
            "controls": [{"type": "Button", "name": "Seven", "automation_id": "num7",
                          "rect": [0, 0, 20, 20], "enabled": True, "visible": True}],
        }]}
        for i in range(3)
    ]
    (tmp_path / "events.jsonl").write_text(
        "\n".join(json.dumps(row) for row in states) + "\n", encoding="utf-8"
    )
    root, metadata, sample, screenshots = read_session(tmp_path)
    assert root == tmp_path.resolve()
    assert metadata["target_title"] == "Calculator"
    assert len(sample) == 3
    assert sample[0]["windows"][0]["controls"][0]["name"] == "Seven"
    assert screenshots == []


def test_read_session_requires_capture_files(tmp_path):
    with pytest.raises(ValueError, match="session.json and events.jsonl"):
        read_session(tmp_path)

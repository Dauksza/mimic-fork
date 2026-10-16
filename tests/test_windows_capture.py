import json

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

"""Consent-driven Windows UI Automation capture for programs the user selects.

Only captures a selected process' visible windows. It does not install hooks,
record global keystrokes, inspect password fields, or collect clipboard content.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


class WindowsCaptureError(RuntimeError):
    pass


def require_windows_dependencies():
    if sys.platform != "win32":
        raise WindowsCaptureError("Windows desktop observation works only on Windows.")
    try:
        import pywinauto  # noqa: F401
        from PIL import Image  # noqa: F401
    except ImportError as exc:
        raise WindowsCaptureError(
            'Install Windows capture dependencies with: python -m pip install -e ".[windows]"'
        ) from exc


def _now():
    return datetime.now(timezone.utc).isoformat()


def _safe_text(value, limit=220):
    text = str(value or "").strip()
    text = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "[REDACTED]", text)
    text = re.sub(r"(?i)(password|passwd|token|secret|api.?key|authorization|cookie)(\s*[:=]\s*)\S+", r"\1=[REDACTED]", text)
    return text[:limit]




def count_capture_states(session_dir):
    """Count valid saved UI states; an empty events.jsonl is not a successful capture."""
    event_path = Path(session_dir) / "events.jsonl"
    if not event_path.is_file():
        return 0
    count = 0
    try:
        with event_path.open("r", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                windows = row.get("windows") if isinstance(row, dict) else None
                if isinstance(windows, list) and windows:
                    count += 1
    except OSError:
        return 0
    return count



_PROCESS_PATH_CACHE = {}


def _process_image_path(pid):
    """Return the Windows executable path for a PID when permissions allow."""
    if pid in _PROCESS_PATH_CACHE:
        return _PROCESS_PATH_CACHE[pid]
    if sys.platform != "win32":
        return None
    try:
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
        handle = kernel32.OpenProcess(0x1000, False, int(pid))
        if not handle:
            return None
        try:
            buffer = ctypes.create_unicode_buffer(32768)
            size = wintypes.DWORD(len(buffer))
            if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                _PROCESS_PATH_CACHE[pid] = buffer.value
                return buffer.value
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        return None
    return None


def _list_windows_native(exclude_pid=None):
    """Fallback to Win32 EnumWindows when UI Automation cannot expose any windows."""
    if sys.platform != "win32":
        return []
    import ctypes
    from ctypes import wintypes

    class RECT(ctypes.Structure):
        _fields_ = [
            ("left", wintypes.LONG),
            ("top", wintypes.LONG),
            ("right", wintypes.LONG),
            ("bottom", wintypes.LONG),
        ]

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.EnumWindows.restype = wintypes.BOOL
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.IsWindowVisible.restype = wintypes.BOOL
    user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    user32.GetWindowTextLengthW.restype = ctypes.c_int
    user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetWindowTextW.restype = ctypes.c_int
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(RECT)]
    user32.GetWindowRect.restype = wintypes.BOOL
    user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetClassNameW.restype = ctypes.c_int
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    found = []

    def visit(hwnd, _lparam):
        try:
            if not user32.IsWindowVisible(hwnd):
                return True
            title_length = user32.GetWindowTextLengthW(hwnd)
            if title_length <= 0:
                return True
            title_buffer = ctypes.create_unicode_buffer(min(title_length + 1, 2048))
            if user32.GetWindowTextW(hwnd, title_buffer, len(title_buffer)) <= 0:
                return True
            title = _safe_text(title_buffer.value, 180)
            if not title:
                return True

            pid_value = wintypes.DWORD(0)
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid_value))
            pid = int(pid_value.value)
            if pid <= 0 or (exclude_pid is not None and pid == int(exclude_pid)):
                return True

            rect = RECT()
            if not user32.GetWindowRect(hwnd, ctypes.byref(rect)):
                return True
            width = max(0, int(rect.right - rect.left))
            height = max(0, int(rect.bottom - rect.top))
            if width < 80 or height < 50:
                return True

            class_buffer = ctypes.create_unicode_buffer(512)
            user32.GetClassNameW(hwnd, class_buffer, len(class_buffer))
            try:
                handle_value = int(hwnd)
            except (TypeError, ValueError):
                handle_value = int(ctypes.cast(hwnd, ctypes.c_void_p).value or 0)
            found.append({
                "hwnd": handle_value,
                "pid": pid,
                "executable_path": _process_image_path(pid),
                "title": title,
                "class_name": _safe_text(class_buffer.value, 120),
                "rect": [int(rect.left), int(rect.top), width, height],
                "enumeration_backend": "win32",
            })
        except Exception:
            # One unusual or protected window must not prevent discovery of the rest.
            pass
        return True

    callback = callback_type(visit)
    if not user32.EnumWindows(callback, 0):
        error_code = ctypes.get_last_error()
        if error_code:
            raise OSError(error_code, "Win32 EnumWindows failed")
    unique = {(row["pid"], row["hwnd"]): row for row in found}
    return sorted(unique.values(), key=lambda row: (row["title"].casefold(), row["pid"], row["hwnd"]))


def list_windows(exclude_pid=None):
    """Return visible top-level windows using UI Automation with a Win32 fallback."""
    require_windows_dependencies()
    from pywinauto import Desktop

    found = []
    errors = []
    try:
        desktop = Desktop(backend="uia")
        wrappers = desktop.windows(visible_only=True, enabled_only=False)
        for wrapper in wrappers:
            try:
                hwnd = int(wrapper.handle)
                pid = int(wrapper.element_info.process_id or 0)
                title = _safe_text(wrapper.window_text(), 180)
                if not title or pid <= 0 or (exclude_pid is not None and pid == int(exclude_pid)):
                    continue
                rect = wrapper.rectangle()
                width, height = max(0, rect.width()), max(0, rect.height())
                if width < 80 or height < 50:
                    continue
                found.append({
                    "hwnd": hwnd,
                    "pid": pid,
                    "executable_path": _process_image_path(pid),
                    "title": title,
                    "class_name": _safe_text(wrapper.element_info.class_name, 120),
                    "rect": [rect.left, rect.top, width, height],
                    "enumeration_backend": "uia",
                })
            except Exception:
                continue
    except Exception as exc:
        errors.append("UI Automation: " + str(exc))

    unique = {(row["pid"], row["hwnd"]): row for row in found}
    if unique:
        return sorted(unique.values(), key=lambda row: (row["title"].casefold(), row["pid"], row["hwnd"]))

    try:
        native_rows = _list_windows_native(exclude_pid=exclude_pid)
    except Exception as exc:
        errors.append("Win32 window enumeration: " + str(exc))
        native_rows = []
    if native_rows:
        return native_rows
    if errors:
        raise WindowsCaptureError(
            "Could not enumerate visible app windows. "
            + " | ".join(errors)[:1200]
            + ". Try running Mimic at the same privilege level as the target app."
        )
    return []


def _element_snapshot(window, max_controls=450):
    controls = []
    try:
        descendants = window.descendants()
    except Exception:
        descendants = []
    for wrapper in descendants[:max_controls]:
        try:
            info = wrapper.element_info
            kind = _safe_text(getattr(info, "control_type", ""), 60)
            # Do not retrieve ValuePattern contents. Edit/document values are
            # intentionally omitted because they may contain private information.
            sensitive_or_dynamic = kind.casefold() in {
                "edit", "document", "password", "dataitem", "cell"
            }
            raw_name = getattr(info, "name", "")
            name = "[value omitted]" if sensitive_or_dynamic else _safe_text(raw_name, 160)
            rect = wrapper.rectangle()
            controls.append({
                "type": kind,
                "name": name,
                "automation_id": _safe_text(getattr(info, "automation_id", ""), 100),
                "class_name": _safe_text(getattr(info, "class_name", ""), 100),
                "enabled": bool(getattr(info, "enabled", False)),
                "visible": bool(getattr(info, "visible", False)),
                "rect": [rect.left, rect.top, max(0, rect.width()), max(0, rect.height())],
                "is_password": bool(getattr(info, "is_password", False)),
            })
        except Exception:
            continue
    return controls


def snapshot_process(pid, target_title=""):
    """Snapshot visible top-level windows and UIA element structure for one PID."""
    require_windows_dependencies()
    from pywinauto import Desktop

    windows = []
    desktop = Desktop(backend="uia")
    try:
        wrappers = desktop.windows(visible_only=True, enabled_only=False)
    except Exception as exc:
        raise WindowsCaptureError("Could not read UI Automation tree: " + str(exc)) from exc
    for wrapper in wrappers:
        try:
            if int(wrapper.element_info.process_id or 0) != int(pid):
                continue
            title = _safe_text(wrapper.window_text(), 180)
            if not title:
                continue
            rect = wrapper.rectangle()
            if rect.width() < 1 or rect.height() < 1:
                continue
            windows.append({
                "hwnd": int(wrapper.handle),
                "title": title,
                "class_name": _safe_text(wrapper.element_info.class_name, 120),
                "rect": [rect.left, rect.top, rect.width(), rect.height()],
                "controls": _element_snapshot(wrapper),
            })
        except Exception:
            continue
    return {
        "timestamp": _now(),
        "target_pid": int(pid),
        "target_title": _safe_text(target_title, 180),
        "windows": windows,
    }


def _screenshot_bytes(pid):
    from pywinauto import Desktop
    from PIL import Image

    desktop = Desktop(backend="uia")
    candidates = []
    foreground_handle = None
    foreground_pid = None
    try:
        import ctypes
        from ctypes import wintypes
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.GetForegroundWindow.restype = wintypes.HWND
        user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        user32.GetWindowThreadProcessId.restype = wintypes.DWORD
        foreground_handle = int(user32.GetForegroundWindow() or 0)
        foreground_pid_value = wintypes.DWORD(0)
        if foreground_handle:
            user32.GetWindowThreadProcessId(wintypes.HWND(foreground_handle), ctypes.byref(foreground_pid_value))
            foreground_pid = int(foreground_pid_value.value)
    except Exception:
        foreground_handle = foreground_pid = None

    for wrapper in desktop.windows(visible_only=True, enabled_only=False):
        try:
            if int(wrapper.element_info.process_id or 0) == int(pid):
                rect = wrapper.rectangle()
                if rect.width() >= 80 and rect.height() >= 50:
                    is_foreground = foreground_pid == int(pid) and int(wrapper.handle) == foreground_handle
                    candidates.append((is_foreground, rect.width() * rect.height(), wrapper))
        except Exception:
            continue
    if not candidates:
        return None
    # Prefer an active modal dialog/child window when possible, otherwise the largest top-level app window.
    wrapper = sorted(candidates, key=lambda item: (item[0], item[1]), reverse=True)[0][2]
    try:
        image = wrapper.capture_as_image()
    except Exception:
        # UIA's capture can fail for custom-rendered windows. Fall back to a
        # screen-region capture while the user keeps the target visible.
        try:
            from PIL import ImageGrab
            rect = wrapper.rectangle()
            image = ImageGrab.grab(
                bbox=(rect.left, rect.top, rect.right, rect.bottom),
                all_screens=True,
            )
        except Exception:
            return None
    if not isinstance(image, Image.Image):
        return None
    output = io.BytesIO()
    image.convert("RGB").save(output, format="JPEG", quality=78, optimize=True)
    return output.getvalue()


class CaptureSession:
    def __init__(self, pid, title, out_dir, poll_interval=1.0, on_status=None, executable_path=None):
        self.pid = int(pid)
        self.title = _safe_text(title, 180)
        self.executable_path = executable_path or _process_image_path(self.pid)
        self.out_dir = Path(out_dir).expanduser().resolve()
        self.poll_interval = max(0.5, float(poll_interval))
        self.on_status = on_status or (lambda message: None)
        self.stop_event = __import__("threading").Event()
        self._thread = None
        self._last_signature = None
        self._last_image_hash = None
        self._last_image_time = 0.0
        self._image_count = 0
        self._sequence = 0

    def start(self):
        require_windows_dependencies()
        if self.out_dir.exists() and any(self.out_dir.iterdir()):
            raise WindowsCaptureError("Capture output folder must be new or empty: " + str(self.out_dir))
        self.out_dir.mkdir(parents=True, exist_ok=True)
        (self.out_dir / "screenshots").mkdir(exist_ok=True)
        metadata = {
            "schema_version": 1,
            "platform": "windows",
            "capture_mode": "visible window UI Automation and screenshots",
            "target_pid": self.pid,
            "target_title": self.title,
            "executable_path": self.executable_path,
            "started_at": _now(),
            "ended_at": None,
            "notes": [
                "Only the selected process is observed.",
                "Password and editable field values are omitted.",
                "No global keyboard or clipboard recording is performed.",
                "Screenshots may contain visible private information; keep this folder private."
            ],
        }
        (self.out_dir / "session.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        self._thread = __import__("threading").Thread(target=self._run, name="mimic-windows-capture", daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self.stop_event.set()
        if self._thread and self._thread is not __import__("threading").current_thread():
            self._thread.join(timeout=8)
        metadata_path = self.out_dir / "session.json"
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["ended_at"] = _now()
            metadata["event_count"] = self._sequence
            metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        except (OSError, ValueError):
            pass
        self.on_status("Capture stopped. Session saved to " + str(self.out_dir))

    def _run(self):
        event_path = self.out_dir / "events.jsonl"
        screenshots_dir = self.out_dir / "screenshots"
        with event_path.open("a", encoding="utf-8") as events:
            poll_count = 0
            last_warning = None
            while not self.stop_event.is_set():
                try:
                    snapshot = snapshot_process(self.pid, self.title)
                    poll_count += 1
                    if not snapshot.get("windows"):
                        if poll_count == 1 or poll_count % 5 == 0:
                            self.on_status(
                                "No accessible visible UI windows for "
                                + self.title
                                + ". Keep the app unminimized and run Mimic at the same privilege level."
                            )
                        last_warning = None
                        self.stop_event.wait(self.poll_interval)
                        continue
                    last_warning = None
                    snapshot["sequence"] = self._sequence + 1
                    signature_data = {k: v for k, v in snapshot.items() if k not in {"timestamp", "sequence"}}
                    serialized = json.dumps(signature_data, ensure_ascii=False, sort_keys=True)
                    signature = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
                    image_data = _screenshot_bytes(self.pid)
                    image_hash = hashlib.sha256(image_data).hexdigest() if image_data else None
                    tree_changed = signature != self._last_signature
                    image_changed = image_hash is not None and image_hash != self._last_image_hash
                    now_monotonic = time.monotonic()
                    visual_due = (
                        image_changed and self._image_count < 240
                        and now_monotonic - self._last_image_time >= 2.0
                    )
                    if tree_changed or visual_due:
                        self._sequence += 1
                        snapshot["sequence"] = self._sequence
                        capture_screen = bool(image_data and self._image_count < 240 and image_changed)
                        if capture_screen:
                            self._last_image_hash = image_hash
                            self._image_count += 1
                            self._last_image_time = now_monotonic
                            file_name = f"screen_{self._image_count:05d}.jpg"
                            (screenshots_dir / file_name).write_bytes(image_data)
                            snapshot["screenshot"] = "screenshots/" + file_name
                        else:
                            snapshot["screenshot"] = None
                        snapshot["change"] = "ui_tree" if tree_changed else "visual"
                        events.write(json.dumps(snapshot, ensure_ascii=False) + "\n")
                        events.flush()
                        self._last_signature = signature
                        if self._sequence == 1 or self._sequence % 5 == 0:
                            self.on_status(f"Capturing {self.title}: {self._sequence} distinct states observed")
                except Exception as exc:
                    warning = _safe_text(exc, 240)
                    if warning != last_warning:
                        self.on_status("Capture warning: " + warning)
                        last_warning = warning
                self.stop_event.wait(self.poll_interval)


def start_armed_capture(out_dir, on_target, on_status=None, poll_interval=0.75):
    """Wait for a newly opened visible app window, then invoke on_target(window).

    This is deliberately started by the user through the Mimic GUI. It watches
    visible top-level windows only and does not read keystrokes or clipboard.
    """
    require_windows_dependencies()
    import threading

    status = on_status or (lambda message: None)
    own_pid = os.getpid()
    baseline = {row["hwnd"]: row["title"] for row in list_windows(exclude_pid=own_pid)}
    stopped = threading.Event()

    def watch():
        status("Armed. Open the Windows program you want to reconstruct.")
        while not stopped.wait(poll_interval):
            try:
                current = list_windows(exclude_pid=own_pid)
                new_windows = [row for row in current if row["hwnd"] not in baseline or baseline.get(row["hwnd"]) != row["title"]]
                # Ignore shells and known OS surface windows by choosing the
                # first app window with a title and useful dimensions.
                if new_windows:
                    target = max(new_windows, key=lambda row: row["rect"][2] * row["rect"][3])
                    status("Detected target: " + target["title"])
                    on_target(target)
                    return
            except Exception as exc:
                status("Window discovery warning: " + _safe_text(exc, 240))

    thread = threading.Thread(target=watch, name="mimic-window-discovery", daemon=True)
    thread.start()
    return stopped, thread

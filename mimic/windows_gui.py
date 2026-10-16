"""Tkinter UI for Windows capture, Ghidra analysis, and local reconstruction."""
from __future__ import annotations

import json
import os
import queue
import sys
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, ttk

from .ghidra import find_ghidra_home
from .analyzers import reverse_engineer, summarize_analysis_manifest
from .runtime_trace import RuntimeTrace, RuntimeTraceError
from .windows_capture import (
    CaptureSession,
    WindowsCaptureError,
    require_windows_dependencies,
    start_armed_capture,
    list_windows,
    count_capture_states,
)


class MimicWindowsApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MIMIC | Windows Reverse Engineering")
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        initial_width = min(1160, max(850, screen_width - 80))
        initial_height = min(940, max(640, screen_height - 80))
        self.root.geometry(f"{initial_width}x{initial_height}")
        self.root.minsize(min(950, initial_width), min(680, initial_height))
        self.root.configure(bg="#0b1220")
        self.capture = None
        self.runtime_trace = None
        self.runtime_trace_var = tk.BooleanVar(value=False)
        self.discovery = None
        self.discovery_stopped = None
        self.capture_dir = None
        self.capture_setup_cancelled = False
        self.capture_attempt_id = 0
        self.capture_picker = None
        self.capture_target_rows = []
        self.busy = False
        self.model_var = tk.StringVar(value=os.environ.get("MIMIC_OLLAMA_MODEL", "qwen2.5-coder:14b"))
        self.ollama_url_var = tk.StringVar(value=os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434"))
        self.model_combos = []
        self.max_decompile_var = tk.StringVar(value=os.environ.get("MIMIC_GHIDRA_MAX_DECOMPILE", "1000"))
        self.output_var = tk.StringVar(value=str(Path.home() / "MimicProjects" / "Reconstructions" / "desktop-clone"))
        self.ghidra_var = tk.StringVar(value=str(find_ghidra_home() or os.environ.get("GHIDRA_HOME", "")))
        self.binary_var = tk.StringVar(value="")
        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._close)
        self._log("Ready. Arm capture, then open the Windows application to observe.")
        detected_ghidra = find_ghidra_home()
        if detected_ghidra:
            self._log("Ghidra ready: " + str(detected_ghidra))
        else:
            self._log("Ghidra not detected yet. Use Find Ghidra after checking the installation folder.")

    def _build_ui(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TButton", font=("Segoe UI", 10), padding=(11, 7))
        style.configure("TLabel", background="#0b1220", foreground="#d8e1f0", font=("Segoe UI", 10))
        style.configure("TEntry", fieldbackground="#111b2e", foreground="#edf3ff", padding=7)
        style.configure("TCombobox", fieldbackground="#111b2e", foreground="#edf3ff", padding=6)
        style.configure("TNotebook", background="#0b1220", borderwidth=0)
        style.configure("TNotebook.Tab", padding=(18, 10), font=("Segoe UI", 10, "bold"))
        style.configure("Horizontal.TProgressbar", troughcolor="#111b2e", background="#75e0d0")

        header = tk.Frame(self.root, bg="#101b2d", padx=25, pady=15)
        header.pack(fill="x")
        tk.Label(header, text="MIMIC", fg="#75e0d0", bg="#101b2d",
                 font=("Segoe UI", 22, "bold")).pack(anchor="w")
        tk.Label(header, text="LOCAL APP ANALYSIS  /  GHIDRA  /  OLLAMA",
                 fg="#c5d1e5", bg="#101b2d", font=("Segoe UI", 10)).pack(anchor="w", pady=(2, 0))

        workspace = tk.Frame(self.root, bg="#0b1220", padx=18, pady=12)
        workspace.pack(fill="both", expand=True)
        self.notebook = ttk.Notebook(workspace)
        self.notebook.pack(fill="both", expand=True)

        self.capture_page, capture_tab = self._create_scrollable_page()
        self.analysis_page, analysis_tab = self._create_scrollable_page()
        self.notebook.add(capture_tab, text="Capture & Rebuild")
        self.notebook.add(analysis_tab, text="Analyze Any App")

        # Capture & rebuild page
        page = self.capture_page
        tk.Label(page, text="Observe a program, then rebuild its visible interface",
                 bg="#0b1220", fg="#f0f5ff", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        tk.Label(
            page,
            text="Arm capture first, open the target Windows program, and use its normal screens and workflows. Stop capture to save evidence, then generate a separate PySide6 reconstruction.",
            justify="left", wraplength=1040, fg="#a9bad3", bg="#0b1220",
            font=("Segoe UI", 10), pady=7,
        ).pack(anchor="w")

        self.runtime_trace_check = tk.Checkbutton(
            page,
            text="Advanced runtime trace via Frida (module loads, file/registry paths and connection destinations; no payloads)",
            variable=self.runtime_trace_var,
            bg="#0b1220", fg="#c5d1e5", selectcolor="#132238",
            activebackground="#0b1220", activeforeground="#75e0d0",
            font=("Segoe UI", 9), anchor="w",
        )
        self.runtime_trace_check.pack(anchor="w", pady=(2, 8))

        capture_buttons = tk.Frame(page, bg="#0b1220")
        capture_buttons.pack(fill="x", pady=(2, 12))
        self.arm_button = ttk.Button(capture_buttons, text="ARM CAPTURE", command=self._arm)
        self.arm_button.pack(side="left")
        self.stop_button = ttk.Button(capture_buttons, text="STOP CAPTURE", command=self._stop, state="disabled")
        self.stop_button.pack(side="left", padx=(8, 0))
        self.build_button = ttk.Button(capture_buttons, text="GENERATE DESKTOP COPY", command=self._build, state="disabled")
        self.build_button.pack(side="left", padx=(8, 0))

        self._field(page, "Detected target executable (EXE / DLL)", self.binary_var, 0, self._browse_binary, "Browse EXE")
        self._field(page, "Ghidra installation folder", self.ghidra_var, 1, self._detect_ghidra, "Find Ghidra")
        self._model_field(page, row=2, include_url=True)
        self._field(page, "Maximum functions to decompile (0–50000)", self.max_decompile_var, 3)
        self._field(page, "Output reconstruction folder", self.output_var, 4, self._browse_reconstruction_output, "Browse")
        tk.Label(
            page,
            text="The generated app is a reconstruction from observed UI and static-analysis evidence—not the original source code. Backend-only behavior may need authorized API evidence.",
            justify="left", wraplength=1040, fg="#8399b5", bg="#0b1220",
            font=("Segoe UI", 9), pady=10,
        ).pack(anchor="w")

        # Standalone reverse-engineering page
        page = self.analysis_page
        tk.Label(page, text="Reverse engineer a binary, installed app, package, or source project",
                 bg="#0b1220", fg="#f0f5ff", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        tk.Label(
            page,
            text="Choose a file or folder. Mimic detects the likely format and runs the available local analyzers. It does not launch the target application or send analysis data to a cloud AI service.",
            justify="left", wraplength=1040, fg="#a9bad3", bg="#0b1220",
            font=("Segoe UI", 10), pady=7,
        ).pack(anchor="w")

        self.analysis_target_var = tk.StringVar(value="")
        self.analysis_output_var = tk.StringVar(value=str(Path.home() / "MimicProjects" / "Analyses" / "new-analysis"))
        self.analysis_summary_var = tk.BooleanVar(value=True)
        self._field(
            page, "Target file or application folder", self.analysis_target_var, 0,
            self._browse_analysis_file, "Browse File", extra_button=(self._browse_analysis_folder, "Browse Folder"),
        )
        self._field(
            page, "Analysis results folder", self.analysis_output_var, 1,
            self._browse_analysis_output, "Browse Output",
        )
        self._field(
            page, "Ghidra installation folder (optional for non-native targets)", self.ghidra_var, 2,
            self._detect_ghidra, "Find Ghidra",
        )
        self._model_field(page, row=3, include_url=True)
        self._field(page, "Maximum functions to decompile (0–50000)", self.max_decompile_var, 4)
        tk.Checkbutton(
            page,
            text="Generate an evidence-based findings report with local Ollama after static analysis",
            variable=self.analysis_summary_var,
            bg="#0b1220", fg="#c5d1e5", selectcolor="#132238",
            activebackground="#0b1220", activeforeground="#75e0d0",
            font=("Segoe UI", 9), anchor="w",
        ).pack(anchor="w", pady=(10, 7))

        analysis_buttons = tk.Frame(page, bg="#0b1220")
        analysis_buttons.pack(fill="x", pady=(5, 8))
        self.analyze_button = ttk.Button(analysis_buttons, text="START ANALYSIS", command=self._start_analysis)
        self.analyze_button.pack(side="left")
        self.open_analysis_button = ttk.Button(analysis_buttons, text="OPEN RESULTS FOLDER", command=self._open_analysis_output)
        self.open_analysis_button.pack(side="left", padx=(8, 0))
        self.analysis_progress = ttk.Progressbar(page, mode="indeterminate", style="Horizontal.TProgressbar")
        self.analysis_progress.pack(fill="x", pady=(7, 4))
        self.analysis_progress.stop()

        # Shared activity feed remains visible whichever workflow tab is selected.
        status_bar = tk.Frame(self.root, bg="#132238", padx=18, pady=8)
        status_bar.pack(fill="x", padx=18, pady=(0, 6))
        self.status_var = tk.StringVar(value="Ready")
        tk.Label(
            status_bar, textvariable=self.status_var, fg="#75e0d0", bg="#132238",
            font=("Segoe UI", 10, "bold"), wraplength=1080, justify="left",
        ).pack(anchor="w")

        log_frame = tk.Frame(self.root, bg="#0b1220", padx=18)
        log_frame.pack(fill="both", pady=(0, 8))
        log_header = tk.Frame(log_frame, bg="#0b1220")
        log_header.pack(fill="x")
        tk.Label(log_header, text="ACTIVITY", fg="#c5d1e5", bg="#0b1220",
                 font=("Segoe UI", 9, "bold")).pack(side="left")
        ttk.Button(log_header, text="Clear Log", command=self._clear_log).pack(side="right")
        self.activity = tk.Text(
            log_frame, height=7, bg="#080e18", fg="#c6d4e7", insertbackground="#ffffff",
            relief="flat", padx=10, pady=7, font=("Consolas", 9), wrap="word",
        )
        self.activity.pack(fill="both", expand=True, pady=(4, 0))
        self.activity.configure(state="disabled")

        tk.Label(
            self.root,
            text="Ollama runs locally • Tool availability is reported honestly • Only analyze software you own or are authorized to inspect",
            fg="#7f91aa", bg="#0b1220", font=("Segoe UI", 9), pady=6,
        ).pack(fill="x")

    def _create_scrollable_page(self):
        """Create a notebook tab whose contents remain reachable on shorter screens."""
        container = tk.Frame(self.notebook, bg="#0b1220")
        canvas = tk.Canvas(container, bg="#0b1220", highlightthickness=0, borderwidth=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        content = tk.Frame(canvas, bg="#0b1220", padx=20, pady=16)
        window_id = canvas.create_window((0, 0), window=content, anchor="nw")
        content.bind(
            "<Configure>",
            lambda _event: canvas.configure(scrollregion=canvas.bbox("all")),
        )
        canvas.bind(
            "<Configure>",
            lambda event: canvas.itemconfigure(window_id, width=event.width),
        )

        def scroll(event):
            number = getattr(event, "num", None)
            if number == 4:
                canvas.yview_scroll(-1, "units")
            elif number == 5:
                canvas.yview_scroll(1, "units")
            else:
                delta = getattr(event, "delta", 0)
                if delta:
                    units = int(-delta / 120)
                    canvas.yview_scroll(units if units else (-1 if delta > 0 else 1), "units")

        def enable_mousewheel(_event):
            canvas.bind_all("<MouseWheel>", scroll)
            canvas.bind_all("<Button-4>", scroll)
            canvas.bind_all("<Button-5>", scroll)

        def disable_mousewheel(_event):
            canvas.unbind_all("<MouseWheel>")
            canvas.unbind_all("<Button-4>")
            canvas.unbind_all("<Button-5>")

        canvas.bind("<Enter>", enable_mousewheel)
        canvas.bind("<Leave>", disable_mousewheel)
        return content, container

    def _field(self, parent, label_text, variable, row, browse_callback=None, browse_label="Browse", extra_button=None):
        wrap = tk.Frame(parent, bg="#0b1220")
        wrap.pack(fill="x", pady=(4, 5))
        tk.Label(wrap, text=label_text, fg="#d8e1f0", bg="#0b1220",
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        line = tk.Frame(wrap, bg="#0b1220")
        line.pack(fill="x", pady=(3, 0))
        ttk.Entry(line, textvariable=variable).pack(side="left", fill="x", expand=True)
        if browse_callback:
            ttk.Button(line, text=browse_label, command=browse_callback).pack(side="left", padx=(7, 0))
        if extra_button:
            callback, text = extra_button
            ttk.Button(line, text=text, command=callback).pack(side="left", padx=(7, 0))

    def _model_field(self, parent, row, include_url):
        wrap = tk.Frame(parent, bg="#0b1220")
        wrap.pack(fill="x", pady=(4, 5))
        tk.Label(wrap, text="Local Ollama coding / analysis model", fg="#d8e1f0", bg="#0b1220",
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        line = tk.Frame(wrap, bg="#0b1220")
        line.pack(fill="x", pady=(3, 0))
        combo = ttk.Combobox(line, textvariable=self.model_var, values=[], state="normal")
        combo.pack(side="left", fill="x", expand=True)
        if not hasattr(self, "model_combos"):
            self.model_combos = []
        self.model_combos.append(combo)
        ttk.Button(line, text="Refresh Models", command=self._refresh_models).pack(side="left", padx=(7, 0))
        if include_url:
            url_line = tk.Frame(wrap, bg="#0b1220")
            url_line.pack(fill="x", pady=(6, 0))
            tk.Label(url_line, text="Ollama server URL", fg="#a9bad3", bg="#0b1220",
                     font=("Segoe UI", 9)).pack(side="left")
            ttk.Entry(url_line, textvariable=self.ollama_url_var, width=40).pack(side="left", padx=(8, 0))

    def _clear_log(self):
        self.activity.configure(state="normal")
        self.activity.delete("1.0", "end")
        self.activity.configure(state="disabled")

    def _refresh_models(self):
        if self.busy:
            return
        from .ollama import Ollama
        model = self.model_var.get().strip() or None
        base_url = self.ollama_url_var.get().strip() or None

        def worker():
            try:
                models = Ollama(base_url=base_url, model=model).models()
                self.root.after(0, self._models_refreshed, models, None)
            except Exception as exc:
                self.root.after(0, self._models_refreshed, [], str(exc))

        self._log("Connecting to the configured local Ollama server to list installed models…")
        threading.Thread(target=worker, name="mimic-list-ollama-models", daemon=True).start()

    def _models_refreshed(self, models, error):
        for combo in getattr(self, "model_combos", []):
            combo.configure(values=models)
        if error:
            self._log("Could not list Ollama models: " + error)
            messagebox.showwarning("Ollama not reachable", error)
        else:
            self._log("Ollama models loaded: " + (", ".join(models) if models else "none installed"))
            if models and self.model_var.get().strip() not in models:
                preferred = next((name for name in models if "coder" in name.casefold()), models[0])
                self.model_var.set(preferred)

    def _path_picker(self, title, mode="folder", initial=None):
        """Tk-only path picker; avoids Windows shell dialogs that can hang behind the UI."""
        initial_path = Path(initial).expanduser() if initial else Path.home()
        if initial_path.is_file():
            initial_path = initial_path.parent
        while not initial_path.is_dir() and initial_path != initial_path.parent:
            initial_path = initial_path.parent
        if not initial_path.is_dir():
            initial_path = Path.home()

        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.transient(self.root)
        dialog.geometry("780x570")
        dialog.minsize(650, 440)
        dialog.configure(bg="#0b1220")
        result = {"path": None, "current": str(initial_path), "rows": [], "generation": 0, "drives": False}

        title_label = tk.Label(
            dialog, text=title, fg="#f0f5ff", bg="#0b1220",
            font=("Segoe UI", 13, "bold"), padx=16, pady=12,
        )
        title_label.pack(anchor="w")
        address = tk.Frame(dialog, bg="#0b1220", padx=16)
        address.pack(fill="x")
        path_var = tk.StringVar(value=str(initial_path))
        path_entry = ttk.Entry(address, textvariable=path_var)
        path_entry.pack(side="left", fill="x", expand=True)
        status_var = tk.StringVar(value="Choose a folder or type a path.")
        list_frame = tk.Frame(dialog, bg="#0b1220", padx=16, pady=10)
        list_frame.pack(fill="both", expand=True)
        entries = tk.Listbox(
            list_frame, bg="#080e18", fg="#d8e1f0", selectbackground="#245f73",
            selectforeground="#ffffff", activestyle="dotbox", font=("Segoe UI", 10),
            relief="flat", borderwidth=0, exportselection=False,
        )
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=entries.yview)
        entries.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        entries.pack(side="left", fill="both", expand=True)

        status_label = tk.Label(
            dialog, textvariable=status_var, fg="#a9bad3", bg="#0b1220",
            font=("Segoe UI", 9), anchor="w", padx=16, pady=4, wraplength=720,
        )
        status_label.pack(fill="x")

        def close(value=None):
            result["path"] = value
            try:
                dialog.grab_release()
            except tk.TclError:
                pass
            dialog.destroy()

        def show_rows(generation, folder, rows, error=None, drives=False):
            try:
                if not dialog.winfo_exists() or generation != result["generation"]:
                    return
            except tk.TclError:
                return
            entries.delete(0, "end")
            result["rows"] = rows
            result["drives"] = drives
            result["current"] = str(folder) if folder else ""
            path_var.set(str(folder) if folder else "This PC — choose a drive")
            if error:
                status_var.set("Cannot read that location: " + error)
                return
            for path, is_dir in rows:
                name = str(path) if drives else path.name
                if is_dir:
                    entries.insert("end", "[FOLDER] " + name)
                else:
                    entries.insert("end", "[FILE]   " + name)
            if drives:
                status_var.set("Select a drive, or type a folder path above and press Go.")
            elif mode == "file":
                status_var.set(f"{len(rows)} items in {folder}. Double-click a file to select it.")
            else:
                status_var.set(f"{len(rows)} folders in {folder}. Double-click to enter; Select Folder chooses the highlighted or current folder.")

        def load_folder(folder):
            candidate = Path(str(folder).strip().strip('"')).expanduser()
            result["generation"] += 1
            generation = result["generation"]
            status_var.set("Reading folder in the background…")
            entries.delete(0, "end")

            def worker():
                try:
                    if not candidate.exists():
                        raise FileNotFoundError(str(candidate))
                    if not candidate.is_dir():
                        if mode == "file" and candidate.is_file():
                            self.root.after(0, close, str(candidate))
                            return
                        raise NotADirectoryError(str(candidate))
                    directories, files = [], []
                    with os.scandir(str(candidate)) as scanner:
                        for index, item in enumerate(scanner):
                            if index >= 5000:
                                break
                            try:
                                if item.is_dir(follow_symlinks=False):
                                    directories.append(Path(item.path))
                                elif mode == "file" and item.is_file(follow_symlinks=False):
                                    files.append(Path(item.path))
                            except OSError:
                                continue
                    directories.sort(key=lambda path: path.name.casefold())
                    files.sort(key=lambda path: path.name.casefold())
                    rows = [(path, True) for path in directories] + [(path, False) for path in files]
                    self.root.after(0, show_rows, generation, candidate, rows, None, False)
                except Exception as exc:
                    try:
                        self.root.after(0, show_rows, generation, candidate, [], str(exc), False)
                    except tk.TclError:
                        pass

            threading.Thread(target=worker, name="mimic-path-picker", daemon=True).start()

        def show_drives():
            result["generation"] += 1
            generation = result["generation"]
            rows = []
            if os.name == "nt":
                try:
                    import ctypes
                    mask = ctypes.windll.kernel32.GetLogicalDrives()
                    for index, letter in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
                        if mask & (1 << index):
                            rows.append((Path(letter + ":\\"), True))
                except Exception:
                    rows = [(Path(letter + ":\\"), True) for letter in ("C", "D", "E", "F") if Path(letter + ":\\").exists()]
            else:
                rows = [(Path("/"), True)]
            show_rows(generation, None, rows, None, True)

        def go_to_path(_event=None):
            value = path_var.get().strip().strip('"')
            if not value:
                return
            if value.casefold().startswith("this pc"):
                show_drives()
            else:
                load_folder(value)

        def go_up():
            if result["drives"] or not result["current"]:
                show_drives()
                return
            current = Path(result["current"])
            parent = current.parent
            if parent == current:
                show_drives()
            else:
                load_folder(parent)

        def go_home():
            load_folder(Path.home())

        def selected_row():
            picked = entries.curselection()
            if not picked:
                return None
            index = picked[0]
            rows = result["rows"]
            return rows[index] if 0 <= index < len(rows) else None

        def activate_row(_event=None):
            row = selected_row()
            if not row:
                return
            path, is_dir = row
            if is_dir:
                load_folder(path)
            elif mode == "file":
                close(str(path))

        # Navigation controls live below the address bar so the path remains wide.
        nav_bar = tk.Frame(dialog, bg="#0b1220", padx=16)
        nav_bar.pack(fill="x", pady=(8, 2), before=list_frame)
        ttk.Button(nav_bar, text="Go", command=go_to_path).pack(side="left")
        ttk.Button(nav_bar, text="Up", command=go_up).pack(side="left", padx=(6, 0))
        ttk.Button(nav_bar, text="Home", command=go_home).pack(side="left", padx=(6, 0))
        if os.name == "nt":
            ttk.Button(nav_bar, text="This PC / Drives", command=show_drives).pack(side="left", padx=(6, 0))

        buttons = tk.Frame(dialog, bg="#0b1220", padx=16, pady=12)
        buttons.pack(fill="x")

        def select_location():
            row = selected_row()
            if mode == "folder":
                if row and row[1]:
                    close(str(row[0]))
                elif result["current"] and Path(result["current"]).is_dir():
                    close(result["current"])
                else:
                    status_var.set("Choose a valid folder first.")
            else:
                if row and not row[1]:
                    close(str(row[0]))
                elif row and row[1]:
                    load_folder(row[0])
                else:
                    status_var.set("Select a file, or double-click it in the list.")

        button_label = "Select Folder" if mode == "folder" else "Select File"
        ttk.Button(buttons, text=button_label, command=select_location).pack(side="right")
        ttk.Button(buttons, text="Cancel", command=lambda: close(None)).pack(side="right", padx=(0, 8))
        entries.bind("<Double-Button-1>", activate_row)
        path_entry.bind("<Return>", go_to_path)
        dialog.protocol("WM_DELETE_WINDOW", lambda: close(None))
        dialog.update_idletasks()
        dialog.lift()
        dialog.grab_set()
        path_entry.focus_set()
        load_folder(initial_path)
        self.root.wait_window(dialog)
        return result["path"]

    def _browse_analysis_file(self):
        path = self._path_picker(
            "Choose a target application or package",
            mode="file",
            initial=self.analysis_target_var.get() or Path.home(),
        )
        if path:
            self.analysis_target_var.set(path)
            self._suggest_analysis_output(path)

    def _browse_analysis_folder(self):
        path = self._path_picker(
            "Choose an application installation or source folder",
            mode="folder",
            initial=self.analysis_target_var.get() or Path.home(),
        )
        if path:
            self.analysis_target_var.set(path)
            self._suggest_analysis_output(path)

    def _suggest_analysis_output(self, target):
        target_path = Path(target)
        name = target_path.stem if target_path.is_file() else target_path.name
        name = "".join(character if character.isalnum() or character in "-_ " else "_" for character in name).strip()
        self.analysis_output_var.set(str(Path.home() / "MimicProjects" / "Analyses" / ((name or "app") + "-analysis")))

    def _browse_analysis_output(self):
        path = self._path_picker(
            "Choose analysis results folder",
            mode="folder",
            initial=self.analysis_output_var.get() or Path.home(),
        )
        if path:
            self.analysis_output_var.set(path)

    def _browse_reconstruction_output(self):
        path = self._path_picker(
            "Choose desktop reconstruction output folder",
            mode="folder",
            initial=self.output_var.get() or Path.home(),
        )
        if path:
            self.output_var.set(path)

    def _open_analysis_output(self):
        target = Path(self.analysis_output_var.get()).expanduser()
        if not target.exists():
            messagebox.showinfo("Results not created yet", "Run an analysis first. The results folder will appear here.")
            return
        try:
            if sys.platform == "win32":
                os.startfile(str(target))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                import subprocess
                subprocess.Popen(["open", str(target)])
            else:
                import subprocess
                subprocess.Popen(["xdg-open", str(target)])
        except Exception as exc:
            messagebox.showerror("Could not open folder", str(exc))

    def _start_analysis(self):
        if self.busy:
            messagebox.showinfo("Mimic is busy", "Wait for the current operation to finish.")
            return
        if self.capture or self.discovery:
            messagebox.showwarning(
                "Capture is active",
                "Stop the current UI capture before starting a separate static analysis job.",
            )
            return
        target = Path(self.analysis_target_var.get().strip().strip('"')).expanduser()
        output = Path(self.analysis_output_var.get().strip().strip('"')).expanduser()
        if not target.exists():
            messagebox.showwarning("Choose a target", "Browse to an application file or folder first.")
            return
        if not self.analysis_output_var.get().strip():
            messagebox.showwarning("Choose an output folder", "Choose where the analysis reports should be saved.")
            return
        try:
            max_decompile = max(0, min(50000, int(self.max_decompile_var.get().strip())))
        except ValueError:
            messagebox.showwarning("Invalid decompilation depth", "Enter an integer from 0 to 50000.")
            return
        use_summary = self.analysis_summary_var.get()
        model = self.model_var.get().strip()
        if use_summary and not model:
            messagebox.showwarning("Model required", "Enter an installed Ollama model or turn off AI summary.")
            return
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            if output.exists() and not output.is_dir():
                raise NotADirectoryError(str(output) + " is not a folder")
            if (
                output.is_dir()
                and any(output.iterdir())
                and not (output / "mimic-analysis-manifest.json").is_file()
            ):
                raise FileExistsError(
                    "The selected results folder is not empty and has no Mimic manifest. "
                    "Choose an empty folder so existing files are not overwritten:\n" + str(output)
                )
        except OSError as exc:
            messagebox.showerror("Cannot prepare output folder", str(exc))
            return

        self.busy = True
        self.analyze_button.configure(state="disabled")
        self.build_button.configure(state="disabled")
        self.arm_button.configure(state="disabled")
        self.open_analysis_button.configure(state="disabled")
        self.analysis_progress.start(12)
        self._log("Starting format detection and local static analysis: " + str(target))
        ghidra_home = self.ghidra_var.get().strip() or None
        ollama_url = self.ollama_url_var.get().strip() or None

        def worker():
            report = None
            summary_result = None
            summary_error = None
            error = None
            try:
                report = reverse_engineer(
                    str(target), str(output), ghidra_home=ghidra_home,
                    max_decompile=max_decompile, on_status=self._status_from_worker,
                )
                if report.get("analysis_error"):
                    raise RuntimeError(report["analysis_error"])
                if use_summary:
                    self._status_from_worker("Static analysis saved. Ollama is preparing an evidence-based report…")
                    try:
                        summary_result = summarize_analysis_manifest(
                            str(output / "mimic-analysis-manifest.json"), model=model, base_url=ollama_url,
                        )
                    except Exception as exc:
                        summary_error = str(exc)
            except Exception as exc:
                error = str(exc)
            try:
                self.root.after(0, self._analysis_finished, report, summary_result, summary_error, error, output)
            except tk.TclError:
                pass

        threading.Thread(target=worker, name="mimic-format-analysis", daemon=True).start()

    def _analysis_finished(self, report, summary_result, summary_error, error, output):
        self.analysis_progress.stop()
        self.busy = False
        self.analyze_button.configure(state="normal")
        self.open_analysis_button.configure(state="normal")
        self.arm_button.configure(state="normal")
        self.build_button.configure(
            state="normal" if self.capture_dir and count_capture_states(self.capture_dir) > 0 else "disabled"
        )
        if error:
            self._log("Analysis failed: " + error)
            messagebox.showerror("Analysis failed", error)
            return
        detection = (report or {}).get("detection", {}).get("type", "unknown")
        self._log("Static analysis complete. Detected type: " + detection)
        availability = (report or {}).get("tool_availability", {})
        if isinstance(availability, dict):
            missing = [name for name, details in availability.items() if isinstance(details, dict) and details.get("available") is False]
            if missing:
                self._log("Optional analyzers not installed: " + ", ".join(missing))
        self._log("Results saved to: " + str(output))
        if summary_result:
            self._log("Ollama findings report saved to: " + summary_result["markdown"])
        if summary_error:
            self._log("Static analysis succeeded, but Ollama summary failed: " + summary_error)
        warnings = (report or {}).get("warnings", [])
        if warnings:
            self._log("Warnings: " + " | ".join(str(item) for item in warnings[:8]))
        if summary_error:
            messagebox.showwarning(
                "Analysis saved; AI report unavailable",
                "The analysis artifacts were saved successfully, but Ollama could not finish the summary.\n\n"
                + summary_error + "\n\nOpen the results folder to inspect the manifest and tool output."
            )
        else:
            messagebox.showinfo(
                "Analysis complete",
                "Detected type: " + detection + "\n\nResults folder:\n" + str(output)
                + ("\n\nOllama findings report saved to:\n" + summary_result["markdown"] if summary_result else "")
            )

    def _log(self, message):
        line = datetime.now().strftime("%H:%M:%S") + "  " + str(message)
        self.activity.configure(state="normal")
        self.activity.insert("end", line + "\n")
        self.activity.see("end")
        self.activity.configure(state="disabled")
        self.status_var.set(str(message))

    def _status_from_worker(self, message):
        try:
            self.root.after(0, self._log, message)
        except tk.TclError:
            pass

    def _arm(self):
        if self.capture or self.discovery or self.busy or self.capture_picker:
            return
        trace_notice = (
            "\n\nThe optional Frida trace records selected module, file/registry paths, and connection destinations. It may affect app stability."
            if self.runtime_trace_var.get() else ""
        )
        confirmed = messagebox.askyesno(
            "Capture a desktop app",
            "Mimic records visible windows and UI Automation structure for one selected process. "
            "Choose an app that is already open, or choose Wait for New App. Screenshots may contain private data. "
            "Use a test account and keep the capture folder private." + trace_notice + "\n\nStart local capture?",
            parent=self.root,
        )
        if not confirmed:
            return
        try:
            require_windows_dependencies()
            root_dir = Path.home() / "MimicProjects" / "Captures"
            root_dir.mkdir(parents=True, exist_ok=True)
            self.capture_dir = root_dir / ("capture_" + datetime.now().strftime("%Y%m%d_%H%M%S_%f"))
        except Exception as exc:
            messagebox.showerror("Cannot prepare capture", str(exc), parent=self.root)
            return
        self.capture_attempt_id += 1
        self.capture_setup_cancelled = False
        self.arm_button.configure(state="disabled")
        self.stop_button.configure(state="disabled")
        self.build_button.configure(state="disabled")
        self._log("Choose an already-running app below, or use Wait for New App.")

        dialog = tk.Toplevel(self.root)
        self.capture_picker = dialog
        dialog.title("Choose app to capture")
        dialog.transient(self.root)
        dialog.geometry("800x520")
        dialog.minsize(650, 400)
        dialog.configure(bg="#0b1220")
        tk.Label(
            dialog, text="Select the application you actually want to capture",
            bg="#0b1220", fg="#f0f5ff", font=("Segoe UI", 13, "bold"),
            padx=16, pady=12,
        ).pack(anchor="w")
        tk.Label(
            dialog,
            text="This list includes visible windows that are already open. Mimic captures the selected process, not the whole desktop.",
            bg="#0b1220", fg="#a9bad3", font=("Segoe UI", 9),
            padx=16, pady=2, wraplength=750, justify="left",
        ).pack(anchor="w")
        list_frame = tk.Frame(dialog, bg="#0b1220", padx=16, pady=10)
        list_frame.pack(fill="both", expand=True)
        targets = tk.Listbox(
            list_frame, bg="#080e18", fg="#d8e1f0", selectbackground="#245f73",
            selectforeground="#ffffff", font=("Segoe UI", 10), relief="flat",
            borderwidth=0, exportselection=False,
        )
        target_scroll = ttk.Scrollbar(list_frame, orient="vertical", command=targets.yview)
        targets.configure(yscrollcommand=target_scroll.set)
        target_scroll.pack(side="right", fill="y")
        targets.pack(side="left", fill="both", expand=True)
        status_var = tk.StringVar(value="Loading visible windows in the background…")
        tk.Label(
            dialog, textvariable=status_var, bg="#0b1220", fg="#a9bad3",
            font=("Segoe UI", 9), anchor="w", padx=16, pady=5,
        ).pack(fill="x")
        button_bar = tk.Frame(dialog, bg="#0b1220", padx=16, pady=12)
        button_bar.pack(fill="x")

        picker_updates = queue.Queue()

        def alive():
            try:
                return bool(dialog.winfo_exists())
            except tk.TclError:
                return False

        def drain_picker_updates():
            """Apply worker results from the Tk thread; never call Tkinter from a worker."""
            if not alive():
                return
            try:
                while True:
                    rows, error = picker_updates.get_nowait()
                    update_rows(rows, error)
            except queue.Empty:
                pass
            except tk.TclError:
                return
            try:
                if alive():
                    dialog.after(40, drain_picker_updates)
            except tk.TclError:
                pass

        def close_picker():
            if alive():
                try:
                    dialog.grab_release()
                except tk.TclError:
                    pass
                dialog.destroy()
            self.capture_picker = None

        def cancel():
            close_picker()
            self._cancel_capture_setup()

        def refresh():
            if not alive():
                return
            status_var.set("Enumerating visible app windows in a worker thread…")
            refresh_button.configure(state="disabled")

            def worker():
                try:
                    rows = list_windows(exclude_pid=os.getpid())
                    rows.sort(key=lambda row: (row["title"].casefold(), row["pid"], row["hwnd"]))
                    error = None
                except Exception as exc:
                    rows, error = [], str(exc)
                # Queue the data only. Calling root.after() from this worker is
                # unreliable on some Windows/Tk builds and can leave the picker
                # forever at "Loading visible windows..." with an empty list.
                picker_updates.put((rows, error))

            threading.Thread(target=worker, name="mimic-list-capture-targets", daemon=True).start()

        def update_rows(rows, error):
            if not alive():
                return
            refresh_button.configure(state="normal")
            targets.delete(0, "end")
            self.capture_target_rows = rows
            if error:
                status_var.set("Could not enumerate windows: " + error)
                return
            for row in rows:
                executable = Path(row["executable_path"]).name if row.get("executable_path") else "(executable path unavailable)"
                targets.insert("end", f'{row["title"]}    | PID {row["pid"]}    | {executable}')
            if rows:
                targets.selection_set(0)
                targets.activate(0)
                status_var.set(f"{len(rows)} visible windows found. Select the correct app, then Capture Selected.")
            else:
                status_var.set("No visible app windows found. Refresh, check the app is visible, or use Wait for New App.")

        def capture_selected(_event=None):
            selection = targets.curselection()
            if not selection:
                status_var.set("Select a window first.")
                return
            index = selection[0]
            if index >= len(self.capture_target_rows):
                status_var.set("The window list changed. Press Refresh.")
                return
            target = self.capture_target_rows[index]
            close_picker()
            self._start_target_capture(target)

        def wait_new():
            close_picker()
            self._start_waiting_for_new_app()

        targets.bind("<Double-Button-1>", capture_selected)
        ttk.Button(button_bar, text="Refresh Windows", command=refresh).pack(side="left")
        ttk.Button(button_bar, text="Wait for New App", command=wait_new).pack(side="left", padx=(8, 0))
        ttk.Button(button_bar, text="Capture Selected", command=capture_selected).pack(side="right")
        ttk.Button(button_bar, text="Cancel", command=cancel).pack(side="right", padx=(0, 8))
        dialog.protocol("WM_DELETE_WINDOW", cancel)
        dialog.update_idletasks()
        dialog.lift()
        dialog.grab_set()
        dialog.after(40, drain_picker_updates)
        refresh()

    def _cancel_capture_setup(self):
        self.capture_setup_cancelled = True
        self.capture_attempt_id += 1
        if self.discovery_stopped:
            self.discovery_stopped.set()
        self.discovery_stopped = None
        self.discovery = None
        self.capture_picker = None
        self.capture_dir = None
        self.arm_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.build_button.configure(state="disabled")
        self._log("Capture setup cancelled. No capture was saved.")

    def _start_waiting_for_new_app(self):
        if not self.capture_dir:
            self._cancel_capture_setup()
            return
        attempt_id = self.capture_attempt_id
        self.stop_button.configure(state="normal")
        self._log("Taking a baseline of current windows in the background. Open the target app after Mimic says it is waiting.")

        def worker():
            try:
                stopped, watcher = start_armed_capture(
                    self.capture_dir,
                    lambda target: self._target_detected(target, attempt_id),
                    self._status_from_worker,
                )
                try:
                    self.root.after(0, self._watch_started, stopped, watcher, attempt_id)
                except tk.TclError:
                    stopped.set()
            except Exception as exc:
                try:
                    self.root.after(0, self._watch_start_failed, str(exc), attempt_id)
                except tk.TclError:
                    pass

        threading.Thread(target=worker, name="mimic-prepare-window-watch", daemon=True).start()

    def _watch_started(self, stopped, watcher, attempt_id):
        if attempt_id != self.capture_attempt_id or self.capture_setup_cancelled or self.capture:
            stopped.set()
            return
        self.discovery_stopped = stopped
        self.discovery = watcher
        self.stop_button.configure(state="normal")
        self._log("Waiting for a newly opened app window. Existing windows are not auto-selected.")

    def _watch_start_failed(self, error, attempt_id):
        if attempt_id != self.capture_attempt_id or self.capture_setup_cancelled:
            return
        self._log("Could not start window discovery: " + error)
        messagebox.showerror("Window discovery failed", error, parent=self.root)
        self._cancel_capture_setup()

    def _target_detected(self, target, attempt_id=None):
        attempt_id = self.capture_attempt_id if attempt_id is None else attempt_id
        if attempt_id != self.capture_attempt_id or self.capture_setup_cancelled:
            return
        try:
            self.root.after(0, self._start_target_capture, target, attempt_id)
        except tk.TclError:
            pass

    def _start_target_capture(self, target, attempt_id=None):
        attempt_id = self.capture_attempt_id if attempt_id is None else attempt_id
        if attempt_id != self.capture_attempt_id or self.capture_setup_cancelled or self.capture:
            return
        if self.discovery_stopped and self.discovery_stopped.is_set():
            return
        if self.discovery_stopped:
            self.discovery_stopped.set()
        self.discovery_stopped = None
        self.discovery = None
        self._log("Starting UI capture for: " + target["title"] + " (PID " + str(target["pid"]) + ")")
        self.binary_var.set(target.get("executable_path") or "")
        if not target.get("executable_path"):
            self._log("Windows did not reveal this process's executable path; Browse EXE can set it manually.")
        try:
            self.capture = CaptureSession(
                target["pid"], target["title"], self.capture_dir,
                on_status=self._status_from_worker,
                executable_path=target.get("executable_path"),
            ).start()
        except Exception as exc:
            self.capture = None
            self._log("Could not capture target: " + str(exc))
            messagebox.showerror("Capture failed", str(exc), parent=self.root)
            self.arm_button.configure(state="normal")
            self.stop_button.configure(state="disabled")
            return
        if self.runtime_trace_var.get():
            try:
                self.runtime_trace = RuntimeTrace(
                    target["pid"], self.capture_dir / "runtime-events.jsonl",
                    on_status=self._status_from_worker,
                ).start()
            except RuntimeTraceError as exc:
                self.runtime_trace = None
                self._log("Runtime trace was not started: " + str(exc))
        project_name = self.capture_dir.name + "-clone"
        self.output_var.set(str(Path.home() / "MimicProjects" / "Reconstructions" / project_name))
        self.arm_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.build_button.configure(state="disabled")
        self._log("Capture started. Keep the target visible and exercise screens, menus, dialogs, settings, and normal workflows. Mimic will report each distinct UI state it records.")

    def _stop(self):
        if self.capture_picker:
            return
        self.capture_setup_cancelled = True
        self.capture_attempt_id += 1
        if self.discovery_stopped:
            self.discovery_stopped.set()
        active = self.capture
        trace = self.runtime_trace
        self.capture = None
        self.runtime_trace = None
        self.discovery = None
        self.discovery_stopped = None
        self.stop_button.configure(state="disabled")
        self.arm_button.configure(state="disabled")
        self.build_button.configure(state="disabled")
        if active or trace:
            self._log("Stopping capture, flushing UI events, and detaching runtime instrumentation…")

            def finish_capture():
                errors = []
                if active:
                    try:
                        active.stop()
                    except Exception as exc:
                        errors.append("Capture stop error: " + str(exc))
                if trace:
                    try:
                        trace.stop()
                    except Exception as exc:
                        errors.append("Runtime trace stop error: " + str(exc))
                try:
                    self.root.after(0, self._capture_stopped, errors)
                except tk.TclError:
                    pass

            threading.Thread(target=finish_capture, name="mimic-stop-capture", daemon=True).start()
        else:
            self._capture_stopped([])

    def _capture_stopped(self, errors=None):
        errors = errors or []
        self.arm_button.configure(state="normal")
        actual_events = count_capture_states(self.capture_dir) if self.capture_dir else 0
        has_states = actual_events > 0
        self.build_button.configure(state="normal" if has_states and not self.busy else "disabled")
        self._log(f"Capture stopped. Saved {actual_events} UI states.")
        if errors:
            self._log("Capture shutdown warnings: " + " | ".join(errors))
        if has_states:
            self._log("Capture folder: " + str(self.capture_dir))
        else:
            self._log("No UI states were captured. Keep the target visible and make sure Mimic and the target run at the same privilege level.")
            messagebox.showwarning(
                "No UI states captured",
                "Mimic did not record any visible UI states, so reconstruction is disabled.\n\n"
                "Select the actual app window, keep it unminimized, interact with several screens, "
                "and avoid running the app as administrator while Mimic is not elevated (or vice versa).",
                parent=self.root,
            )
        self.stop_button.configure(state="disabled")
        self.capture_setup_cancelled = False

    def _browse_binary(self):
        path = self._path_picker(
            "Choose the original executable",
            mode="file",
            initial=self.binary_var.get() or Path.home(),
        )
        if path:
            self.binary_var.set(path)

    def _detect_ghidra(self):
        # Detection is filesystem-based and non-blocking: avoid the native Windows
        # folder dialog, which can hang or appear behind the app on some systems.
        configured = self.ghidra_var.get().strip() or None
        detected = find_ghidra_home(configured)
        if detected:
            self.ghidra_var.set(str(detected))
            launcher = detected / "support" / (
                "analyzeHeadless.bat" if sys.platform == "win32" else "analyzeHeadless"
            )
            if not launcher.is_file():
                alternate = detected / "support" / "analyzeHeadless"
                if alternate.is_file():
                    launcher = alternate
            self._log("Ghidra detected: " + str(detected))
            self._log("Headless launcher: " + str(launcher))
            return
        messagebox.showwarning(
            "Ghidra not detected",
            "Mimic could not find a Ghidra installation containing "
            "support\\analyzeHeadless.bat. Your installation root should be the folder "
            "inside the extracted archive that contains the support and Ghidra folders. "
            "You can paste that full folder path into the editable field.",
            parent=self.root,
        )

    def _build(self):
        if self.busy:
            return
        if not self.capture_dir or count_capture_states(self.capture_dir) < 1:
            messagebox.showwarning(
                "No usable capture",
                "Mimic has no saved UI states to reconstruct. Capture a visible app window, "
                "wait for the first state-count message, and interact with its screens before stopping.",
                parent=self.root,
            )
            return
        model = self.model_var.get().strip()
        ollama_url = self.ollama_url_var.get().strip() or None
        output = Path(self.output_var.get()).expanduser()
        try:
            max_decompile = max(0, min(50000, int(self.max_decompile_var.get().strip())))
        except ValueError:
            messagebox.showwarning("Invalid decompilation depth", "Enter an integer from 0 to 50000.")
            return
        if not model:
            messagebox.showwarning("Model required", "Enter an installed local Ollama model name.")
            return
        binary = self.binary_var.get().strip()
        if not binary and (self.capture_dir / "session.json").is_file():
            try:
                binary = json.loads((self.capture_dir / "session.json").read_text(encoding="utf-8")).get("executable_path") or ""
            except (OSError, ValueError):
                binary = ""
        if not binary:
            messagebox.showwarning("Executable required", "Mimic could not resolve the selected process EXE. Use Browse EXE to select the original program binary.")
            return
        ghidra_home = self.ghidra_var.get().strip() or None
        if not ghidra_home and not find_ghidra_home():
            messagebox.showwarning("Ghidra required", "Install Ghidra and enter its extracted folder, or set GHIDRA_HOME. Mimic uses native Ghidra headless analysis before generation.")
            return
        self.busy = True
        self.build_button.configure(state="disabled")
        self.arm_button.configure(state="disabled")
        self._log("Running Ghidra static reverse engineering first, then reconstructing with local Ollama. Runtime depends on binary size and model speed.")

        capture_dir = self.capture_dir

        def worker():
            try:
                reverse_dir = capture_dir / "reverse-engineering"
                report = reverse_engineer(
                    binary, str(reverse_dir), ghidra_home=ghidra_home,
                    max_decompile=max_decompile,
                    on_status=self._status_from_worker,
                )
                if report.get("analysis_error"):
                    raise RuntimeError(report["analysis_error"])
                manifest = reverse_dir / "mimic-analysis-manifest.json"
                analysis_summary = None
                try:
                    analysis_summary = summarize_analysis_manifest(str(manifest), model=model, base_url=ollama_url)
                    self._status_from_worker("Local Ollama has summarized static-analysis findings; reconstructing the UI from all available evidence…")
                except Exception as summary_error:
                    self._status_from_worker("Analysis summary note: " + str(summary_error)[:260])
                from .windows_reconstruct import reconstruct_desktop
                files, notes = reconstruct_desktop(
                    str(capture_dir), str(output), model=model,
                    base_url=ollama_url, static_report=str(manifest),
                )
                analyzed = report.get("analysis", {})
                functions = analyzed.get("total_function_count", analyzed.get("function_count", 0)) if isinstance(analyzed, dict) else 0
                message = (
                    "Static reverse engineering finished for " + str(binary) +
                    "; Ghidra found " + str(functions) + " functions. Created " +
                    str(len(files)) + " project files at " + str(output) +
                    ". Review the generated code before running main.py."
                )
                if analysis_summary:
                    message += " Ollama findings report saved to: " + analysis_summary["markdown"]
                if notes:
                    message += " | " + "; ".join(notes)
                self.root.after(0, self._build_finished, True, message)
            except Exception as exc:
                try:
                    self.root.after(0, self._build_finished, False, str(exc))
                except tk.TclError:
                    pass

        threading.Thread(target=worker, name="mimic-ghidra-ollama-build", daemon=True).start()

    def _build_finished(self, success, message):
        self.busy = False
        self._log(message)
        self.build_button.configure(state="normal" if self.capture_dir and count_capture_states(self.capture_dir) > 0 else "disabled")
        self.arm_button.configure(state="normal")
        if success:
            messagebox.showinfo("Reconstruction generated", message)
        else:
            messagebox.showerror("Build failed", message)

    def _close(self):
        if self.capture or self.discovery or self.runtime_trace:
            if not messagebox.askyesno("Stop capture?", "Stop the active UI capture/runtime trace and close Mimic?"):
                return
            if self.discovery_stopped:
                self.discovery_stopped.set()
            if self.capture:
                self.capture.stop()
                self.capture = None
            if self.runtime_trace:
                self.runtime_trace.stop()
                self.runtime_trace = None
        self.root.destroy()


def main():
    try:
        require_windows_dependencies()
    except WindowsCaptureError as exc:
        details = str(exc) + '\n\nRun Install-Mimic.bat in the repository folder to install the required Windows UI dependencies.'
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Mimic setup required", details)
            root.destroy()
        except Exception:
            print(details, file=sys.stderr)
        return 1
    root = tk.Tk()
    MimicWindowsApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

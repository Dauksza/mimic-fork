"""Tkinter UI for Windows capture, Ghidra analysis, and local reconstruction."""
from __future__ import annotations

import json
import os
import sys
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .ghidra import analyze_binary, find_ghidra_home
from .windows_capture import (
    CaptureSession,
    WindowsCaptureError,
    require_windows_dependencies,
    start_armed_capture,
)


class MimicWindowsApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MIMIC | Windows Reverse Engineering")
        self.root.geometry("1020x860")
        self.root.minsize(850, 720)
        self.root.configure(bg="#0b1220")
        self.capture = None
        self.discovery = None
        self.discovery_stopped = None
        self.capture_dir = None
        self.busy = False
        self.model_var = tk.StringVar(value=os.environ.get("MIMIC_OLLAMA_MODEL", "qwen2.5-coder:14b"))
        self.output_var = tk.StringVar(value=str(Path.home() / "MimicProjects" / "Reconstructions" / "desktop-clone"))
        self.ghidra_var = tk.StringVar(value=str(find_ghidra_home() or os.environ.get("GHIDRA_HOME", "")))
        self.binary_var = tk.StringVar(value="")
        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._close)
        self._log("Ready. Arm capture, then open the Windows application to observe.")

    def _build_ui(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TButton", font=("Segoe UI", 10), padding=(12, 8))
        style.configure("TLabel", background="#0b1220", foreground="#d8e1f0", font=("Segoe UI", 10))
        style.configure("TEntry", fieldbackground="#111b2e", foreground="#edf3ff", padding=8)

        header = tk.Frame(self.root, bg="#101b2d", padx=26, pady=20)
        header.pack(fill="x")
        tk.Label(header, text="MIMIC", fg="#75e0d0", bg="#101b2d", font=("Segoe UI", 23, "bold")).pack(anchor="w")
        tk.Label(header, text="WINDOWS OBSERVER  /  GHIDRA  /  LOCAL OLLAMA",
                 fg="#c5d1e5", bg="#101b2d", font=("Segoe UI", 10)).pack(anchor="w", pady=(2, 0))

        body = tk.Frame(self.root, bg="#0b1220", padx=26, pady=16)
        body.pack(fill="both", expand=True)
        tk.Label(body, text="Observe → Reverse engineer → Reconstruct",
                 font=("Segoe UI", 15, "bold")).pack(anchor="w")
        instructions = (
            "1. Click ARM CAPTURE.  2. Open the target program.  3. Exercise its screens and workflows.\n"
            "4. Click STOP CAPTURE.  5. Generate Desktop Copy runs Ghidra on the selected EXE, then uses local Ollama.\n"
            "Mimic records the selected process's visible UI. No global keylogging or clipboard capture."
        )
        tk.Label(body, text=instructions, justify="left", wraplength=930, fg="#a9bad3",
                 bg="#0b1220", font=("Segoe UI", 10), pady=9).pack(anchor="w")

        buttons = tk.Frame(body, bg="#0b1220")
        buttons.pack(fill="x", pady=(4, 10))
        self.arm_button = ttk.Button(buttons, text="ARM CAPTURE", command=self._arm)
        self.arm_button.pack(side="left")
        self.stop_button = ttk.Button(buttons, text="STOP CAPTURE", command=self._stop, state="disabled")
        self.stop_button.pack(side="left", padx=(8, 0))
        self.build_button = ttk.Button(buttons, text="GENERATE DESKTOP COPY", command=self._build, state="disabled")
        self.build_button.pack(side="left", padx=(8, 0))

        tk.Label(body, text="Detected target executable (EXE / DLL)", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        binary_row = tk.Frame(body, bg="#0b1220")
        binary_row.pack(fill="x", pady=(3, 8))
        ttk.Entry(binary_row, textvariable=self.binary_var).pack(side="left", fill="x", expand=True)
        ttk.Button(binary_row, text="Browse EXE", command=self._browse_binary).pack(side="left", padx=(8, 0))

        tk.Label(body, text="Ghidra install folder", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        ghidra_row = tk.Frame(body, bg="#0b1220")
        ghidra_row.pack(fill="x", pady=(3, 8))
        ttk.Entry(ghidra_row, textvariable=self.ghidra_var).pack(side="left", fill="x", expand=True)
        ttk.Button(ghidra_row, text="Browse Ghidra", command=self._browse_ghidra).pack(side="left", padx=(8, 0))

        tk.Label(body, text="Local Ollama coding model", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        ttk.Entry(body, textvariable=self.model_var).pack(fill="x", pady=(3, 8))

        tk.Label(body, text="Output project folder", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        ttk.Entry(body, textvariable=self.output_var).pack(fill="x", pady=(3, 8))

        self.status_var = tk.StringVar(value="Idle")
        status_bar = tk.Frame(body, bg="#132238", padx=12, pady=9)
        status_bar.pack(fill="x", pady=(2, 8))
        tk.Label(status_bar, textvariable=self.status_var, fg="#75e0d0", bg="#132238",
                 font=("Segoe UI", 10, "bold"), wraplength=930, justify="left").pack(anchor="w")

        tk.Label(body, text="Activity", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.activity = tk.Text(body, height=9, bg="#080e18", fg="#c6d4e7", insertbackground="#ffffff",
                                relief="flat", padx=12, pady=9, font=("Consolas", 9), wrap="word")
        self.activity.pack(fill="both", expand=True, pady=(5, 0))
        self.activity.configure(state="disabled")

        footer = tk.Label(
            self.root,
            text="Local analysis • Ghidra static analysis • No global keylogging • Password/edit values omitted",
            fg="#7f91aa", bg="#0b1220", font=("Segoe UI", 9), pady=8
        )
        footer.pack(fill="x")

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
        if self.capture or self.discovery or self.busy:
            return
        try:
            require_windows_dependencies()
            root_dir = Path.home() / "MimicProjects" / "Captures"
            root_dir.mkdir(parents=True, exist_ok=True)
            self.capture_dir = root_dir / ("capture_" + datetime.now().strftime("%Y%m%d_%H%M%S_%f"))
            self.discovery_stopped, self.discovery = start_armed_capture(
                self.capture_dir, self._target_detected, self._status_from_worker
            )
        except Exception as exc:
            messagebox.showerror("Cannot start capture", str(exc))
            return
        self.arm_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.build_button.configure(state="disabled")
        self._log("Armed. Open the target program now. Mimic will detect the new window and its process.")

    def _target_detected(self, target):
        try:
            self.root.after(0, self._start_target_capture, target)
        except tk.TclError:
            pass

    def _start_target_capture(self, target):
        if self.discovery_stopped and self.discovery_stopped.is_set():
            return
        self._log("Detected: " + target["title"] + " (PID " + str(target["pid"]) + ")")
        self.binary_var.set(target.get("executable_path") or "")
        if not target.get("executable_path"):
            self._log("Windows did not reveal this process's executable path; use Browse EXE to choose it manually.")
        try:
            self.capture = CaptureSession(
                target["pid"], target["title"], self.capture_dir,
                on_status=self._status_from_worker,
                executable_path=target.get("executable_path"),
            ).start()
        except Exception as exc:
            self.capture = None
            self._log("Could not capture target: " + str(exc))
            messagebox.showerror("Capture failed", str(exc))
            self.arm_button.configure(state="normal")
            self.stop_button.configure(state="disabled")
            return
        project_name = self.capture_dir.name + "-clone"
        self.output_var.set(str(Path.home() / "MimicProjects" / "Reconstructions" / project_name))
        self._log("Capture active. Exercise distinct pages, menus, dialogs, settings, and normal workflows. Visible private data may appear in screenshots.")

    def _stop(self):
        if self.discovery_stopped:
            self.discovery_stopped.set()
        active = self.capture
        self.capture = None
        self.discovery = None
        self.discovery_stopped = None
        self.stop_button.configure(state="disabled")
        self.arm_button.configure(state="normal")
        self.build_button.configure(state="disabled")
        if active:
            self._log("Stopping capture and flushing events to disk…")
            def finish_capture():
                active.stop()
                try:
                    self.root.after(0, self._capture_stopped)
                except tk.TclError:
                    pass
            threading.Thread(target=finish_capture, daemon=True).start()
        else:
            self._capture_stopped()

    def _capture_stopped(self):
        has_events = bool(self.capture_dir and (self.capture_dir / "events.jsonl").exists())
        self.build_button.configure(state="normal" if has_events and not self.busy else "disabled")
        self._log("Capture saved. Generation will run Ghidra first, then local Ollama.")

    def _browse_binary(self):
        path = filedialog.askopenfilename(
            title="Choose the original executable",
            filetypes=[("Windows executables and libraries", "*.exe *.dll *.ocx *.sys"), ("All files", "*.*")]
        )
        if path:
            self.binary_var.set(path)

    def _browse_ghidra(self):
        path = filedialog.askdirectory(title="Choose the extracted Ghidra installation folder")
        if path:
            self.ghidra_var.set(path)

    def _build(self):
        if self.busy:
            return
        if not self.capture_dir or not (self.capture_dir / "events.jsonl").exists():
            messagebox.showwarning("No capture", "Capture a Windows program first.")
            return
        model = self.model_var.get().strip()
        output = Path(self.output_var.get()).expanduser()
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
                report = analyze_binary(
                    binary, reverse_dir, ghidra_home=ghidra_home,
                    on_status=self._status_from_worker,
                )
                from .windows_reconstruct import reconstruct_desktop
                files, notes = reconstruct_desktop(
                    str(capture_dir), str(output), model=model,
                    static_report=str(reverse_dir / "ghidra-analysis.json"),
                )
                message = (
                    "Ghidra analyzed " + str(report.get("analyzed_binary", binary)) +
                    " and found " + str(report.get("function_count", 0)) +
                    " functions. Created " + str(len(files)) + " project files at " +
                    str(output) + ". Review the generated code before running main.py."
                )
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
        self.build_button.configure(state="normal" if self.capture_dir and (self.capture_dir / "events.jsonl").exists() else "disabled")
        self.arm_button.configure(state="normal")
        if success:
            messagebox.showinfo("Reconstruction generated", message)
        else:
            messagebox.showerror("Build failed", message)

    def _close(self):
        if self.capture or self.discovery:
            if not messagebox.askyesno("Stop capture?", "Stop the active capture and close Mimic?"):
                return
            if self.discovery_stopped:
                self.discovery_stopped.set()
            if self.capture:
                active = self.capture
                self.capture = None
                active.stop()
        self.root.destroy()


def main():
    try:
        require_windows_dependencies()
    except WindowsCaptureError as exc:
        print(str(exc), file=sys.stderr)
        print('Install dependencies with: python -m pip install -e ".[windows]"', file=sys.stderr)
        return 1
    root = tk.Tk()
    MimicWindowsApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Tkinter front-end for consent-driven Windows desktop observation."""
from __future__ import annotations

import os
import sys
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, ttk

from .windows_capture import CaptureSession, WindowsCaptureError, require_windows_dependencies, start_armed_capture


class MimicWindowsApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MIMIC | Windows Observer")
        self.root.geometry("940x700")
        self.root.minsize(780, 600)
        self.root.configure(bg="#0b1220")
        self.capture = None
        self.discovery = None
        self.discovery_stopped = None
        self.capture_dir = None
        self.busy = False
        self.model_var = tk.StringVar(value=os.environ.get("MIMIC_OLLAMA_MODEL", "qwen2.5-coder:14b"))
        self.output_var = tk.StringVar(value=str(Path.home() / "MimicProjects" / "Reconstructions" / "desktop-clone"))
        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._close)
        self._log("Ready. Start an explicitly armed capture, then open the Windows program to observe.")

    def _build_ui(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TButton", font=("Segoe UI", 10), padding=(14, 9))
        style.configure("TLabel", background="#0b1220", foreground="#d8e1f0", font=("Segoe UI", 10))
        style.configure("TEntry", fieldbackground="#111b2e", foreground="#edf3ff", padding=8)

        header = tk.Frame(self.root, bg="#101b2d", padx=26, pady=22)
        header.pack(fill="x")
        tk.Label(header, text="MIMIC", fg="#75e0d0", bg="#101b2d", font=("Segoe UI", 23, "bold")).pack(anchor="w")
        tk.Label(header, text="WINDOWS DESKTOP OBSERVER  /  LOCAL OLLAMA", fg="#c5d1e5", bg="#101b2d",
                 font=("Segoe UI", 10)).pack(anchor="w", pady=(2, 0))

        body = tk.Frame(self.root, bg="#0b1220", padx=26, pady=20)
        body.pack(fill="both", expand=True)

        tk.Label(body, text="Capture a program", font=("Segoe UI", 15, "bold")).pack(anchor="w")
        instructions = (
            "1. Click ARM CAPTURE.  2. Open the Windows program you own or are authorized to reproduce.\n"
            "3. Use its screens and workflows normally.  4. Return here and click STOP CAPTURE.\n"
            "Mimic records visible UI structure and changing screenshots for the detected process only."
        )
        tk.Label(body, text=instructions, justify="left", wraplength=850, fg="#a9bad3",
                 bg="#0b1220", font=("Segoe UI", 10), pady=10).pack(anchor="w")

        buttons = tk.Frame(body, bg="#0b1220")
        buttons.pack(fill="x", pady=(4, 16))
        self.arm_button = ttk.Button(buttons, text="ARM CAPTURE", command=self._arm)
        self.arm_button.pack(side="left")
        self.stop_button = ttk.Button(buttons, text="STOP CAPTURE", command=self._stop, state="disabled")
        self.stop_button.pack(side="left", padx=(10, 0))
        self.build_button = ttk.Button(buttons, text="GENERATE DESKTOP COPY", command=self._build, state="disabled")
        self.build_button.pack(side="left", padx=(10, 0))

        tk.Label(body, text="Local Ollama model", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        ttk.Entry(body, textvariable=self.model_var).pack(fill="x", pady=(4, 12))

        tk.Label(body, text="Output project folder", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        ttk.Entry(body, textvariable=self.output_var).pack(fill="x", pady=(4, 12))

        self.status_var = tk.StringVar(value="Idle")
        status_bar = tk.Frame(body, bg="#132238", padx=12, pady=10)
        status_bar.pack(fill="x", pady=(2, 12))
        tk.Label(status_bar, textvariable=self.status_var, fg="#75e0d0", bg="#132238",
                 font=("Segoe UI", 10, "bold"), wraplength=840, justify="left").pack(anchor="w")

        tk.Label(body, text="Activity", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.activity = tk.Text(body, height=11, bg="#080e18", fg="#c6d4e7", insertbackground="#ffffff",
                                relief="flat", padx=12, pady=10, font=("Consolas", 9), wrap="word")
        self.activity.pack(fill="both", expand=True, pady=(6, 0))
        self.activity.configure(state="disabled")

        footer = tk.Label(self.root, text="Local capture only • No global keylogging • Editable/password field values omitted",
                          fg="#7f91aa", bg="#0b1220", font=("Segoe UI", 9), pady=8)
        footer.pack(fill="x")

    def _log(self, message):
        line = datetime.now().strftime("%H:%M:%S") + "  " + str(message)
        self.activity.configure(state="normal")
        self.activity.insert("end", line + "\n")
        self.activity.see("end")
        self.activity.configure(state="disabled")
        self.status_var.set(str(message))

    def _status_from_worker(self, message):
        self.root.after(0, self._log, message)

    def _arm(self):
        if self.capture or self.discovery:
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
        self._log("Armed. Open the target program now. Its visible window will be detected automatically.")

    def _target_detected(self, target):
        self.root.after(0, self._start_target_capture, target)

    def _start_target_capture(self, target):
        if self.discovery_stopped and self.discovery_stopped.is_set():
            return
        self._log(f"Target detected: {target['title']}  (process {target['pid']})")
        try:
            self.capture = CaptureSession(
                target["pid"], target["title"], self.capture_dir,
                on_status=self._status_from_worker,
            ).start()
        except Exception as exc:
            self.capture = None
            self._log("Could not capture target: " + str(exc))
            messagebox.showerror("Capture failed", str(exc))
            self.arm_button.configure(state="normal")
            self.stop_button.configure(state="disabled")
            return
        self.output_var.set(str(Path.home() / "MimicProjects" / "Reconstructions" / (self.capture_dir.name + "-clone")))
        self._log("Capture active. Exercise different pages, dialogs, menus, search, settings, and common tasks.")

    def _stop(self):
        if self.discovery_stopped:
            self.discovery_stopped.set()
        if self.capture:
            active = self.capture
            self.capture = None
            threading.Thread(target=active.stop, daemon=True).start()
        self.discovery = None
        self.discovery_stopped = None
        self.arm_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.build_button.configure(state="normal" if self.capture_dir and (self.capture_dir / "events.jsonl").exists() else "disabled")
        self._log("Capture stop requested. Your captured session remains on this PC.")

    def _build(self):
        if not self.capture_dir or not (self.capture_dir / "events.jsonl").exists():
            messagebox.showwarning("No capture", "Capture a Windows program first.")
            return
        model = self.model_var.get().strip()
        output = Path(self.output_var.get()).expanduser()
        if not model:
            messagebox.showwarning("Model required", "Enter an installed local Ollama model name.")
            return
        self.busy = True
        self.build_button.configure(state="disabled")
        self._log("Generating the desktop reconstruction with local Ollama. This can take several minutes for large captures.")

        def worker():
            try:
                from .windows_reconstruct import reconstruct_desktop
                files, notes = reconstruct_desktop(str(self.capture_dir), str(output), model=model)
                message = f"Created {len(files)} files at {output}. Run: python main.py"
                if notes:
                    message += " | " + "; ".join(notes)
                self.root.after(0, self._build_finished, True, message)
            except Exception as exc:
                self.root.after(0, self._build_finished, False, str(exc))

        threading.Thread(target=worker, name="mimic-desktop-build", daemon=True).start()

    def _build_finished(self, success, message):
        self.busy = False
        self._log(message)
        self.build_button.configure(state="normal")
        if success:
            messagebox.showinfo("Reconstruction generated", message)
        else:
            messagebox.showerror("Build failed", message)

    def _close(self):
        if self.capture or self.discovery:
            if not messagebox.askyesno("Stop capture?", "Stop the active capture and close Mimic?"):
                return
            self._stop()
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

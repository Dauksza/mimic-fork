"""Double-click launcher for the Mimic Windows desktop interface."""
import traceback
import tkinter as tk
from tkinter import messagebox


def main():
    try:
        from mimic.windows_gui import main as launch
        return launch()
    except Exception:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Mimic could not start",
            "Mimic encountered a startup error.\n\n" + traceback.format_exc()[-5000:],
        )
        root.destroy()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

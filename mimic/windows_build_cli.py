from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .ghidra import analyze_binary
from .ollama import OllamaError
from .windows_reconstruct import reconstruct_desktop


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="mimic-desktop-build",
        description="Run native Ghidra static analysis, then reconstruct a Windows desktop UI with local Ollama.",
    )
    parser.add_argument("session_dir", help="capture folder containing session.json and events.jsonl")
    parser.add_argument("-o", "--out", required=True, help="new or empty output project directory")
    parser.add_argument("--binary", help="EXE/DLL to analyze; defaults to the executable path stored by capture")
    parser.add_argument("--ghidra-home", default=os.environ.get("GHIDRA_HOME"),
                        help="Ghidra installation folder containing support/analyzeHeadless.bat")
    parser.add_argument("--model", default=os.environ.get("MIMIC_OLLAMA_MODEL", "qwen2.5-coder:14b"),
                        help="installed local Ollama coding model")
    parser.add_argument("--vision-model", default=os.environ.get("MIMIC_OLLAMA_VISION_MODEL", "qwen2.5vl:7b"),
                        help="installed vision-capable Ollama model for screenshots")
    parser.add_argument("--ollama-url", default=None, help="Ollama base URL; defaults to OLLAMA_HOST or localhost")
    args = parser.parse_args(argv)
    try:
        session_dir = Path(args.session_dir).expanduser().resolve()
        metadata_path = session_dir / "session.json"
        if not metadata_path.is_file():
            raise ValueError("Capture session.json was not found in " + str(session_dir))
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        binary = args.binary or metadata.get("executable_path")
        if not binary:
            raise ValueError("No executable path found. Supply --binary C:\\path\\to\\program.exe")
        reverse_dir = session_dir / "reverse-engineering"
        report = analyze_binary(binary, reverse_dir, ghidra_home=args.ghidra_home)
        files, notes = reconstruct_desktop(
            str(session_dir), args.out, model=args.model, vision_model=args.vision_model,
            base_url=args.ollama_url, static_report=str(reverse_dir / "ghidra-analysis.json"),
        )
    except (OllamaError, ValueError, FileExistsError, OSError) as exc:
        print("Desktop reconstruction failed: " + str(exc), file=sys.stderr)
        return 1
    print("Ghidra analyzed " + str(report.get("analyzed_binary", binary)))
    print("Functions identified: " + str(report.get("function_count", 0)))
    print("Generated " + str(len(files)) + " files in " + args.out)
    for note in notes:
        print("- " + note)
    print("\nReview the generated source, then run:")
    print("  cd " + args.out)
    print("  python -m pip install -r requirements.txt")
    print("  python main.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

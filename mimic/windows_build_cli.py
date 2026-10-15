from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .analyzers import reverse_engineer, summarize_analysis_manifest
from .ghidra import find_ghidra_home
from .ollama import OllamaError
from .windows_reconstruct import reconstruct_desktop


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="mimic-desktop-build",
        description="Run format-aware static analysis, then reconstruct a Windows desktop UI with local Ollama.",
    )
    parser.add_argument("session_dir", help="capture folder containing session.json and events.jsonl")
    parser.add_argument("-o", "--out", required=True, help="new or empty output project directory")
    parser.add_argument("--binary", help="EXE/DLL to analyze; defaults to the executable path stored by capture")
    parser.add_argument("--ghidra-home", default=os.environ.get("GHIDRA_HOME"),
                        help="Ghidra installation folder containing support/analyzeHeadless.bat")
    parser.add_argument("--max-decompile", type=int, default=int(os.environ.get("MIMIC_GHIDRA_MAX_DECOMPILE", "1000")),\n                        help="maximum decompiled functions per primary binary (0-5000; higher takes longer)")\n    parser.add_argument("--model", default=os.environ.get("MIMIC_OLLAMA_MODEL", "qwen2.5-coder:14b"),
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
        report = reverse_engineer(
            binary, str(reverse_dir), ghidra_home=args.ghidra_home or find_ghidra_home(),
            max_decompile=max(0, min(5000, args.max_decompile)),
            on_status=lambda message: print("[mimic] " + str(message), file=sys.stderr, flush=True),
        )
        if report.get("analysis_error"):
            raise RuntimeError(report["analysis_error"])
        manifest_path = reverse_dir / "mimic-analysis-manifest.json"
        try:
            summary = summarize_analysis_manifest(str(manifest_path), model=args.model, base_url=args.ollama_url)
            print("Static analysis report: " + summary["markdown"])
        except (OllamaError, OSError, ValueError) as summary_error:
            print("Static summary unavailable: " + str(summary_error), file=sys.stderr)
        files, notes = reconstruct_desktop(
            str(session_dir), args.out, model=args.model, vision_model=args.vision_model,
            base_url=args.ollama_url, static_report=str(manifest_path),
        )
    except (OllamaError, ValueError, FileExistsError, OSError, RuntimeError) as exc:
        print("Desktop reconstruction failed: " + str(exc), file=sys.stderr)
        return 1
    print("Analysis target: " + str(report.get("target", binary)))
    print("Detected app type: " + str(report.get("detection", {}).get("type")))
    print("Analysis artifacts: " + str(reverse_dir))
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

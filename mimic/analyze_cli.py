"""Run format-aware static analysis and local Ollama summarization."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .analyzers import reverse_engineer, summarize_analysis_manifest
from .ghidra import find_ghidra_home
from .ollama import OllamaError


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="mimic-analyze",
        description="Identify and analyze Windows, native, .NET, Android, Apple, Electron, JVM, Python and source projects with local tools.",
    )
    parser.add_argument("target", help="EXE/DLL, folder, APK/AAB/JAR, IPA, app.asar, source archive, installer, or source project")
    parser.add_argument("-o", "--out", help="new or existing Mimic analysis output folder")
    parser.add_argument("--ghidra-home", default=os.environ.get("GHIDRA_HOME"),
                        help="Ghidra directory containing support/analyzeHeadless.bat")
    parser.add_argument("--model", default=os.environ.get("MIMIC_OLLAMA_MODEL", "qwen2.5-coder:14b"),
                        help="installed local Ollama model for the evidence-based summary")
    parser.add_argument("--ollama-url", default=None, help="local Ollama base URL; defaults to OLLAMA_HOST or localhost")
    parser.add_argument("--no-summary", action="store_true", help="run static analyzers without the Ollama summary")
    args = parser.parse_args(argv)
    target = Path(args.target).expanduser().resolve()
    out = Path(args.out).expanduser().resolve() if args.out else Path.cwd() / (target.stem + "-mimic-analysis")
    if not target.exists():
        parser.error("Target not found: " + str(target))

    try:
        report = reverse_engineer(
            str(target), str(out), ghidra_home=args.ghidra_home or find_ghidra_home(),
            on_status=lambda message: print("[mimic] " + str(message), file=sys.stderr, flush=True),
        )
    except (OSError, ValueError) as exc:
        print("Analysis failed: " + str(exc), file=sys.stderr)
        return 1

    manifest = out / "mimic-analysis-manifest.json"
    print("Detected type: " + str(report.get("detection", {}).get("type")))
    print("Full local artifacts: " + str(out))
    print("Analysis manifest: " + str(manifest))
    for warning in report.get("warnings", []):
        print("WARNING: " + str(warning))

    if not args.no_summary:
        try:
            result = summarize_analysis_manifest(str(manifest), model=args.model, base_url=args.ollama_url)
            print("Ollama report: " + result["markdown"])
            print("Structured summary: " + result["json"])
        except (OllamaError, OSError, ValueError) as exc:
            print("Ollama summary skipped: " + str(exc), file=sys.stderr)
            print("Static artifacts are still saved; start Ollama and rerun without --no-summary to generate the report.")
    print("Review extracted content before using or executing it. Mimic does not run extracted application code.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

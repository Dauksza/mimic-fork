from __future__ import annotations

import argparse
import os
import sys

from .ollama import OllamaError
from .windows_reconstruct import reconstruct_desktop


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="mimic-desktop-build",
        description="Generate a native Windows desktop reconstruction from a Mimic capture using Ollama only.",
    )
    parser.add_argument("session_dir", help="capture folder containing session.json and events.jsonl")
    parser.add_argument("-o", "--out", required=True, help="new or empty output project directory")
    parser.add_argument("--model", default=os.environ.get("MIMIC_OLLAMA_MODEL", "qwen2.5-coder:14b"),
                        help="installed local model used to generate source")
    parser.add_argument("--vision-model", default=os.environ.get("MIMIC_OLLAMA_VISION_MODEL", "qwen2.5vl:7b"),
                        help="installed vision-capable Ollama model used to interpret screenshots")
    parser.add_argument("--ollama-url", default=None, help="Ollama base URL; defaults to OLLAMA_HOST or localhost")
    args = parser.parse_args(argv)
    try:
        files, notes = reconstruct_desktop(
            args.session_dir, args.out, model=args.model,
            vision_model=args.vision_model, base_url=args.ollama_url,
        )
    except (OllamaError, ValueError, FileExistsError, OSError) as exc:
        print("Desktop reconstruction failed: " + str(exc), file=sys.stderr)
        return 1
    print(f"Generated {len(files)} files in {args.out}")
    for note in notes:
        print("- " + note)
    print("\nReview the generated source, then run:")
    print("  cd " + args.out)
    print("  python -m pip install -r requirements.txt")
    print("  python main.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

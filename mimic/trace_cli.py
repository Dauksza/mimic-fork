"""Attach an opt-in Frida metadata trace to a running process."""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from .runtime_trace import RuntimeTrace, RuntimeTraceError


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="mimic-trace",
        description="Record selected file/registry/network destination metadata and module loads for an authorized running process.",
    )
    parser.add_argument("pid", type=int, help="PID of the program you own or are authorized to analyze")
    parser.add_argument("-o", "--out", required=True, help="JSONL output file")
    parser.add_argument("--duration", type=int, default=120, help="trace duration in seconds (default: 120, max: 3600)")
    args = parser.parse_args(argv)
    duration = max(1, min(3600, args.duration))
    output = Path(args.out).expanduser().resolve()
    try:
        trace = RuntimeTrace(args.pid, output, on_status=lambda message: print("[mimic] " + str(message), flush=True)).start()
        print("[mimic] Attached trace requested; use the program normally for " + str(duration) + " seconds.")
        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            print("[mimic] Stopping early…")
        report = trace.stop()
    except (RuntimeTraceError, OSError, ValueError) as exc:
        print("Runtime trace failed: " + str(exc), file=sys.stderr)
        return 1
    print("Trace file: " + str(output))
    print("Events written: " + str(report.get("event_count", 0)))
    if report.get("error"):
        print("Trace error: " + str(report["error"]), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Command-line interface for Spidercrypt repository analysis."""
from __future__ import annotations
import argparse
from pathlib import Path
from .analyzer import analyze_repository, report_json

def main() -> int:
    parser = argparse.ArgumentParser(prog="spidercrypt-scan", description="Analyze a Python repository for common security issues.")
    parser.add_argument("repository", nargs="?", default=".", help="Repository directory")
    parser.add_argument("--json", dest="json_output", help="Write JSON report to this path")
    args = parser.parse_args()
    try:
        report = analyze_repository(args.repository)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    output = report_json(report)
    if args.json_output:
        Path(args.json_output).write_text(output + "\n", encoding="utf-8")
    print(output)
    return 1 if report["summary"]["findings"] else 0

if __name__ == "__main__":
    raise SystemExit(main())
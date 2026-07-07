from __future__ import annotations

import argparse
from pathlib import Path
import sys

from app.source_audit import SourceAuditBlocked, run_source_audit


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan")
    scan.add_argument("--repo", required=True)
    scan.add_argument("--scope", required=True)
    scan.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command != "scan":
        parser.error("unsupported command")

    try:
        result = run_source_audit(args.repo, args.scope)
    except SourceAuditBlocked as error:
        print(f"source audit blocked: {error}", file=sys.stderr)
        return 2

    if args.output:
        Path(args.output).write_text(result.report_markdown, encoding="utf-8")
    else:
        print(result.report_markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

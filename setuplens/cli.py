"""Command line entry point. Nothing here shells out to the scanned repository."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .render import html_report, markdown_report, text_report
from .scanner import MAX_FILES, PRIORITIES, redact, scan


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="setuplens", description="See a repository's setup footprint before you run it. Offline and read-only.")
    parser.add_argument("path", nargs="?", default=".", help="Local repository directory (default: current directory)")
    parser.add_argument("--format", choices=("text", "json", "html", "markdown"), default="text", help="Output format (default: text)")
    parser.add_argument("-o", "--output", type=Path, help="Write report to a new file (stdout by default)")
    parser.add_argument("--force", action="store_true", help="Replace an existing output file; never a scanned setup file")
    parser.add_argument("--exclude", action="append", default=[], help="Skip a directory name or relative glob; repeatable")
    parser.add_argument("--fail-on", choices=("high", "medium", "info"), help="Exit 1 if any finding meets this priority or higher")
    parser.add_argument("--strict", action="store_true", help="Exit 2 if an input cannot be fully inspected (lexical limitation notes excluded)")
    parser.add_argument("--max-files", type=int, default=MAX_FILES, help=f"Maximum supported files to inspect (1–{MAX_FILES})")
    parser.add_argument("--version", action="version", version=f"SetupLens {__version__}")
    args = parser.parse_args(argv)
    if not 1 <= args.max_files <= MAX_FILES:
        parser.error(f"--max-files must be between 1 and {MAX_FILES}")
    try:
        root = Path(args.path).resolve()
        report = scan(root, excludes=tuple(args.exclude), max_files=args.max_files)
        if args.format == "json":
            result = json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"
        elif args.format == "html":
            result = html_report(report)
        elif args.format == "markdown":
            result = markdown_report(report)
        else:
            result = text_report(report)
        if args.output:
            output = args.output.absolute()
            # Check parents too, so a report cannot be redirected through a
            # symlink or Windows junction to overwrite an unrelated file.
            for part in (output, *output.parents):
                if part.is_symlink() or part.exists() and getattr(part.lstat(), "st_file_attributes", 0) & 0x400:
                    raise ValueError("Output must not use a symlink or reparse point.")
            resolved = output.resolve()
            if output.exists() and output.stat().st_nlink > 1:
                raise ValueError("Refusing to overwrite a hard-linked output file.")
            if any(resolved == (root / f).resolve() for f in report.files):
                raise ValueError("Refusing to overwrite a scanned setup file.")
            # Real secret files must never be a report destination either.
            if output.name.lower().startswith(".env"):
                raise ValueError("Refusing to write a report to an environment file.")
            with output.open("w" if args.force else "x", encoding="utf-8", newline="\n") as handle:
                handle.write(result)
            print(f"Report written: {redact(str(output))}", file=sys.stderr)
        else:
            try:
                sys.stdout.write(result)
            except UnicodeEncodeError:
                # Legacy Windows terminals can lack UTF-8; keep the CLI useful.
                sys.stdout.write(result.encode(sys.stdout.encoding or "ascii", errors="backslashreplace").decode(sys.stdout.encoding or "ascii"))
        incomplete = any(not n.startswith(("Compose and workflow inspection", "Compose indirection", "Rust build-script inspection")) for n in report.notes)
        if args.strict and incomplete:
            return 2
        if args.fail_on and any(PRIORITIES[f.priority] <= PRIORITIES[args.fail_on] for f in report.findings):
            return 1
        return 0
    except (OSError, ValueError, RecursionError) as error:
        print(f"setuplens: {redact(str(error))}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

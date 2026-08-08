"""The `pronoia` command: `uv run pronoia doctor` (DESIGN.md §5.4).

Batch jobs stay `python -m ingest.run` / `-m enrich.run` / `-m refdata.run`.
`doctor` gets a short name because it is the one you run interactively, when
something is already wrong.
"""

from __future__ import annotations

import argparse
import sys

from dotenv import load_dotenv


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pronoia", description="pronoia operator commands.")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser(
        "doctor",
        help="resolve LLM/embedding/database config, probe each endpoint, and "
        "print what is enabled, what is degraded, and how to fix it",
    )

    args = parser.parse_args(argv)
    load_dotenv()

    if args.command == "doctor":
        from enrich.doctor import run_doctor

        return run_doctor()

    parser.error(f"unknown command {args.command!r}")  # unreachable; argparse validates
    return 2


if __name__ == "__main__":
    sys.exit(main())

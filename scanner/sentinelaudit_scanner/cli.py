"""Command-line interface for SentinelAudit scanner."""

import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="SentinelAudit web security scanner",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a target URL")
    scan_parser.add_argument("target", help="Target URL to scan (e.g. https://example.com)")
    scan_parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")

    return parser


def handle_scan(args: argparse.Namespace) -> None:
    """Execute a scan against the given target (skeleton for now)."""
    print(f"Scan target: {args.target}")
    print(f"Timeout: {args.timeout}s")
    print("Scanner engine will be invoked here in Phase 1.")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        handle_scan(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

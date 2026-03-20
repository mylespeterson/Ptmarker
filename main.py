"""
main.py

CLI entry point for Ptmarker — scans a folder for Cisco Packet Tracer `.pka`
activity files, extracts the score from each one, and saves all results to a
CSV file.

Usage:
    python main.py /path/to/pka/folder [output.csv]

    If the output CSV path is omitted, results are saved to ``results.csv`` in
    the current working directory.
"""

import argparse
import logging
import sys

from pka_parser import scan_folder
from csv_writer import write_results


def _build_arg_parser():
    """Return the :class:`argparse.ArgumentParser` for the CLI."""
    parser = argparse.ArgumentParser(
        prog="ptmarker",
        description=(
            "Scan a folder for Cisco Packet Tracer .pka activity files, "
            "extract the score from each one, and save all results to a CSV file."
        ),
    )
    parser.add_argument(
        "folder",
        metavar="FOLDER",
        help="Path to the folder containing .pka files (searched recursively).",
    )
    parser.add_argument(
        "output",
        metavar="OUTPUT_CSV",
        nargs="?",
        default="results.csv",
        help="Destination CSV file path (default: results.csv).",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug logging.",
    )
    return parser


def main(argv=None):
    """Entry point for the Ptmarker CLI.

    Args:
        argv: Optional list of command-line arguments (defaults to
            :data:`sys.argv`).

    Returns:
        Exit code integer (0 for success, non-zero for failure).
    """
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    # Configure logging.
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(levelname)s: %(message)s",
    )
    logger = logging.getLogger(__name__)

    # Scan folder.
    try:
        results = scan_folder(args.folder)
    except ValueError as exc:
        logger.error("%s", exc)
        return 1

    if not results:
        logger.info("No .pka files were found in '%s'. Nothing to write.", args.folder)
        return 0

    # Summary statistics.
    total = len(results)
    errors = sum(1 for r in results if r.get("error"))
    logger.info("Found %d .pka file(s); %d parsed successfully, %d with errors.",
                total, total - errors, errors)

    # Write CSV.
    try:
        write_results(results, args.output)
    except OSError as exc:
        logger.error("Failed to write CSV: %s", exc)
        return 1

    print(f"Results written to '{args.output}' ({total} file(s) processed).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

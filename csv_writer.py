"""
csv_writer.py

Logic to write extracted `.pka` score results to a CSV file.
"""

import csv
import logging
import os

logger = logging.getLogger(__name__)

# Column order for the output CSV.
FIELDNAMES = ["filename", "score", "max_score", "percentage", "user_profile_name"]


def write_results(results, output_path):
    """Write a list of parsed `.pka` result dicts to a CSV file.

    Each dict in *results* is expected to contain the keys defined in
    :data:`FIELDNAMES` (``filename``, ``score``, ``max_score``,
    ``percentage``, ``user_profile_name``).  Any extra keys (e.g. ``error``)
    are silently ignored in the CSV output.

    Args:
        results: A list of dicts as returned by
            :func:`pka_parser.parse_pka_file`.
        output_path: Destination file path (str) for the CSV.  Parent
            directories must already exist.

    Returns:
        None

    Raises:
        OSError: If the file cannot be written (permissions, missing parent
            directory, etc.).
    """
    if not results:
        logger.warning("No results to write — CSV file will not be created.")
        return

    output_path = os.path.abspath(output_path)
    logger.info("Writing %d result(s) to '%s' …", len(results), output_path)

    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)

    logger.info("CSV written successfully.")

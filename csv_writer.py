"""
csv_writer.py

Logic to write extracted `.pka` score results to a CSV file, plus an
optional detailed-feedback file listing every incorrect assessment item.
"""

import csv
import logging
import os

logger = logging.getLogger(__name__)

# Column order for the summary CSV.
FIELDNAMES = ["filename", "score", "max_score", "percentage", "user_profile_name"]

# Column order for the per-item feedback CSV.
FEEDBACK_FIELDNAMES = [
    "Student File",
    "Student Name",
    "Score",
    "Max Score",
    "Percentage",
    "Device",
    "Property",
    "Expected Configuration",
    "Student Configuration",
    "Item Points",
]


def write_results(results, output_path):
    """Write a list of parsed `.pka` result dicts to a CSV file.

    Each dict in *results* is expected to contain the keys defined in
    :data:`FIELDNAMES` (``filename``, ``score``, ``max_score``,
    ``percentage``, ``user_profile_name``).  Any extra keys (e.g. ``error``)
    are silently ignored in the CSV output.

    If any result contains a ``feedback`` list (per-item details on incorrect
    assessment items), a second CSV file is written alongside the summary file
    with a ``_feedback`` suffix (e.g. ``results_feedback.csv``).

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

    # --- Feedback detail file ------------------------------------------------
    _write_feedback(results, output_path)


def _write_feedback(results, summary_path):
    """Write a separate feedback CSV listing every incorrect assessment item.

    The file is created next to the summary CSV with a ``_feedback`` suffix.
    If no results contain feedback data, the file is not created.
    """
    # Build feedback rows.
    feedback_rows = []
    for r in results:
        items = r.get("feedback")
        if not items:
            continue
        for fb in items:
            feedback_rows.append({
                "Student File": r.get("filename", ""),
                "Student Name": r.get("user_profile_name", ""),
                "Score": r.get("score", ""),
                "Max Score": r.get("max_score", ""),
                "Percentage": r.get("percentage", ""),
                "Device": fb.get("device", ""),
                "Property": fb.get("property", ""),
                "Expected Configuration": fb.get("expected", ""),
                "Student Configuration": fb.get("student", ""),
                "Item Points": fb.get("points", ""),
            })

    if not feedback_rows:
        return

    # Derive the feedback file path from the summary path.
    base, ext = os.path.splitext(summary_path)
    feedback_path = f"{base}_feedback{ext}"

    logger.info("Writing %d feedback row(s) to '%s' …",
                len(feedback_rows), feedback_path)

    with open(feedback_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=FEEDBACK_FIELDNAMES)
        writer.writeheader()
        writer.writerows(feedback_rows)

    logger.info("Feedback CSV written successfully.")

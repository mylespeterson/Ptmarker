"""
pka_parser.py

Logic to unzip .pka Cisco Packet Tracer activity files, parse the embedded XML,
and extract the score, max score, and user profile name.
"""

import io
import logging
import zipfile
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

# XML tag names to search for score/max-score/user data.
# Packet Tracer .pka archives embed an XML document whose schema varies slightly
# across Packet Tracer versions.  We search for the most common variants.
_SCORE_TAGS = ("SCORE", "Score", "score")
_MAX_SCORE_TAGS = ("MAXSCORE", "MaxScore", "maxScore", "MAX_SCORE", "TOTALSCORE", "TotalScore")
_PERCENTAGE_TAGS = ("PERCENTAGE", "Percentage", "percentage")
_PROFILE_TAGS = ("USERPROFILENAME", "UserProfileName", "userProfileName",
                 "USER_PROFILE_NAME", "PROFILE", "Profile", "profile",
                 "USERNAME", "UserName", "userName")

# XML file names that are most likely to contain scoring data inside the archive.
_PREFERRED_XML_FILES = ("default.xml", "activity.xml", "scoring.xml")

# Standard ZIP local-file-header signature.
_ZIP_SIGNATURE = b"PK\x03\x04"


def _open_pka_as_zip(filepath):
    """Open a `.pka` file and return a :class:`zipfile.ZipFile`.

    Packet Tracer `.pka` files are ZIP archives, but some versions prepend a
    proprietary binary header before the ZIP data.  This helper first tries to
    open the file directly; if that fails it scans for the ZIP local-file-header
    signature (``PK\\x03\\x04``) and retries from that offset.

    Args:
        filepath: Path (str) to the `.pka` file.

    Returns:
        A :class:`zipfile.ZipFile` opened for reading.  The caller is
        responsible for closing it.

    Raises:
        zipfile.BadZipFile: If no valid ZIP data can be found in the file.
    """
    # Fast path: try opening directly — works for standard ZIP-based PKA files.
    try:
        return zipfile.ZipFile(filepath, "r")
    except zipfile.BadZipFile:
        pass

    # Slow path: read raw bytes, locate the ZIP signature, and retry.
    with open(filepath, "rb") as fh:
        raw = fh.read()

    offset = raw.find(_ZIP_SIGNATURE)
    if offset < 0:
        raise zipfile.BadZipFile("Not a valid ZIP/PKA archive")

    logger.debug("Found ZIP signature at byte offset %d in %s", offset, filepath)
    return zipfile.ZipFile(io.BytesIO(raw[offset:]), "r")


def _find_text(element, tag_names):
    """Return the text of the first child element whose tag matches any of *tag_names*.

    Searches recursively through *element* and all of its descendants.

    Args:
        element: An :class:`xml.etree.ElementTree.Element` to search.
        tag_names: An iterable of tag-name strings to look for.

    Returns:
        The stripped text string, or ``None`` if no matching element is found.
    """
    for tag in tag_names:
        found = element.find(".//" + tag)
        if found is not None and found.text:
            return found.text.strip()
    return None


def _find_attr(element, tag_names, attr_names):
    """Return an attribute value from the first element matching any of *tag_names*.

    Args:
        element: An :class:`xml.etree.ElementTree.Element` to search.
        tag_names: An iterable of tag-name strings.
        attr_names: An iterable of attribute names to check on matching elements.

    Returns:
        The attribute value string, or ``None`` if nothing is found.
    """
    for tag in tag_names:
        for el in element.iter(tag):
            for attr in attr_names:
                value = el.get(attr)
                if value:
                    return value.strip()
    return None


def _parse_xml_for_scores(xml_bytes):
    """Parse XML bytes and attempt to extract score, max_score, and user_profile_name.

    Args:
        xml_bytes: Raw bytes of an XML document.

    Returns:
        A dict with keys ``score``, ``max_score``, ``user_profile_name``; any
        value that cannot be found will be ``None``.

    Raises:
        ET.ParseError: If the bytes are not valid XML.
    """
    root = ET.fromstring(xml_bytes)

    result = {
        "score": None,
        "max_score": None,
        "user_profile_name": None,
    }

    # --- Score ---
    # Try element text first, then attributes.
    score_text = _find_text(root, _SCORE_TAGS)
    if score_text is None:
        score_text = _find_attr(root, _SCORE_TAGS, ("value", "val", "points"))
    result["score"] = score_text

    # --- Max Score ---
    max_score_text = _find_text(root, _MAX_SCORE_TAGS)
    if max_score_text is None:
        max_score_text = _find_attr(root, _MAX_SCORE_TAGS, ("value", "val", "points"))
    # Also check for a <SCORING maxPoints="…"> attribute pattern.
    if max_score_text is None:
        scoring_el = root.find(".//SCORING")
        if scoring_el is None:
            scoring_el = root.find(".//Scoring")
        if scoring_el is not None:
            for attr in ("maxPoints", "maxScore", "totalPoints", "total"):
                val = scoring_el.get(attr)
                if val:
                    max_score_text = val.strip()
                    break
    result["max_score"] = max_score_text

    # --- Score from SCORING element attributes (common Packet Tracer pattern) ---
    if result["score"] is None:
        scoring_el = root.find(".//SCORING")
        if scoring_el is None:
            scoring_el = root.find(".//Scoring")
        if scoring_el is not None:
            for attr in ("earnedPoints", "score", "points", "earned"):
                val = scoring_el.get(attr)
                if val:
                    result["score"] = val.strip()
                    break

    # --- Percentage fallback (derive score/max from PERCENTAGE element) ---
    if result["score"] is None or result["max_score"] is None:
        pct_text = _find_text(root, _PERCENTAGE_TAGS)
        if pct_text is None:
            pct_text = _find_attr(root, _PERCENTAGE_TAGS, ("value", "val"))
        if pct_text:
            # Store the raw percentage so the caller can use it even without
            # separate score/max values.
            result["_percentage_raw"] = pct_text.rstrip("%").strip()

    # --- User Profile Name ---
    profile_text = _find_text(root, _PROFILE_TAGS)
    if profile_text is None:
        profile_text = _find_attr(root, _PROFILE_TAGS, ("name", "value", "val"))
    result["user_profile_name"] = profile_text

    return result


def parse_pka_file(filepath):
    """Extract scoring data from a single `.pka` file.

    A `.pka` file is a ZIP archive containing one or more XML files.  This
    function opens the archive, searches for the XML file most likely to contain
    scoring data, parses it, and returns the extracted values.

    Args:
        filepath: Path (str) to the `.pka` file.

    Returns:
        A dict with the following keys:

        * ``filename``         — base name of the `.pka` file
        * ``score``            — numeric score as a string, or ``"N/A"``
        * ``max_score``        — numeric max score as a string, or ``"N/A"``
        * ``percentage``       — formatted percentage string (e.g. ``"80.0%"``), or ``"N/A"``
        * ``user_profile_name``— student/user name, or ``"N/A"``
        * ``error``            — error message string if parsing failed, else ``None``

    Raises:
        Nothing — all exceptions are caught and reflected in the ``error`` key.
    """
    import os

    filename = os.path.basename(filepath)
    base_result = {
        "filename": filename,
        "score": "N/A",
        "max_score": "N/A",
        "percentage": "N/A",
        "user_profile_name": "N/A",
        "error": None,
    }

    try:
        with _open_pka_as_zip(filepath) as zf:
            names = zf.namelist()
            logger.debug("%s contains entries: %s", filename, names)

            # Build an ordered list of XML entries to try: preferred names first,
            # then any remaining .xml files in the archive.
            xml_entries = []
            for preferred in _PREFERRED_XML_FILES:
                matches = [n for n in names if n.lower().endswith("/" + preferred) or n.lower() == preferred]
                xml_entries.extend(matches)
            # Add all other .xml files not already in the list.
            for name in names:
                if name.lower().endswith(".xml") and name not in xml_entries:
                    xml_entries.append(name)

            if not xml_entries:
                logger.warning("%s: no XML entries found inside archive.", filename)
                base_result["error"] = "No XML content found in archive"
                return base_result

            parsed = None
            for entry in xml_entries:
                try:
                    xml_bytes = zf.read(entry)
                    parsed = _parse_xml_for_scores(xml_bytes)
                    logger.debug("%s/%s parsed OK", filename, entry)
                    # If we found both score and max_score we can stop here.
                    if parsed.get("score") and parsed.get("max_score"):
                        break
                except ET.ParseError as exc:
                    logger.debug("%s/%s is not valid XML: %s", filename, entry, exc)
                    continue

            if parsed is None:
                logger.warning("%s: could not parse any XML entries.", filename)
                base_result["error"] = "Could not parse XML content"
                return base_result

            score_str = parsed.get("score")
            max_str = parsed.get("max_score")
            profile = parsed.get("user_profile_name") or "N/A"

            base_result["user_profile_name"] = profile

            # Calculate percentage.
            if score_str and max_str:
                try:
                    score_val = float(score_str)
                    max_val = float(max_str)
                    if max_val > 0:
                        pct = (score_val / max_val) * 100.0
                        base_result["score"] = score_str
                        base_result["max_score"] = max_str
                        base_result["percentage"] = f"{pct:.1f}%"
                    else:
                        base_result["score"] = score_str
                        base_result["max_score"] = max_str
                        base_result["percentage"] = "N/A"
                except ValueError:
                    logger.warning("%s: non-numeric score/max_score values ('%s'/'%s').",
                                   filename, score_str, max_str)
                    base_result["score"] = score_str
                    base_result["max_score"] = max_str
            elif "_percentage_raw" in parsed and parsed["_percentage_raw"]:
                # We only have a raw percentage; store it directly.
                base_result["percentage"] = parsed["_percentage_raw"] + "%"
            else:
                logger.warning("%s: scoring data not found in XML.", filename)
                base_result["error"] = "Scoring data not found"

            return base_result

    except zipfile.BadZipFile:
        logger.warning("%s: not a valid ZIP/PKA archive.", filename)
        base_result["error"] = "Not a valid ZIP archive"
        return base_result
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning("%s: unexpected error: %s", filename, exc)
        base_result["error"] = str(exc)
        return base_result


def scan_folder(folder_path):
    """Scan *folder_path* recursively for `.pka` files and parse each one.

    Args:
        folder_path: Path (str) to a directory to scan.

    Returns:
        A list of result dicts as returned by :func:`parse_pka_file`.

    Raises:
        ValueError: If *folder_path* is not a valid directory.
    """
    import os

    if not os.path.isdir(folder_path):
        raise ValueError(f"'{folder_path}' is not a valid directory.")

    results = []
    for dirpath, _dirnames, filenames in os.walk(folder_path):
        for fname in filenames:
            if fname.lower().endswith(".pka"):
                full_path = os.path.join(dirpath, fname)
                logger.info("Parsing %s …", full_path)
                results.append(parse_pka_file(full_path))

    if not results:
        logger.info("No .pka files found in '%s'.", folder_path)

    return results

"""
pka_parser.py

Logic to open .pka Cisco Packet Tracer activity files (ZIP-based or encrypted),
parse the embedded XML, and extract the score, max score, and user profile name.
"""

import io
import logging
import re
import zipfile
import xml.etree.ElementTree as ET

from pt_decrypt import decrypt_pka

logger = logging.getLogger(__name__)

# Regex that matches characters illegal in XML 1.0.  Valid chars are:
#   #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
_ILLEGAL_XML_RE = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x84\x86-\x9f"
    "\ud800-\udfff\ufdd0-\ufddf\ufffe\uffff]"
)

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


def _tally_comparison_points(comparisons_el):
    """Walk the ``<COMPARISONS>`` verification tree and tally leaf-node points.

    In Packet Tracer 7.x+ encrypted PKA files, scoring is represented as a
    tree of ``<NODE>`` elements.  Leaf nodes (those without child ``<NODE>``
    elements) carry a ``<POINTS>`` value of ``0`` (failed) or ``1`` (passed).
    Parent nodes aggregate their children.

    Args:
        comparisons_el: An :class:`~xml.etree.ElementTree.Element` for the
            ``<COMPARISONS>`` tag.

    Returns:
        A tuple ``(earned, total)`` of integers.
    """

    def _walk(node):
        children = node.findall("NODE")
        if not children:
            # Leaf node — count it.
            points_el = node.find("POINTS")
            if points_el is not None and points_el.text and points_el.text.strip().isdigit():
                return int(points_el.text.strip()), 1
            return 0, 0
        earned = 0
        total = 0
        for child in children:
            e, t = _walk(child)
            earned += e
            total += t
        return earned, total

    earned = 0
    total = 0
    for top_node in comparisons_el.findall("NODE"):
        e, t = _walk(top_node)
        earned += e
        total += t
    return earned, total


def _get_device_configs(pt5_element):
    """Extract running-config lines for every device inside a ``<PACKETTRACER5>`` element.

    Args:
        pt5_element: An :class:`~xml.etree.ElementTree.Element` for a
            ``<PACKETTRACER5>`` tag.

    Returns:
        A dict mapping device name (str) to a list of stripped config-line
        strings.
    """
    configs = {}
    for device in pt5_element.findall(".//DEVICE"):
        engine = device.find("ENGINE")
        if engine is None:
            continue
        name_el = engine.find("NAME")
        if name_el is None or not name_el.text:
            continue
        rc = engine.find("RUNNINGCONFIG")
        if rc is not None:
            lines = []
            for line_el in rc.findall("LINE"):
                if line_el.text:
                    lines.append(line_el.text.strip())
            configs[name_el.text] = lines
    return configs


def _score_by_config_comparison(root):
    """Compare student and answer running-configs to compute the score.

    Encrypted PKA files with three ``<PACKETTRACER5>`` elements store:

    * ``PT5[0]`` — the student's current network state,
    * ``PT5[1]`` — the initial (starter) network state,
    * ``PT5[2]`` — the answer-key network state.

    Scoring counts only the config lines that the student needed to *add*
    relative to the initial state.  Lines already present in the starter
    network are not counted because they do not represent student work.
    Multiplicity is preserved using :class:`collections.Counter` so that
    duplicate lines (e.g. ``shutdown`` on multiple interfaces) are scored
    individually.

    Args:
        root: The parsed XML root element.

    Returns:
        A tuple ``(earned, total)`` of integers, or ``None`` if the
        comparison cannot be performed (e.g. fewer than three
        ``PACKETTRACER5`` elements or no configs found).
    """
    from collections import Counter

    pt5_elements = root.findall("PACKETTRACER5")
    if len(pt5_elements) < 3:
        return None

    student_configs = _get_device_configs(pt5_elements[0])
    initial_configs = _get_device_configs(pt5_elements[1])
    answer_configs = _get_device_configs(pt5_elements[2])

    if not answer_configs:
        return None

    total = 0
    earned = 0
    for device_name, answer_lines in answer_configs.items():
        sig_answer = [l for l in answer_lines if l and l != "!"]
        sig_initial = [l for l in initial_configs.get(device_name, [])
                       if l and l != "!"]
        sig_student = [l for l in student_configs.get(device_name, [])
                       if l and l != "!"]

        # Lines the student needed to add (answer minus initial).
        required = Counter(sig_answer) - Counter(sig_initial)
        # Lines the student actually has that match required items.
        matched = required & Counter(sig_student)

        total += sum(required.values())
        earned += sum(matched.values())

    return (earned, total) if total > 0 else None


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

    # --- Running-config comparison (Packet Tracer 7.x+ encrypted format) ---
    # Encrypted PKA files typically contain three <PACKETTRACER5> elements:
    # [0] student work, [1] initial state, [2] answer key.  The most accurate
    # scoring method compares the student's device running-configs against
    # the answer-key configs.  The COMPARISONS tree is a static template that
    # does not reflect student-specific results, so config comparison takes
    # priority.  Both score and max_score are set together to keep them
    # consistent.
    if result["score"] is None and result["max_score"] is None:
        config_result = _score_by_config_comparison(root)
        if config_result is not None:
            earned, total = config_result
            result["score"] = str(earned)
            result["max_score"] = str(total)

    # --- COMPARISONS tree fallback (Packet Tracer 7.x+ encrypted format) ---
    # If config comparison is not available (e.g. fewer than three
    # PACKETTRACER5 elements), fall back to the COMPARISONS verification tree.
    if result["score"] is None and result["max_score"] is None:
        comparisons = root.find(".//COMPARISONS")
        if comparisons is not None:
            earned, total = _tally_comparison_points(comparisons)
            if total > 0:
                result["score"] = str(earned)
                result["max_score"] = str(total)

    # --- User Profile Name ---
    profile_text = _find_text(root, _PROFILE_TAGS)
    if profile_text is None:
        profile_text = _find_attr(root, _PROFILE_TAGS, ("name", "value", "val"))
    # In encrypted PKA files, the student's name is often stored in a
    # <USER_PROFILE><NAME>…</NAME></USER_PROFILE> element inside the first
    # (student) PACKETTRACER5 block.  Prefer a non-"Guest" name.
    if profile_text is None:
        for up in root.iter("USER_PROFILE"):
            name_el = up.find("NAME")
            if name_el is not None and name_el.text:
                candidate = name_el.text.strip()
                if candidate and candidate != "Guest":
                    profile_text = candidate
                    break
    result["user_profile_name"] = profile_text

    return result


def _apply_parsed_scores(base_result, parsed, filename):
    """Populate *base_result* from a *parsed* scores dict.

    Shared helper used by both the ZIP path and the encrypted-decryption path
    so score/percentage calculation logic is not duplicated.
    """
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


def _parse_zip_pka(filepath, filename, base_result):
    """Try to open *filepath* as a ZIP-based PKA and extract scores.

    Returns ``True`` if the file was successfully opened as a ZIP archive
    (even if no scores were found inside it), ``False`` if the file is not
    a valid ZIP and a different strategy should be attempted.
    """
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
                return True

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
                return True

            _apply_parsed_scores(base_result, parsed, filename)
            return True

    except zipfile.BadZipFile:
        return False


def _parse_encrypted_pka(filepath, filename, base_result):
    """Try to decrypt *filepath* as an encrypted PKA and extract scores.

    Returns ``True`` if decryption succeeded, ``False`` otherwise.
    """
    try:
        with open(filepath, "rb") as fh:
            raw = fh.read()

        xml_bytes = decrypt_pka(raw)
        logger.debug("%s: decrypted encrypted PKA (%d bytes of XML).",
                     filename, len(xml_bytes))

        # Encrypted PKA XML may contain binary data in attribute values
        # (e.g. hashed passwords) that include control characters illegal in
        # XML 1.0.  Decode as latin-1 (lossless for all byte values) and
        # strip those characters so the XML parser can handle the document.
        xml_text = xml_bytes.decode("latin-1")
        xml_text = _ILLEGAL_XML_RE.sub("", xml_text)
        xml_bytes = xml_text.encode("utf-8")

        try:
            parsed = _parse_xml_for_scores(xml_bytes)
        except ET.ParseError as exc:
            logger.warning("%s: decrypted content is not valid XML: %s", filename, exc)
            base_result["error"] = "Decrypted content is not valid XML"
            return True

        _apply_parsed_scores(base_result, parsed, filename)
        return True

    except (ValueError, OSError) as exc:
        logger.debug("%s: encrypted-PKA decryption failed: %s", filename, exc)
        return False


def parse_pka_file(filepath):
    """Extract scoring data from a single `.pka` file.

    A `.pka` file is either a ZIP archive containing XML, or an encrypted
    Packet Tracer file that decrypts to XML.  This function tries both
    strategies and returns the extracted values.

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
        # Strategy 1: try opening as a ZIP archive (standard or header-prefixed).
        if _parse_zip_pka(filepath, filename, base_result):
            return base_result

        # Strategy 2: try decrypting as an encrypted PKA file.
        if _parse_encrypted_pka(filepath, filename, base_result):
            return base_result

        # Neither strategy worked.
        logger.warning("%s: not a valid ZIP or encrypted PKA archive.", filename)
        base_result["error"] = "Not a valid ZIP or encrypted PKA archive"
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

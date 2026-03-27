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

    This is a broad heuristic used as a fallback when property-level
    evaluation is not available (e.g. the COMPARISONS tree has no
    ``checkType="2"`` assessment items).

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


def _score_by_property_evaluation(root):
    """Evaluate student work against the COMPARISONS marking-tree properties.

    Encrypted PKA files with three ``<PACKETTRACER5>`` elements store:

    * ``PT5[0]`` — the student's current network state,
    * ``PT5[1]`` — the initial (starter) network state,
    * ``PT5[2]`` — the answer-key network state.

    The ``<COMPARISONS>`` tree contains ``checkType="2"`` leaf nodes that
    represent instructor-graded assessment items.  Each item specifies a
    device property (e.g. SSH Version, Enable Secret) with an expected
    ``nodeValue``.  This function evaluates each item against the student's
    running-config and structured device data to produce an exact score.

    For property types that have a dedicated evaluator the result is exact.
    For unrecognised property types a generic answer-key comparison is
    attempted: the answer-key config is searched for lines containing the
    expected ``nodeValue``, and those lines are checked against the student
    config.  This allows the scorer to handle *any* PKA file regardless of
    which property types it checks.

    Args:
        root: The parsed XML root element.

    Returns:
        A tuple ``(earned, total, feedback)`` where *earned* and *total* are
        integers and *feedback* is a list of dicts (one per incorrect item)
        with keys ``device``, ``property``, ``expected``, ``student``, and
        ``points``.  Returns ``None`` if the evaluation cannot be performed.
    """
    comparisons = root.find(".//COMPARISONS")
    if comparisons is None:
        return None

    pt5_elements = root.findall("PACKETTRACER5")
    if len(pt5_elements) < 1:
        return None

    ct2_items = _extract_ct2_items(comparisons)
    if not ct2_items:
        return None

    student_configs = _get_device_configs(pt5_elements[0])

    # Answer-key and initial-state configs are used by the generic fallback
    # evaluator when a specific evaluator is not available.
    answer_configs = (
        _get_device_configs(pt5_elements[2]) if len(pt5_elements) >= 3
        else {}
    )
    initial_configs = (
        _get_device_configs(pt5_elements[1]) if len(pt5_elements) >= 3
        else {}
    )

    earned = 0
    total_points = 0
    generic_used = 0
    unevaluated = 0
    feedback = []
    for item in ct2_items:
        dev = item["device"]
        weight = item.get("points", 1)
        total_points += weight
        config_lines = student_configs.get(dev, [])
        config_set = set(l.strip() for l in config_lines if l)
        sections = _parse_config_sections(config_lines)
        engine = _find_device_engine(pt5_elements[0], dev)

        result = _evaluate_ct2_item(item, config_lines, config_set, sections,
                                    engine)

        if result is None:
            # No dedicated evaluator — try the generic answer-key comparison.
            answer_lines = answer_configs.get(dev, [])
            initial_lines = initial_configs.get(dev, [])
            answer_sections = _parse_config_sections(answer_lines)
            result = _evaluate_ct2_item_generic(
                item, config_lines, config_set, sections,
                answer_lines, initial_lines, answer_sections)
            if result is not None:
                generic_used += 1
            else:
                unevaluated += 1

        if result is True:
            earned += weight
        else:
            # Collect feedback for incorrect / unevaluated items.
            answer_lines = answer_configs.get(dev, [])
            answer_sections = _parse_config_sections(answer_lines)
            expected_desc = _describe_expected(item, answer_lines,
                                               answer_sections)
            student_desc = _describe_student(item, config_lines, config_set,
                                             sections, engine)
            prop_path = "/".join(item["path"])
            feedback.append({
                "device": dev,
                "property": prop_path,
                "expected": expected_desc,
                "student": student_desc,
                "points": weight,
            })

    if generic_used > 0 or unevaluated > 0:
        logger.debug(
            "Property evaluation: %d/%d items used generic matching, "
            "%d could not be evaluated",
            generic_used, unevaluated, len(ct2_items))

    return (earned, total_points, feedback)


def _extract_ct2_items(comparisons_el):
    """Extract all ``checkType="2"`` leaf items from a COMPARISONS tree.

    Returns a list of dicts, each with keys ``name``, ``id``,
    ``nodeValue``, ``device``, ``path``, ``path_ids``, and ``points``.
    Items may be worth more than 1 point (``points`` reflects the weight).
    """
    items = []

    def _walk(node, ancestors=()):
        name_el = node.find("NAME")
        if name_el is None:
            return
        name = (name_el.text or "").strip()
        check_type = name_el.get("checkType", "")
        node_value = name_el.get("nodeValue", "")
        id_el = node.find("ID")
        item_id = (id_el.text.strip()
                   if id_el is not None and id_el.text else "")
        pts_el = node.find("POINTS")
        pts = (pts_el.text.strip()
               if pts_el is not None and pts_el.text else "")
        children = node.findall("NODE")
        current = ancestors + ((name, item_id),)

        if check_type == "2" and not children:
            try:
                weight = int(pts)
            except (ValueError, TypeError):
                weight = 0
            if weight > 0:
                items.append({
                    "name": name,
                    "id": item_id,
                    "nodeValue": node_value,
                    "device": current[1][0] if len(current) > 1 else "",
                    "path": [a[0] for a in current[2:]],
                    "path_ids": [a[1] for a in current[2:]],
                    "points": weight,
                })
        for child in children:
            _walk(child, current)

    for top_node in comparisons_el.findall("NODE"):
        _walk(top_node)
    return items


def _find_device_engine(pt5_el, device_name):
    """Locate and return the ENGINE element for *device_name*."""
    for device in pt5_el.findall(".//DEVICE"):
        engine = device.find("ENGINE")
        if engine is None:
            continue
        name_el = engine.find("NAME")
        if (name_el is not None and name_el.text
                and name_el.text.strip() == device_name):
            return engine
    return None


# ---- Running-config section parser ------------------------------------------

_SECTION_PREFIXES = (
    "line ", "interface ", "router ", "ip access-list ",
    "zone ", "zone-pair ", "class-map ", "policy-map ",
    "radius ", "crypto ", "aaa ",
)


def _parse_config_sections(config_lines):
    """Parse running-config lines into hierarchical sections.

    Returns a dict with:

    * ``con_lines``   — sub-commands under ``line con 0``
    * ``vty_ranges``  — list of ``(start, end, [lines])`` for VTY ranges
    * ``interfaces``  — dict mapping interface name → sub-command list
    * ``sections``    — dict mapping section header → sub-command list
    """
    result = {
        "con_lines": [],
        "vty_ranges": [],
        "interfaces": {},
        "sections": {},
    }
    current_section = None
    current_lines = []  # type: list[str]

    def _close(sec, lines):
        if sec is None:
            return
        result["sections"][sec] = lines
        if sec.startswith("line vty "):
            parts = sec.split()
            if len(parts) >= 4:
                try:
                    result["vty_ranges"].append(
                        (int(parts[2]), int(parts[3]), lines))
                except ValueError:
                    pass
        elif sec.startswith("line con"):
            result["con_lines"] = lines
        elif sec.startswith("interface "):
            result["interfaces"][sec[len("interface "):]] = lines

    for line in config_lines:
        stripped = line.strip()
        if not stripped or stripped == "!":
            if current_section:
                _close(current_section, current_lines)
                current_section = None
                current_lines = []
            continue

        is_header = any(stripped.startswith(p) for p in _SECTION_PREFIXES)
        if is_header:
            _close(current_section, current_lines)
            current_section = stripped
            current_lines = []
        elif current_section:
            current_lines.append(stripped)

    _close(current_section, current_lines)
    return result


def _get_vty_section_lines(sections, vty_num):
    """Return the sub-command list for the VTY range containing *vty_num*."""
    for start, end, lines in sections["vty_ranges"]:
        if start <= vty_num <= end:
            return lines
    return []


# ---- Individual property evaluators -----------------------------------------

def _evaluate_ct2_item(item, config_lines, config_set, sections,
                       engine=None):
    """Return ``True`` if the student satisfies a single checkType=2 item."""
    nv = item["nodeValue"].strip()
    item_id = item["id"]
    path = item["path"]
    path_str = " ".join(path)

    # --- Global IOS properties (checked against flat config set) ----------

    if item_id == "Enable Secret":
        return f"enable secret 5 {nv}" in config_set

    if item_id == "Service Password Encryption":
        return "service password-encryption" in config_set

    if item_id == "IP Domain Name":
        return f"ip domain-name {nv}" in config_set

    if item_id == "SSH Server Version":
        return f"ip ssh version {nv}" in config_set

    if item_id == "SSH Server Authentication-retries":
        return f"ip ssh authentication-retries {nv}" in config_set

    if item_id == "SSH Server Timeout":
        return f"ip ssh time-out {nv}" in config_set

    if item_id == "Security Password Min-Length":
        return f"security passwords min-length {nv}" in config_set

    if item_id == "Service timestamp log":
        return "service timestamps log datetime msec" in config_set

    # --- AAA ---------------------------------------------------------------

    if item_id == "New-model" and "AAA" in path:
        return "aaa new-model" in config_set

    if ("AAA" in path and "Authentication" in path
            and "Authen Command" in path_str):
        return nv.strip() in config_set

    # --- Login options -----------------------------------------------------

    if item_id == "Login On Success":
        return "login on-success log" in config_set

    if item_id == "Login On Failure":
        return "login on-failure log" in config_set

    if item_id == "Duration" and "Blocking" in path:
        return any(f"login block-for {nv}" in l for l in config_lines)

    if item_id == "Attempts" and "Blocking" in path:
        return any(f"attempts {nv} within" in l for l in config_lines)

    if item_id == "Period" and "Blocking" in path:
        return any(f"within {nv}" in l for l in config_lines)

    # --- Security / crypto -------------------------------------------------

    if item_id == "Modulus Bits":
        if engine is not None:
            sec_el = engine.find("SECURITY")
            if sec_el is not None:
                mb = sec_el.find("MODULUS_BITS")
                if mb is not None and mb.text:
                    return mb.text.strip() == nv
        return False

    # --- NTP ---------------------------------------------------------------

    if item_id == "Address0" and "NTP" in path:
        # NTP server address; the config line may have extra options
        # like ``key 1`` after the address.
        return any(l.strip().startswith(f"ntp server {nv}")
                   for l in config_lines)

    if (item_id == "Password" and "NTP" in path
            and "Authentication Keys" in path):
        key_num = None
        for p in path:
            if p.startswith("Key "):
                key_num = p.split(" ", 1)[1]
                break
        if key_num:
            return any(f"ntp authentication-key {key_num} md5" in l
                       for l in config_lines)
        return False

    # --- SYSLOG ------------------------------------------------------------

    if item_id == "Address" and "SYSLOG" in path_str:
        return f"logging {nv}" in config_set

    # --- Console / VTY line properties (section-aware) ---------------------

    if item_id == "AAA Method List Name":
        target = f"login authentication {nv}"
        if "Console" in path_str:
            return target in sections["con_lines"]
        if "VTY" in path_str:
            vn = _vty_num_from_path(path)
            if vn is not None:
                return target in _get_vty_section_lines(sections, vn)
        return target in config_set

    if item_id == "Transport Input":
        if nv == "2":  # 2 → SSH
            target = "transport input ssh"
            if "VTY" in path_str:
                vn = _vty_num_from_path(path)
                if vn is not None:
                    return target in _get_vty_section_lines(sections, vn)
            return target in config_set
        return False

    if item_id == "Login" and ("VTY" in path_str or "Console" in path_str):
        if nv == "2":  # 2 → login local
            target = "login local"
            if "Console" in path_str:
                return target in sections["con_lines"]
            if "VTY" in path_str:
                vn = _vty_num_from_path(path)
                if vn is not None:
                    return target in _get_vty_section_lines(sections, vn)
            return target in config_set
        return False

    # --- Usernames ---------------------------------------------------------

    if "User Names" in path:
        parts = nv.split(" ", 1)
        if len(parts) == 2:
            uname, secret_hash = parts
            # Username line may include ``privilege N`` before ``secret``.
            # The secret type may be 5 (MD5), 9 (scrypt), or others.
            prefix = f"username {uname} "
            for line in config_lines:
                s = line.strip()
                if s.startswith(prefix) and secret_hash in s:
                    return True
        return False

    # --- VTY Access Class In -----------------------------------------------

    if item_id == "Access Class In" and "VTY" in path_str:
        vn = _vty_num_from_path(path)
        if vn is not None:
            vty_lines = _get_vty_section_lines(sections, vn)
            return any(f"access-class {nv} in" in l for l in vty_lines)
        return any(f"access-class {nv} in" in l for l in config_lines)

    # --- ACLs --------------------------------------------------------------

    if "ACL" in path and len(path) <= 2:
        # nodeValue may contain multiple ACE lines separated by newlines.
        ace_lines = [l.strip() for l in nv.split('\n') if l.strip()]
        if not ace_lines:
            return False
        for ace in ace_lines:
            # Named ACLs store ACEs as sub-commands (no prefix).
            if ace in config_set:
                continue
            # Numbered ACLs store ACEs as "access-list <number> <ace>".
            if f"access-list {item_id} {ace}" in config_set:
                continue
            return False
        return True

    # --- OSPF --------------------------------------------------------------

    if "OSPF" in path and "Area Authentication" in path:
        if nv == "2":  # 2 → message-digest
            return (f"area {item_id} authentication message-digest"
                    in config_set)
        return False

    if "OSPF Message Digest Key" in path_str and "Ports" in path:
        iface_name = _iface_name_from_path(path)
        if iface_name:
            iface_lines = sections["interfaces"].get(iface_name, [])
            return any(f"ip ospf message-digest-key {item_id} md5" in l
                       for l in iface_lines)
        return any(f"ip ospf message-digest-key {item_id} md5" in l
                   for l in config_lines)

    # --- Zone-Based Firewall -----------------------------------------------

    if "Zone Based Firewall" in path and "Zone Names" in path:
        return f"zone security {nv}" in config_set

    if "Zone Pairs" in path_str and item_id == "Name":
        return any(f"zone-pair security {nv}" in l for l in config_lines)

    if "Zone Pairs" in path_str and item_id == "Source Zone":
        pair = _zone_pair_name_from_path(path)
        if pair:
            return any(f"zone-pair security {pair} source {nv}" in l
                       for l in config_lines)
        return False

    if "Zone Pairs" in path_str and item_id == "Destination Zone":
        pair = _zone_pair_name_from_path(path)
        if pair:
            return any(f"destination {nv}" in l and pair in l
                       for l in config_lines)
        return False

    if "Zone Pairs" in path_str and item_id == "Service Policy":
        return f"service-policy type inspect {nv}" in config_set

    # --- Class Maps --------------------------------------------------------

    if "Class Maps" in path and item_id == "Map Type":
        cm_name = _class_map_name_from_path(path)
        if cm_name and nv == "2":  # 2 → match-any inspect
            return (f"class-map type inspect match-any {cm_name}"
                    in config_set)
        return False

    if "Class Maps" in path and "Statements" in path:
        return f"match {nv}" in config_set

    # --- Policy Maps (section-aware for class/action) ----------------------

    if "Policy Maps" in path and item_id == "Policy Map Name":
        return f"policy-map type inspect {nv}" in config_set

    if "Policy Maps" in path and item_id == "Policy Map Type":
        pm_name = _policy_map_name_from_path(path)
        if pm_name and nv == "2":  # 2 → inspect
            return f"policy-map type inspect {pm_name}" in config_set
        return False

    if "Policy Maps" in path and item_id == "Class Map":
        pm_name = _policy_map_name_from_path(path)
        if pm_name:
            pm_lines = sections["sections"].get(
                f"policy-map type inspect {pm_name}", [])
            return f"class type inspect {nv}" in pm_lines
        return f"class type inspect {nv}" in config_set

    if "Policy Maps" in path and item_id == "Action":
        if nv == "2":  # 2 → inspect
            pm_name = _policy_map_name_from_path(path)
            if pm_name:
                pm_lines = sections["sections"].get(
                    f"policy-map type inspect {pm_name}", [])
                return "inspect" in pm_lines
            return "inspect" in config_set
        return False

    # --- Interface / port properties (Ports > {iface} > …) -----------------

    if "Ports" in path:
        iface_name = _iface_name_from_path(path)
        iface_lines = (sections["interfaces"].get(iface_name, [])
                       if iface_name else [])

        if item_id == "IP Address":
            return any(l.startswith("ip address ") and f" {nv} " in l
                       for l in iface_lines)

        if item_id == "Subnet Mask":
            return any(l.startswith("ip address ") and l.endswith(nv)
                       for l in iface_lines)

        if item_id == "Port Up":
            if nv == "1":
                return "shutdown" not in iface_lines
            return "shutdown" in iface_lines

        if item_id == "Access VLAN":
            return f"switchport access vlan {nv}" in iface_lines

        if item_id == "Native VLAN":
            return f"switchport trunk native vlan {nv}" in iface_lines

        if item_id == "Channel Group":
            return any(f"channel-group {nv}" in l for l in iface_lines)

        if item_id == "Channel mode":
            # 1 → active, 2 → passive, 3 → desirable, 4 → auto, 5 → on
            mode_map = {"1": "active", "2": "passive", "3": "desirable",
                        "4": "auto", "5": "on"}
            kw = mode_map.get(nv)
            if kw:
                return any(f"mode {kw}" in l for l in iface_lines)
            return any(f"mode {nv}" in l for l in iface_lines)

        if item_id == "Bpduguard":
            if nv == "1":
                return "spanning-tree bpduguard enable" in iface_lines
            return "spanning-tree bpduguard enable" not in iface_lines

        if item_id == "PortFast":
            if nv == "1":
                return "spanning-tree portfast" in iface_lines
            return "spanning-tree portfast" not in iface_lines

        if item_id == "CDP Enabled":
            if nv == "1":
                # CDP is on by default; "no cdp enable" turns it off.
                return "no cdp enable" not in iface_lines
            return "no cdp enable" in iface_lines

        if item_id == "NAT" or "NAT Mode" in path_str:
            # 1 → inside, 2 → outside
            if nv == "1":
                return "ip nat inside" in iface_lines
            if nv == "2":
                return "ip nat outside" in iface_lines
            return False

        if item_id == "Power" and "Port Status" in path_str:
            # Same as Port Up: nv="1" means no shutdown, nv="0" means shutdown.
            if nv == "1":
                return "shutdown" not in iface_lines
            return "shutdown" in iface_lines

        if item_id == "Mode" and "Tunnel Mode" in path_str:
            # nv is the tunnel mode, e.g. "gre ip".  In IOS config:
            # ``tunnel mode gre ip``.  GRE/IP is the default and may not
            # appear in the running-config.
            if nv == "gre ip":
                # Default mode — True unless a different mode is configured.
                return not any(l.startswith("tunnel mode ")
                               and l != "tunnel mode gre ip"
                               for l in iface_lines)
            return f"tunnel mode {nv}" in iface_lines

        if item_id == "Source" and "Tunnel" in (iface_name or ""):
            return f"tunnel source {nv}" in iface_lines

        if item_id == "Destination" and "Tunnel" in (iface_name or ""):
            return f"tunnel destination {nv}" in iface_lines

        # Note: "Autthentication" is the actual spelling used in the PKA
        # XML item ID (a typo in Packet Tracer's data format).
        if item_id == "OSPF Port Autthentication" or (
                item_id.startswith("OSPF") and "Authentication" in path_str
                and "Key" not in path_str):
            # nv="2" → message-digest authentication on the interface.
            if nv == "2":
                return "ip ospf authentication message-digest" in iface_lines
            return False

        if item_id == "OSPF Authentication Key" or (
                "OSPF" in path_str and "Authentication Key" in path_str):
            return f"ip ospf authentication-key {nv}" in iface_lines

        if item_id == "OSPF Hello Interval" or "OSPF Hello" in path_str:
            return f"ip ospf hello-interval {nv}" in iface_lines

        if item_id == "OSPF Dead Interval" or "OSPF Dead" in path_str:
            return f"ip ospf dead-interval {nv}" in iface_lines

        if item_id == "Access-group In":
            if nv:
                return any("ip access-group" in l and "in" in l
                           for l in iface_lines)
            # Empty nv means just checking the access-group exists.
            return any("ip access-group" in l for l in iface_lines)

        # Port Security sub-items
        if "Port Security" in path:
            if item_id == "Enabled":
                if nv == "1":
                    return "switchport port-security" in iface_lines
                return "switchport port-security" not in iface_lines

            if item_id == "Max Secure Mac" or "Maximum" in item_id:
                return (f"switchport port-security maximum {nv}"
                        in iface_lines)

            if item_id == "Violation":
                # 1 → shutdown, 2 → restrict, 3 → protect
                viol_map = {"1": "shutdown", "2": "restrict",
                            "3": "protect"}
                kw = viol_map.get(nv)
                if kw:
                    return (f"switchport port-security violation {kw}"
                            in iface_lines)
                return False

    # --- VLAN properties (VLANS > VLAN N > …) ------------------------------

    if "VLANS" in path or "VLAN" in path_str:
        if item_id == "VLAN Name":
            # VLANs are stored as XML attributes on <VLAN> elements inside
            # the ENGINE/VLANS tree, NOT in the running-config.
            vlan_num = _vlan_num_from_path(path)
            if engine is not None and vlan_num is not None:
                vlans_el = engine.find("VLANS")
                if vlans_el is not None:
                    for vlan_el in vlans_el.findall("VLAN"):
                        num = vlan_el.get("number", "")
                        name = vlan_el.get("name", "")
                        if num == str(vlan_num) and name == nv:
                            return True
                    return False
            # Fallback: check running-config section.
            if vlan_num is not None:
                for sec_hdr, sec_lines in sections["sections"].items():
                    if sec_hdr.strip() == f"vlan {vlan_num}":
                        return f"name {nv}" in sec_lines
            return f"name {nv}" in config_set

    # --- OSPF extended properties ------------------------------------------

    if "OSPF" in path:
        # Extract OSPF process ID from the path (e.g. "Process ID 22").
        ospf_id = _ospf_process_id_from_path(path)
        ospf_section_lines = []
        if ospf_id:
            ospf_section_lines = sections["sections"].get(
                f"router ospf {ospf_id}", [])

        if item_id == "Router ID":
            return f"router-id {nv}" in ospf_section_lines

        if item_id == "Auto Cost":
            return (f"auto-cost reference-bandwidth {nv}"
                    in ospf_section_lines)

        if item_id == "Default Information":
            if nv == "1":
                return "default-information originate" in ospf_section_lines
            return False

        if item_id.startswith("Route"):
            # nodeValue format: "network wildcard area"
            # e.g. "192.168.10.0 0.0.0.255 0"
            parts = nv.split()
            if len(parts) == 3:
                net, wild, area = parts
                target = f"network {net} {wild} area {area}"
                return target in ospf_section_lines
            # Fall through to generic if format is unexpected.

        if "Passive Interface" in path:
            # item_id is the interface name, nv is "1" (enabled).
            if nv == "1":
                # Direct match: ``passive-interface {item_id}``
                if f"passive-interface {item_id}" in ospf_section_lines:
                    return True
                # Indirect match via ``passive-interface default``:
                # all interfaces are passive unless excluded with
                # ``no passive-interface {item_id}``.
                if "passive-interface default" in ospf_section_lines:
                    return (f"no passive-interface {item_id}"
                            not in ospf_section_lines)
                return False
            return False

        if "Area Status" in path_str:
            # Extract the area number from the path.
            area_num = None
            for p in path:
                if p.startswith("Area "):
                    try:
                        area_num = p.split(" ", 1)[1]
                    except IndexError:
                        pass
                    break
            if not nv:
                # Empty nodeValue means the area is a normal (non-stub) area.
                # The area exists if the student has any OSPF network
                # statement for that area.
                if area_num is not None:
                    return any(l.endswith(f"area {area_num}")
                               for l in ospf_section_lines)
                return False
            # Non-empty nv: e.g. "4 stub" or "4 stub no-summary".
            # IOS config: "area 4 stub" or "area 4 stub no-summary".
            return f"area {nv}" in ospf_section_lines

        if "Area Range" in path_str:
            # nodeValue: "area_id network mask"
            # e.g. "4 10.4.0.0 255.255.0.0"
            # IOS config: "area 4 range 10.4.0.0 255.255.0.0"
            parts = nv.split()
            if len(parts) == 3:
                area_id, net, mask = parts
                return (f"area {area_id} range {net} {mask}"
                        in ospf_section_lines)
            return False

        if "Redistribution" in path:
            # nodeValue: "PROTOCOL PROCESS" e.g. "EIGRP 10"
            # IOS config: "redistribute eigrp 10 ..." (with optional params)
            parts = nv.split()
            if len(parts) >= 2:
                proto = parts[0].lower()
                proc_id = parts[1]
                return any(l.startswith(f"redistribute {proto} {proc_id}")
                           for l in ospf_section_lines)
            return False

    # --- Static Routes -----------------------------------------------------

    if "Routes" in path and "Static Routes" in path:
        # nodeValue format: "destination-mask_prefix_len-next_hop-metric-ad"
        # e.g. "0.0.0.0-0-209.91.181.1-0-1"
        parts = nv.split("-")
        if len(parts) >= 3:
            dest = parts[0]
            try:
                prefix_len = int(parts[1])
                mask = _prefix_to_mask(prefix_len)
            except ValueError:
                # Might already be a dotted-decimal mask.
                mask = parts[1]
            next_hop = parts[2]
            return f"ip route {dest} {mask} {next_hop}" in config_set
        return False

    # --- IP Routing --------------------------------------------------------

    if item_id == "IP Routing" and "Routes" in path:
        if nv == "1":
            return "ip routing" in config_set
        return "ip routing" not in config_set

    # --- BGP ---------------------------------------------------------------

    if "BGP" in path:
        as_num = _bgp_as_from_path(path)

        if item_id == "Autonomous System" and "Autonomous System" in path:
            if as_num is None:
                # The AS is in nodeValue; check for the router bgp statement.
                return f"router bgp {nv}" in config_set
            return f"router bgp {nv}" in config_set

        if "Networks" in path:
            # BGP network: nodeValue = "network mask"
            # e.g. "209.91.181.0 255.255.255.252"
            # IOS config: "network 209.91.181.0 mask 255.255.255.252"
            bgp_section = []
            if as_num:
                bgp_section = sections["sections"].get(
                    f"router bgp {as_num}", [])
            else:
                for hdr, lines in sections["sections"].items():
                    if hdr.startswith("router bgp"):
                        bgp_section = lines
                        break
            parts = nv.split()
            if len(parts) == 2:
                net, mask = parts
                return f"network {net} mask {mask}" in bgp_section
            return False

        if item_id == "NeighborAS" and "Neighbors" in path:
            # Extract neighbor IP from path.
            neighbor_ip = None
            for p in path:
                if p not in ("BGP", "Neighbors", "Autonomous System") and \
                   not p.startswith("Process") and "." in p:
                    neighbor_ip = p
                    break
            if neighbor_ip:
                return f"neighbor {neighbor_ip} remote-as {nv}" in config_set
            return False

    # --- EIGRP -------------------------------------------------------------

    if "EIGRP" in path:
        eigrp_as = _eigrp_as_from_path(path)
        eigrp_section = []
        if eigrp_as:
            eigrp_section = sections["sections"].get(
                f"router eigrp {eigrp_as}", [])

        if item_id == "Router ID":
            return f"eigrp router-id {nv}" in eigrp_section

        if "Networks" in path and item_id.startswith("Route"):
            # nodeValue: "network wildcard" e.g. "172.16.1.0 0.0.0.255"
            parts = nv.split()
            if len(parts) == 2:
                net, wild = parts
                return f"network {net} {wild}" in eigrp_section
            if len(parts) == 1:
                return f"network {nv}" in eigrp_section
            return False

        if "Passive Interface" in path:
            # item_id is the interface name, nv is "1" (enabled).
            if nv == "1":
                if f"passive-interface {item_id}" in eigrp_section:
                    return True
                # Handle ``passive-interface default`` pattern.
                if "passive-interface default" in eigrp_section:
                    return (f"no passive-interface {item_id}"
                            not in eigrp_section)
                return False
            return False

        if "Redistribution" in path:
            # nodeValue: "PROTOCOL PROCESS" e.g. "OSPF 10"
            # IOS config: "redistribute ospf 10 metric ..."
            parts = nv.split()
            if len(parts) >= 2:
                proto = parts[0].lower()
                proc_id = parts[1]
                return any(l.startswith(f"redistribute {proto} {proc_id}")
                           for l in eigrp_section)
            return False

    # --- Default Gateway ---------------------------------------------------

    if item_id == "Default Gateway":
        # On router/switch: ``ip default-gateway {nv}`` in config.
        # On PC/end-devices: stored as <GATEWAY> XML element in ENGINE.
        if f"ip default-gateway {nv}" in config_set:
            return True
        if engine is not None:
            gw_el = engine.find("GATEWAY")
            if gw_el is not None and gw_el.text:
                return gw_el.text.strip() == nv
        return False

    # --- NAT (non-interface: NAT > Inside Source …) ------------------------

    if "NAT" in path and "Inside Source Static" in path_str:
        return any(f"ip nat inside source static {nv}".rstrip() in l
                   for l in config_lines)

    if "NAT" in path and "Inside Source List" in path_str:
        # These items often encode complex pool/ACL references.
        if nv:
            return any(nv in l and "ip nat" in l for l in config_lines)
        return False

    # --- TFTP / Server Files -----------------------------------------------

    if "TFTP Server" in path_str or "ServerFiles" in path_str:
        # TFTP server files are stored in the XML FILE_MANAGER tree,
        # not in the running-config.  The nodeValue format is
        # "tftp:/<filename>".
        if engine is not None:
            target_name = nv
            if target_name.startswith("tftp:/"):
                target_name = target_name[len("tftp:/"):]
            for file_el in engine.iter("FILE"):
                name_el_file = file_el.find("NAME")
                if (name_el_file is not None and name_el_file.text
                        and name_el_file.text.strip() == target_name):
                    return True
            return False

    # Unrecognised property — return None so the caller can detect it and
    # fall back to the generic answer-key comparison.
    logger.debug("Unknown checkType=2 property: id=%s path=%s device=%s",
                 item_id, path, item.get("device", "?"))
    return None


# ---- Feedback description helpers -------------------------------------------

# Maps that translate numeric nodeValue codes to human-readable names for
# specific property types, so the feedback output is understandable.
_NAT_MODE_MAP = {"1": "inside", "2": "outside"}
_TRANSPORT_MAP = {"2": "SSH"}
_LOGIN_MAP = {"2": "login local"}
_AUTH_MAP = {"2": "message-digest"}


def _expected_config_line(item, answer_lines, answer_sections):
    """Return the IOS config line(s) that the student should have configured.

    This translates the item's ``nodeValue`` into a human-readable
    representation of the expected configuration.
    """
    nv = item["nodeValue"].strip()
    item_id = item["id"]
    path = item["path"]
    path_str = " ".join(path)

    # --- Interface-scoped properties ---
    if "Ports" in path:
        iface_name = _iface_name_from_path(path)
        prefix = f"interface {iface_name}: " if iface_name else ""

        if item_id == "IP Address":
            return f"{prefix}ip address {nv} ..."
        if item_id == "Subnet Mask":
            return f"{prefix}ip address ... {nv}"
        if item_id in ("Port Up", "Power"):
            return f"{prefix}{'no shutdown' if nv == '1' else 'shutdown'}"
        if item_id in ("NAT", "NAT Mode") or "NAT Mode" in path_str:
            mode = _NAT_MODE_MAP.get(nv, nv)
            return f"{prefix}ip nat {mode}"
        if item_id == "Mode" and "Tunnel" in path_str:
            return f"{prefix}tunnel mode {nv}"
        if item_id == "Source" and "Tunnel" in (iface_name or ""):
            return f"{prefix}tunnel source {nv}"
        if item_id == "Destination" and "Tunnel" in (iface_name or ""):
            return f"{prefix}tunnel destination {nv}"
        if "OSPF Authentication Key" in path_str:
            return f"{prefix}ip ospf authentication-key {nv}"
        if "OSPF Authentication" in path_str and "Key" not in path_str:
            return f"{prefix}ip ospf authentication message-digest"
        if "OSPF Hello" in path_str:
            return f"{prefix}ip ospf hello-interval {nv}"
        if "OSPF Dead" in path_str:
            return f"{prefix}ip ospf dead-interval {nv}"
        if item_id == "Access VLAN":
            return f"{prefix}switchport access vlan {nv}"
        if item_id == "Native VLAN":
            return f"{prefix}switchport trunk native vlan {nv}"
        if item_id == "Bpduguard" and nv == "1":
            return f"{prefix}spanning-tree bpduguard enable"
        if item_id == "PortFast" and nv == "1":
            return f"{prefix}spanning-tree portfast"
        if "Port Security" in path:
            if item_id == "Enabled" and nv == "1":
                return f"{prefix}switchport port-security"
            if "Maximum" in item_id or item_id == "Max Secure Mac":
                return f"{prefix}switchport port-security maximum {nv}"
            if item_id == "Violation":
                viol = {"1": "shutdown", "2": "restrict", "3": "protect"
                        }.get(nv, nv)
                return f"{prefix}switchport port-security violation {viol}"
        if item_id == "Access-group In":
            return f"{prefix}ip access-group ... in"
        return f"{prefix}{nv}"

    # --- OSPF ---
    if "OSPF" in path:
        ospf_id = _ospf_process_id_from_path(path)
        prefix = f"router ospf {ospf_id}: " if ospf_id else ""
        if item_id == "Router ID":
            return f"{prefix}router-id {nv}"
        if item_id == "Auto Cost":
            return f"{prefix}auto-cost reference-bandwidth {nv}"
        if item_id == "Default Information" and nv == "1":
            return f"{prefix}default-information originate"
        if item_id.startswith("Route") and "Networks" in path:
            parts = nv.split()
            if len(parts) == 3:
                return f"{prefix}network {parts[0]} {parts[1]} area {parts[2]}"
        if "Passive Interface" in path:
            return f"{prefix}passive-interface {item_id}"
        if "Area Status" in path_str:
            if not nv:
                return f"{prefix}area exists (network statements for area)"
            return f"{prefix}area {nv}"
        if "Area Range" in path_str:
            parts = nv.split()
            if len(parts) == 3:
                return f"{prefix}area {parts[0]} range {parts[1]} {parts[2]}"
        if "Redistribution" in path:
            parts = nv.split()
            if len(parts) >= 2:
                return (f"{prefix}redistribute {parts[0].lower()} "
                        f"{parts[1]} ...")
        if "Area Authentication" in path:
            return f"{prefix}area {item_id} authentication message-digest"

    # --- BGP ---
    if "BGP" in path:
        if item_id == "Autonomous System":
            return f"router bgp {nv}"
        if "Networks" in path:
            parts = nv.split()
            if len(parts) == 2:
                return f"network {parts[0]} mask {parts[1]}"
        if item_id == "NeighborAS":
            neighbor_ip = None
            for p in path:
                if p not in ("BGP", "Neighbors", "Autonomous System") and \
                   "." in p:
                    neighbor_ip = p
                    break
            if neighbor_ip:
                return f"neighbor {neighbor_ip} remote-as {nv}"

    # --- EIGRP ---
    if "EIGRP" in path:
        eigrp_as = _eigrp_as_from_path(path)
        prefix = f"router eigrp {eigrp_as}: " if eigrp_as else ""
        if item_id == "Router ID":
            return f"{prefix}eigrp router-id {nv}"
        if "Networks" in path:
            parts = nv.split()
            if len(parts) == 2:
                return f"{prefix}network {parts[0]} {parts[1]}"
            return f"{prefix}network {nv}"
        if "Passive Interface" in path:
            return f"{prefix}passive-interface {item_id}"
        if "Redistribution" in path:
            parts = nv.split()
            if len(parts) >= 2:
                return (f"{prefix}redistribute {parts[0].lower()} "
                        f"{parts[1]} ...")

    # --- Static Routes ---
    if "Static Routes" in path:
        parts = nv.split("-")
        if len(parts) >= 3:
            dest = parts[0]
            try:
                mask = _prefix_to_mask(int(parts[1]))
            except ValueError:
                mask = parts[1]
            return f"ip route {dest} {mask} {parts[2]}"

    # --- Other global properties ---
    if item_id == "IP Routing":
        return "ip routing" if nv == "1" else "no ip routing"
    if item_id == "Enable Secret":
        return f"enable secret ... (hash: {nv[:20]}...)"
    if item_id == "IP Domain Name":
        return f"ip domain-name {nv}"
    if item_id == "SSH Server Version":
        return f"ip ssh version {nv}"
    if item_id == "Transport Input":
        return f"transport input {_TRANSPORT_MAP.get(nv, nv)}"
    if item_id == "Login":
        return _LOGIN_MAP.get(nv, f"login ({nv})")
    if item_id == "Access Class In":
        return f"access-class {nv} in"
    if item_id == "Default Gateway":
        return f"ip default-gateway {nv}"
    if "User Names" in path:
        parts = nv.split(" ", 1)
        if len(parts) == 2:
            return f"username {parts[0]} secret ..."
    if "ACL" in path:
        return nv.replace("\n", "; ")

    return nv


def _describe_expected(item, answer_lines, answer_sections):
    """Return a human-readable description of the expected configuration."""
    return _expected_config_line(item, answer_lines, answer_sections)


def _describe_student(item, config_lines, config_set, sections, engine):
    """Return a description of what the student actually configured.

    Searches the student config for lines related to the item's property and
    returns what was found (or ``(not configured)`` if nothing matches).
    """
    nv = item["nodeValue"].strip()
    item_id = item["id"]
    path = item["path"]
    path_str = " ".join(path)

    # --- Interface-scoped properties ---
    if "Ports" in path:
        iface_name = _iface_name_from_path(path)
        iface_lines = (sections["interfaces"].get(iface_name, [])
                       if iface_name else [])

        if item_id == "IP Address":
            for l in iface_lines:
                if l.startswith("ip address "):
                    return l
            return "(not configured)"

        if item_id == "Subnet Mask":
            for l in iface_lines:
                if l.startswith("ip address "):
                    return l
            return "(not configured)"

        if item_id in ("Port Up", "Power"):
            if "shutdown" in iface_lines:
                return "shutdown"
            return "no shutdown"

        if item_id in ("NAT", "NAT Mode") or "NAT Mode" in path_str:
            for l in iface_lines:
                if "ip nat" in l:
                    return l
            return "(not configured)"

        if item_id == "Mode" and "Tunnel" in path_str:
            for l in iface_lines:
                if l.startswith("tunnel mode "):
                    return l
            return "(default: tunnel mode gre ip)"

        if item_id == "Source" and "Tunnel" in (iface_name or ""):
            for l in iface_lines:
                if l.startswith("tunnel source "):
                    return l
            return "(not configured)"

        if item_id == "Destination" and "Tunnel" in (iface_name or ""):
            for l in iface_lines:
                if l.startswith("tunnel destination "):
                    return l
            return "(not configured)"

        if "OSPF" in path_str:
            keyword = None
            if "Authentication Key" in path_str:
                # Look for authentication-key or message-digest-key.
                for l in iface_lines:
                    if "ip ospf authentication-key" in l or \
                       "ip ospf message-digest-key" in l:
                        return l
                return "(not configured)"
            elif "Authentication" in path_str:
                keyword = "ip ospf authentication"
            elif "Hello" in path_str:
                keyword = "ip ospf hello-interval"
            elif "Dead" in path_str:
                keyword = "ip ospf dead-interval"
            if keyword:
                for l in iface_lines:
                    if keyword in l:
                        return l
                return "(not configured)"

    # --- Routing protocol sections ---
    section_key = None
    section_lines = []

    if "OSPF" in path:
        ospf_id = _ospf_process_id_from_path(path)
        if ospf_id:
            section_key = f"router ospf {ospf_id}"
            section_lines = sections["sections"].get(section_key, [])
    elif "EIGRP" in path:
        eigrp_as = _eigrp_as_from_path(path)
        if eigrp_as:
            section_key = f"router eigrp {eigrp_as}"
            section_lines = sections["sections"].get(section_key, [])
    elif "BGP" in path:
        for hdr in sections["sections"]:
            if hdr.startswith("router bgp"):
                section_key = hdr
                section_lines = sections["sections"][hdr]
                break

    if section_key and not section_lines:
        return f"({section_key} section not found)"

    if section_lines:
        if "Passive Interface" in path:
            found = [l for l in section_lines
                     if "passive-interface" in l
                     and (item_id in l or "default" in l)]
            return "; ".join(found) if found else "(not configured)"

        if item_id == "Router ID":
            for l in section_lines:
                if "router-id" in l or "eigrp router-id" in l:
                    return l
            return "(not configured)"

        if item_id == "Auto Cost":
            for l in section_lines:
                if "auto-cost" in l:
                    return l
            return "(not configured)"

        if "Networks" in path and item_id.startswith("Route"):
            found = [l for l in section_lines if l.startswith("network ")]
            return "; ".join(found) if found else "(not configured)"

        if "Networks" in path:
            # BGP networks
            found = [l for l in section_lines if l.startswith("network ")]
            return "; ".join(found) if found else "(not configured)"

        if item_id == "NeighborAS":
            neighbor_ip = None
            for p in path:
                if p not in ("BGP", "Neighbors", "Autonomous System") and \
                   "." in p:
                    neighbor_ip = p
                    break
            if neighbor_ip:
                for l in section_lines:
                    if f"neighbor {neighbor_ip}" in l:
                        return l
            return "(not configured)"

        if "Area Status" in path_str:
            found = [l for l in section_lines
                     if l.startswith("area ") or "network" in l]
            return "; ".join(found[:5]) if found else "(not configured)"

        if "Area Range" in path_str:
            found = [l for l in section_lines if "range" in l]
            return "; ".join(found) if found else "(not configured)"

        if "Redistribution" in path:
            found = [l for l in section_lines if "redistribute" in l]
            return "; ".join(found) if found else "(not configured)"

        if item_id == "Default Information":
            for l in section_lines:
                if "default-information" in l:
                    return l
            return "(not configured)"

    # --- Static Routes ---
    if "Static Routes" in path:
        found = [l.strip() for l in config_lines if "ip route " in l]
        return "; ".join(found) if found else "(not configured)"

    # --- Other global properties ---
    if item_id == "IP Routing":
        return "ip routing" if "ip routing" in config_set else "(not configured)"

    if item_id == "Autonomous System" and "BGP" in path:
        for hdr in sections["sections"]:
            if hdr.startswith("router bgp"):
                return hdr
        return "(not configured)"

    if item_id == "Enable Secret":
        for l in config_lines:
            if l.strip().startswith("enable secret"):
                return l.strip()
        return "(not configured)"

    if item_id == "IP Domain Name":
        for l in config_lines:
            if "ip domain-name" in l:
                return l.strip()
        return "(not configured)"

    if item_id == "SSH Server Version":
        for l in config_lines:
            if "ip ssh version" in l:
                return l.strip()
        return "(not configured)"

    if item_id == "Transport Input":
        # Check VTY sections
        for _, _, lines in sections["vty_ranges"]:
            for l in lines:
                if "transport input" in l:
                    return l
        return "(not configured)"

    if item_id == "Access Class In":
        for _, _, lines in sections["vty_ranges"]:
            for l in lines:
                if "access-class" in l:
                    return l
        return "(not configured)"

    if "User Names" in path:
        parts = nv.split(" ", 1)
        if parts:
            uname = parts[0]
            for l in config_lines:
                if l.strip().startswith(f"username {uname} "):
                    return l.strip()
        return "(not configured)"

    if "ACL" in path:
        acl_name = item_id
        # Look for ACL lines in config
        found = []
        in_acl = False
        for l in config_lines:
            s = l.strip()
            if s == f"ip access-list standard {acl_name}" or \
               s == f"ip access-list extended {acl_name}":
                in_acl = True
                found.append(s)
                continue
            if in_acl:
                if s.startswith("permit ") or s.startswith("deny "):
                    found.append(s)
                elif s and s != "!":
                    break
            if s.startswith(f"access-list {acl_name} "):
                found.append(s)
        return "; ".join(found) if found else "(not configured)"

    if item_id == "Default Gateway":
        for l in config_lines:
            if "ip default-gateway" in l:
                return l.strip()
        if engine is not None:
            gw_el = engine.find("GATEWAY")
            if gw_el is not None and gw_el.text:
                return f"gateway: {gw_el.text.strip()}"
        return "(not configured)"

    return "(not determined)"


# ---- Generic answer-key comparison fallback ---------------------------------

def _evaluate_ct2_item_generic(item, config_lines, config_set, sections,
                               answer_lines, initial_lines,
                               answer_sections):
    """Attempt to evaluate a checkType=2 item using the answer-key config.

    This is a best-effort fallback for property types that have no dedicated
    evaluator.  It searches the answer-key config for lines that contain the
    item's ``nodeValue``, excludes lines already present in the initial state,
    and checks whether the student config contains at least one of the
    remaining "required" lines.

    Returns ``True``/``False`` if a determination can be made, or ``None``
    if the item cannot be evaluated (e.g. empty nodeValue, or the value only
    appears in pre-existing config).
    """
    nv = item["nodeValue"].strip()
    if not nv:
        return None

    path = item["path"]
    iface_name = _iface_name_from_path(path) if "Ports" in path else None

    initial_set = set(l.strip() for l in initial_lines
                      if l and l.strip() != "!")

    # Search the answer config for lines containing the nodeValue.
    # Scope the search to the relevant interface section if possible.
    if iface_name:
        search_lines = answer_sections.get("interfaces", {}).get(
            iface_name, [])
    else:
        search_lines = [l.strip() for l in answer_lines
                        if l and l.strip() != "!"]

    required = []
    for line in search_lines:
        stripped = line.strip()
        if stripped and nv in stripped and stripped not in initial_set:
            required.append(stripped)

    if not required:
        # nodeValue not found in answer config — cannot evaluate.
        return None

    # Check the student config for the required lines.
    if iface_name:
        student_iface = sections["interfaces"].get(iface_name, [])
        student_check = set(student_iface)
    else:
        student_check = config_set

    return any(line in student_check for line in required)


# ---- Path helpers -----------------------------------------------------------

def _vty_num_from_path(path):
    """Extract the VTY line number from a COMPARISONS path list."""
    for p in path:
        if p.startswith("VTY Line "):
            try:
                return int(p.split(" ")[-1])
            except ValueError:
                pass
    return None


def _iface_name_from_path(path):
    """Extract the interface name from a Ports path list."""
    for p in path:
        if p == "Ports":
            continue
        if "OSPF" in p:
            break
        return p
    return None


def _zone_pair_name_from_path(path):
    for p in path:
        if p.startswith("Zone Pair "):
            return p[len("Zone Pair "):]
    return None


def _class_map_name_from_path(path):
    for p in path:
        if p not in ("Class Maps", "Class Map List", "Map Type",
                     "Statements"):
            return p
    return None


def _policy_map_name_from_path(path):
    for p in path:
        if p.startswith("Policy Map ") and "List" not in p:
            return p[len("Policy Map "):]
    return None


def _vlan_num_from_path(path):
    """Extract the VLAN number from a path like ``['VLANS', 'VLAN 10', …]``."""
    for p in path:
        if p.startswith("VLAN "):
            try:
                return int(p.split(" ", 1)[1])
            except (ValueError, IndexError):
                pass
    return None


def _ospf_process_id_from_path(path):
    """Extract the OSPF process ID from a path like ``['OSPF', 'Process ID 22', …]``."""
    for p in path:
        if p.startswith("Process ID "):
            return p[len("Process ID "):]
    return None


def _prefix_to_mask(prefix_len):
    """Convert a prefix length (0–32) to a dotted-decimal subnet mask."""
    if prefix_len < 0:
        prefix_len = 0
    elif prefix_len > 32:
        prefix_len = 32
    bits = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
    return f"{(bits >> 24) & 0xFF}.{(bits >> 16) & 0xFF}.{(bits >> 8) & 0xFF}.{bits & 0xFF}"


def _bgp_as_from_path(path):
    """Extract the BGP AS number from a COMPARISONS path list.

    Looks for ``'Autonomous System'`` in the path; if the element *before*
    it starts with ``'BGP'``, the AS is typically encoded elsewhere (in the
    nodeValue).  Otherwise, the AS may appear in a path element like
    ``'Autonomous System 2014'``.

    Falls back to searching for a ``router bgp`` section header pattern.
    """
    # The BGP section in config is "router bgp <AS>".  We can try to
    # extract the AS from path elements.
    for p in path:
        if p.startswith("Autonomous System ") and "Neighbors" not in path:
            rest = p[len("Autonomous System "):]
            if rest.isdigit():
                return rest
    return None


def _eigrp_as_from_path(path):
    """Extract the EIGRP autonomous system number from a path.

    Looks for ``'Autonomous System N'`` in the path, e.g.
    ``['EIGRP', 'Autonomous System 10', 'Networks', …]``.
    """
    for p in path:
        if p.startswith("Autonomous System "):
            rest = p[len("Autonomous System "):]
            if rest.isdigit():
                return rest
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

    # --- Property evaluation (Packet Tracer 7.x+ encrypted format) ---------
    # Encrypted PKA files typically contain three <PACKETTRACER5> elements:
    # [0] student work, [1] initial state, [2] answer key.  The most accurate
    # scoring method evaluates each checkType="2" assessment item in the
    # COMPARISONS tree against the student's running-config and device
    # properties.  Both score and max_score are set together to keep them
    # consistent.
    if result["score"] is None and result["max_score"] is None:
        prop_result = _score_by_property_evaluation(root)
        if prop_result is not None:
            earned, total, feedback = prop_result
            result["score"] = str(earned)
            result["max_score"] = str(total)
            result["feedback"] = feedback

    # --- Running-config comparison fallback --------------------------------
    # When the COMPARISONS tree has no checkType="2" items (or doesn't exist)
    # but three PACKETTRACER5 elements are present, fall back to a heuristic
    # that counts matching config lines (answer minus initial).
    if result["score"] is None and result["max_score"] is None:
        config_result = _score_by_config_comparison(root)
        if config_result is not None:
            earned, total = config_result
            result["score"] = str(earned)
            result["max_score"] = str(total)

    # --- COMPARISONS tree fallback (Packet Tracer 7.x+ encrypted format) ---
    # If neither property evaluation nor config comparison is available,
    # fall back to the COMPARISONS verification tree leaf-node tally.
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

    # Transfer per-item feedback if present.
    if "feedback" in parsed:
        base_result["feedback"] = parsed["feedback"]

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

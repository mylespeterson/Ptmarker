"""
Tests for pka_parser.py — focused on the ZIP-opening logic that handles
PKA files with proprietary binary headers prepended to the ZIP data.
"""

import io
import os
import tempfile
import zipfile

import pytest

from pka_parser import (
    _evaluate_ct2_item_generic,
    _open_pka_as_zip,
    _score_by_config_comparison,
    _score_by_property_evaluation,
    _tally_comparison_points,
    parse_pka_file,
)
from pt_decrypt import decrypt_pka


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SCORING_XML = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<ACTIVITY>
  <SCORING maxPoints="100" earnedPoints="85">
    <SCORE>85</SCORE>
    <MAXSCORE>100</MAXSCORE>
  </SCORING>
  <USERPROFILENAME>Test Student</USERPROFILENAME>
</ACTIVITY>
"""


def _make_zip_bytes(xml_content=_SCORING_XML, entry_name="default.xml"):
    """Return raw bytes of a ZIP archive containing one XML entry."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(entry_name, xml_content)
    return buf.getvalue()


def _write_tmp(data, suffix=".pka", tmpdir=None):
    """Write *data* to a temp file and return its path."""
    fd, path = tempfile.mkstemp(suffix=suffix, dir=tmpdir)
    os.write(fd, data)
    os.close(fd)
    return path


# ---------------------------------------------------------------------------
# Tests for _open_pka_as_zip
# ---------------------------------------------------------------------------

class TestOpenPkaAsZip:
    """Tests for the _open_pka_as_zip helper."""

    def test_standard_zip(self):
        """Standard ZIP file opens without fallback."""
        path = _write_tmp(_make_zip_bytes())
        try:
            with _open_pka_as_zip(path) as zf:
                assert "default.xml" in zf.namelist()
        finally:
            os.unlink(path)

    def test_zip_with_proprietary_header(self):
        """ZIP data preceded by a non-ZIP header is still found and opened."""
        header = b"\x00\x01CISCOHEADER\xff\xfe" * 4
        path = _write_tmp(header + _make_zip_bytes())
        try:
            with _open_pka_as_zip(path) as zf:
                assert "default.xml" in zf.namelist()
        finally:
            os.unlink(path)

    def test_no_zip_data(self):
        """Completely non-ZIP data raises BadZipFile."""
        path = _write_tmp(b"this is not a zip file at all")
        try:
            with pytest.raises(zipfile.BadZipFile):
                _open_pka_as_zip(path)
        finally:
            os.unlink(path)

    def test_empty_file(self):
        """An empty file raises BadZipFile."""
        path = _write_tmp(b"")
        try:
            with pytest.raises(zipfile.BadZipFile):
                _open_pka_as_zip(path)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Tests for parse_pka_file
# ---------------------------------------------------------------------------

class TestParsePkaFile:
    """Tests for the full parse_pka_file function."""

    def test_standard_pka(self):
        """A plain-ZIP PKA returns correct scores."""
        path = _write_tmp(_make_zip_bytes())
        try:
            result = parse_pka_file(path)
            assert result["score"] == "85"
            assert result["max_score"] == "100"
            assert result["percentage"] == "85.0%"
            assert result["user_profile_name"] == "Test Student"
            assert result["error"] is None
        finally:
            os.unlink(path)

    def test_pka_with_header(self):
        """A PKA with a proprietary header still parses correctly."""
        header = bytes(range(256)) + b"\x00" * 50  # 306 bytes of junk
        path = _write_tmp(header + _make_zip_bytes())
        try:
            result = parse_pka_file(path)
            assert result["score"] == "85"
            assert result["max_score"] == "100"
            assert result["percentage"] == "85.0%"
            assert result["user_profile_name"] == "Test Student"
            assert result["error"] is None
        finally:
            os.unlink(path)

    def test_invalid_file(self):
        """A non-ZIP file returns an error result (no crash)."""
        path = _write_tmp(b"NOTAZIP")
        try:
            result = parse_pka_file(path)
            assert result["score"] == "N/A"
            assert result["max_score"] == "N/A"
            assert result["error"] is not None
        finally:
            os.unlink(path)

    def test_no_xml_inside_archive(self):
        """A valid ZIP with no XML entries reports a meaningful error."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("readme.txt", b"hello")
        path = _write_tmp(buf.getvalue())
        try:
            result = parse_pka_file(path)
            assert result["error"] is not None
            assert "No XML" in result["error"]
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Tests for encrypted PKA decryption + parsing
# ---------------------------------------------------------------------------

_ENCRYPTED_PKA_PATH = os.path.join(
    os.path.dirname(__file__),
    "6.3.7 Packet Tracer - Configure OSPF Authentication-MP.pka",
)

_HAS_ENCRYPTED_PKA = os.path.isfile(_ENCRYPTED_PKA_PATH)


@pytest.mark.skipif(not _HAS_ENCRYPTED_PKA, reason="encrypted PKA test file not present")
class TestEncryptedPka:
    """Tests for encrypted (Twofish-EAX) PKA file handling."""

    def test_decrypt_pka_returns_xml(self):
        """decrypt_pka() on the test file returns valid XML bytes."""
        with open(_ENCRYPTED_PKA_PATH, "rb") as f:
            raw = f.read()
        xml_bytes = decrypt_pka(raw)
        assert xml_bytes.startswith(b"<PACKETTRACER5_ACTIVITY>")

    def test_parse_encrypted_pka_no_error(self):
        """parse_pka_file() processes the encrypted PKA without error."""
        result = parse_pka_file(_ENCRYPTED_PKA_PATH)
        assert result["error"] is None

    def test_parse_encrypted_pka_scores(self):
        """parse_pka_file() extracts numeric scores from the encrypted PKA."""
        result = parse_pka_file(_ENCRYPTED_PKA_PATH)
        assert result["score"] != "N/A"
        assert result["max_score"] != "N/A"
        assert result["percentage"] != "N/A"
        # Verify they are numeric.
        assert float(result["score"]) >= 0
        assert float(result["max_score"]) > 0
        assert result["percentage"].endswith("%")


# ---------------------------------------------------------------------------
# Tests for _tally_comparison_points helper
# ---------------------------------------------------------------------------

class TestTallyComparisonPoints:
    """Tests for the COMPARISONS-tree scoring helper."""

    def test_single_leaf_pass(self):
        """A single leaf node with POINTS=1."""
        import xml.etree.ElementTree as ET
        xml = b"<COMPARISONS><NODE><POINTS>1</POINTS></NODE></COMPARISONS>"
        root = ET.fromstring(xml)
        earned, total = _tally_comparison_points(root)
        assert earned == 1
        assert total == 1

    def test_single_leaf_fail(self):
        """A single leaf node with POINTS=0."""
        import xml.etree.ElementTree as ET
        xml = b"<COMPARISONS><NODE><POINTS>0</POINTS></NODE></COMPARISONS>"
        root = ET.fromstring(xml)
        earned, total = _tally_comparison_points(root)
        assert earned == 0
        assert total == 1

    def test_nested_tree(self):
        """Nested NODE elements; only leaves count."""
        import xml.etree.ElementTree as ET
        xml = (
            b"<COMPARISONS>"
            b"  <NODE><POINTS></POINTS>"
            b"    <NODE><POINTS>1</POINTS></NODE>"
            b"    <NODE><POINTS>0</POINTS></NODE>"
            b"    <NODE><POINTS>1</POINTS></NODE>"
            b"  </NODE>"
            b"</COMPARISONS>"
        )
        root = ET.fromstring(xml)
        earned, total = _tally_comparison_points(root)
        assert earned == 2
        assert total == 3

    def test_empty_comparisons(self):
        """An empty COMPARISONS element returns zeros."""
        import xml.etree.ElementTree as ET
        xml = b"<COMPARISONS></COMPARISONS>"
        root = ET.fromstring(xml)
        earned, total = _tally_comparison_points(root)
        assert earned == 0
        assert total == 0


# ---------------------------------------------------------------------------
# Tests for COMPARISONS-based scoring in parse_pka_file
# ---------------------------------------------------------------------------

class TestComparisonsScoringInParse:
    """Verify that COMPARISONS-tree scoring works end-to-end via ZIP path."""

    _COMPARISONS_XML = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<PACKETTRACER5_ACTIVITY>
  <COMPARISONS>
    <NODE>
      <POINTS></POINTS>
      <NODE><POINTS>1</POINTS></NODE>
      <NODE><POINTS>1</POINTS></NODE>
      <NODE><POINTS>0</POINTS></NODE>
      <NODE><POINTS>1</POINTS></NODE>
    </NODE>
  </COMPARISONS>
</PACKETTRACER5_ACTIVITY>
"""

    def test_zip_with_comparisons_scoring(self):
        """A ZIP-based PKA with COMPARISONS scoring extracts correct values."""
        path = _write_tmp(_make_zip_bytes(
            xml_content=self._COMPARISONS_XML, entry_name="default.xml"))
        try:
            result = parse_pka_file(path)
            assert result["score"] == "3"
            assert result["max_score"] == "4"
            assert result["percentage"] == "75.0%"
            assert result["error"] is None
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Tests for config-comparison scoring
# ---------------------------------------------------------------------------

class TestConfigComparisonScoring:
    """Verify that running-config comparison scoring produces correct results."""

    def test_config_comparison_basic(self):
        """Config comparison scores correctly when student and answer configs differ."""
        xml_content = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<PACKETTRACER5_ACTIVITY>
  <PACKETTRACER5>
    <NETWORK>
      <DEVICES>
        <DEVICE>
          <ENGINE>
            <NAME>R1</NAME>
            <RUNNINGCONFIG>
              <LINE>!</LINE>
              <LINE>hostname R1</LINE>
              <LINE>ip address 10.0.0.1 255.255.255.0</LINE>
              <LINE>!</LINE>
            </RUNNINGCONFIG>
          </ENGINE>
        </DEVICE>
      </DEVICES>
    </NETWORK>
  </PACKETTRACER5>
  <PACKETTRACER5>
    <NETWORK><DEVICES></DEVICES></NETWORK>
  </PACKETTRACER5>
  <PACKETTRACER5>
    <NETWORK>
      <DEVICES>
        <DEVICE>
          <ENGINE>
            <NAME>R1</NAME>
            <RUNNINGCONFIG>
              <LINE>!</LINE>
              <LINE>hostname R1</LINE>
              <LINE>ip address 10.0.0.1 255.255.255.0</LINE>
              <LINE>ip route 0.0.0.0 0.0.0.0 10.0.0.254</LINE>
              <LINE>!</LINE>
            </RUNNINGCONFIG>
          </ENGINE>
        </DEVICE>
      </DEVICES>
    </NETWORK>
  </PACKETTRACER5>
</PACKETTRACER5_ACTIVITY>
"""
        path = _write_tmp(_make_zip_bytes(xml_content=xml_content,
                                          entry_name="default.xml"))
        try:
            result = parse_pka_file(path)
            assert result["error"] is None
            # Answer has 3 significant lines (hostname, ip address, ip route).
            # Student has 2 of them (hostname, ip address).
            assert result["score"] == "2"
            assert result["max_score"] == "3"
            assert result["percentage"] == "66.7%"
        finally:
            os.unlink(path)

    def test_config_comparison_perfect_score(self):
        """Config comparison returns 100% when student matches answer exactly."""
        xml_content = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<PACKETTRACER5_ACTIVITY>
  <PACKETTRACER5>
    <NETWORK>
      <DEVICES>
        <DEVICE>
          <ENGINE>
            <NAME>R1</NAME>
            <RUNNINGCONFIG>
              <LINE>hostname R1</LINE>
              <LINE>interface G0/0</LINE>
              <LINE>ip address 10.0.0.1 255.255.255.0</LINE>
            </RUNNINGCONFIG>
          </ENGINE>
        </DEVICE>
      </DEVICES>
    </NETWORK>
  </PACKETTRACER5>
  <PACKETTRACER5><NETWORK><DEVICES></DEVICES></NETWORK></PACKETTRACER5>
  <PACKETTRACER5>
    <NETWORK>
      <DEVICES>
        <DEVICE>
          <ENGINE>
            <NAME>R1</NAME>
            <RUNNINGCONFIG>
              <LINE>hostname R1</LINE>
              <LINE>interface G0/0</LINE>
              <LINE>ip address 10.0.0.1 255.255.255.0</LINE>
            </RUNNINGCONFIG>
          </ENGINE>
        </DEVICE>
      </DEVICES>
    </NETWORK>
  </PACKETTRACER5>
</PACKETTRACER5_ACTIVITY>
"""
        path = _write_tmp(_make_zip_bytes(xml_content=xml_content,
                                          entry_name="default.xml"))
        try:
            result = parse_pka_file(path)
            assert result["error"] is None
            assert result["score"] == "3"
            assert result["max_score"] == "3"
            assert result["percentage"] == "100.0%"
        finally:
            os.unlink(path)

    def test_config_comparison_fallback_to_comparisons(self):
        """When fewer than 3 PT5 elements exist, COMPARISONS tree is used."""
        xml_content = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<PACKETTRACER5_ACTIVITY>
  <COMPARISONS>
    <NODE><POINTS>1</POINTS></NODE>
    <NODE><POINTS>0</POINTS></NODE>
  </COMPARISONS>
</PACKETTRACER5_ACTIVITY>
"""
        path = _write_tmp(_make_zip_bytes(xml_content=xml_content,
                                          entry_name="default.xml"))
        try:
            result = parse_pka_file(path)
            assert result["score"] == "1"
            assert result["max_score"] == "2"
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Tests for encrypted PKA files with different student scores
# ---------------------------------------------------------------------------

_SAMPLE_PKA_DIR = os.path.dirname(__file__)
_SAMPLE_87 = os.path.join(_SAMPLE_PKA_DIR, "87.pka")
_SAMPLE_97 = os.path.join(_SAMPLE_PKA_DIR, "97.pka")
_SAMPLE_99 = os.path.join(_SAMPLE_PKA_DIR, "99.pka")
_HAS_SAMPLE_PKAS = all(os.path.isfile(p) for p in [_SAMPLE_87, _SAMPLE_97, _SAMPLE_99])


@pytest.mark.skipif(not _HAS_SAMPLE_PKAS, reason="sample PKA test files not present")
class TestDifferentStudentScores:
    """Verify that different student submissions produce different scores."""

    def test_scores_are_different(self):
        """Files with different student work must produce different percentages."""
        results = {}
        for path in [_SAMPLE_87, _SAMPLE_97, _SAMPLE_99]:
            r = parse_pka_file(path)
            results[path] = r
            assert r["error"] is None, f"{path}: {r['error']}"

        pcts = [results[p]["percentage"] for p in [_SAMPLE_87, _SAMPLE_97, _SAMPLE_99]]
        assert len(set(pcts)) == 3, f"Expected 3 different percentages, got {pcts}"

        # Verify percentages are in the expected range for each file.
        # Property evaluation produces per-item scoring (out of 149 items).
        pct87 = float(results[_SAMPLE_87]["percentage"].rstrip("%"))
        pct97 = float(results[_SAMPLE_97]["percentage"].rstrip("%"))
        pct99 = float(results[_SAMPLE_99]["percentage"].rstrip("%"))
        assert 83.0 <= pct87 <= 93.0, f"87.pka: expected ~88%, got {pct87}%"
        assert 90.0 <= pct97 <= 100.0, f"97.pka: expected ~95%, got {pct97}%"
        assert 97.0 <= pct99 <= 100.0, f"99.pka: expected ~100%, got {pct99}%"

    def test_score_ordering(self):
        """87.pka < 97.pka < 99.pka in score percentage."""
        r87 = parse_pka_file(_SAMPLE_87)
        r97 = parse_pka_file(_SAMPLE_97)
        r99 = parse_pka_file(_SAMPLE_99)

        pct87 = float(r87["percentage"].rstrip("%"))
        pct97 = float(r97["percentage"].rstrip("%"))
        pct99 = float(r99["percentage"].rstrip("%"))

        assert pct87 < pct97 < pct99

    def test_user_profile_names(self):
        """97.pka and 99.pka should have non-Guest user profile names."""
        r97 = parse_pka_file(_SAMPLE_97)
        r99 = parse_pka_file(_SAMPLE_99)

        assert r97["user_profile_name"] != "N/A"
        assert r97["user_profile_name"] != "Guest"
        assert r99["user_profile_name"] != "N/A"
        assert r99["user_profile_name"] != "Guest"


# ---------------------------------------------------------------------------
# Tests for config comparison with non-empty initial state
# ---------------------------------------------------------------------------

class TestConfigComparisonInitialState:
    """Verify that config comparison correctly subtracts initial-state lines."""

    def test_initial_lines_not_counted(self):
        """Lines already present in the initial state should not inflate the score."""
        xml_content = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<PACKETTRACER5_ACTIVITY>
  <PACKETTRACER5>
    <NETWORK><DEVICES><DEVICE><ENGINE>
      <NAME>R1</NAME>
      <RUNNINGCONFIG>
        <LINE>hostname R1</LINE>
        <LINE>interface G0/0</LINE>
        <LINE>ip address 10.0.0.1 255.255.255.0</LINE>
      </RUNNINGCONFIG>
    </ENGINE></DEVICE></DEVICES></NETWORK>
  </PACKETTRACER5>
  <PACKETTRACER5>
    <NETWORK><DEVICES><DEVICE><ENGINE>
      <NAME>R1</NAME>
      <RUNNINGCONFIG>
        <LINE>hostname R1</LINE>
        <LINE>interface G0/0</LINE>
        <LINE>ip address 10.0.0.1 255.255.255.0</LINE>
      </RUNNINGCONFIG>
    </ENGINE></DEVICE></DEVICES></NETWORK>
  </PACKETTRACER5>
  <PACKETTRACER5>
    <NETWORK><DEVICES><DEVICE><ENGINE>
      <NAME>R1</NAME>
      <RUNNINGCONFIG>
        <LINE>hostname R1</LINE>
        <LINE>interface G0/0</LINE>
        <LINE>ip address 10.0.0.1 255.255.255.0</LINE>
        <LINE>ip route 0.0.0.0 0.0.0.0 10.0.0.254</LINE>
        <LINE>ip route 192.168.0.0 255.255.0.0 10.0.0.1</LINE>
      </RUNNINGCONFIG>
    </ENGINE></DEVICE></DEVICES></NETWORK>
  </PACKETTRACER5>
</PACKETTRACER5_ACTIVITY>
"""
        path = _write_tmp(_make_zip_bytes(xml_content=xml_content,
                                          entry_name="default.xml"))
        try:
            result = parse_pka_file(path)
            assert result["error"] is None
            # The initial state already has 3 lines (hostname, interface, ip address).
            # Only 2 lines are new in the answer (the two ip routes).
            # The student has 0 of the new lines.
            assert result["score"] == "0"
            assert result["max_score"] == "2"
            assert result["percentage"] == "0.0%"
        finally:
            os.unlink(path)

    def test_duplicate_lines_scored_individually(self):
        """Duplicate config lines (e.g. 'shutdown' on multiple interfaces) are scored."""
        xml_content = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<PACKETTRACER5_ACTIVITY>
  <PACKETTRACER5>
    <NETWORK><DEVICES><DEVICE><ENGINE>
      <NAME>SW1</NAME>
      <RUNNINGCONFIG>
        <LINE>interface Vlan10</LINE>
        <LINE>shutdown</LINE>
        <LINE>interface Vlan20</LINE>
        <LINE>no shutdown</LINE>
      </RUNNINGCONFIG>
    </ENGINE></DEVICE></DEVICES></NETWORK>
  </PACKETTRACER5>
  <PACKETTRACER5>
    <NETWORK><DEVICES><DEVICE><ENGINE>
      <NAME>SW1</NAME>
      <RUNNINGCONFIG>
        <LINE>interface Vlan10</LINE>
        <LINE>shutdown</LINE>
        <LINE>interface Vlan20</LINE>
        <LINE>shutdown</LINE>
      </RUNNINGCONFIG>
    </ENGINE></DEVICE></DEVICES></NETWORK>
  </PACKETTRACER5>
  <PACKETTRACER5>
    <NETWORK><DEVICES><DEVICE><ENGINE>
      <NAME>SW1</NAME>
      <RUNNINGCONFIG>
        <LINE>interface Vlan10</LINE>
        <LINE>no shutdown</LINE>
        <LINE>interface Vlan20</LINE>
        <LINE>no shutdown</LINE>
      </RUNNINGCONFIG>
    </ENGINE></DEVICE></DEVICES></NETWORK>
  </PACKETTRACER5>
</PACKETTRACER5_ACTIVITY>
"""
        path = _write_tmp(_make_zip_bytes(xml_content=xml_content,
                                          entry_name="default.xml"))
        try:
            result = parse_pka_file(path)
            assert result["error"] is None
            # Initial has 2x "shutdown". Answer has 2x "no shutdown" and 0x "shutdown".
            # Required (answer - initial): 2x "no shutdown" (new in answer).
            # Student has 1x "no shutdown", so earned = 1 of 2 required.
            assert result["score"] == "1"
            assert result["max_score"] == "2"
            assert result["percentage"] == "50.0%"
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Tests for CET1000 Midterm student files
# ---------------------------------------------------------------------------

_SAMPLE_TIRTH = os.path.join(
    _SAMPLE_PKA_DIR,
    "Tirth Tejas Bhavsar_2959567_assignsubmission_file_CET1000-Midterm-SBA-V2.pka",
)
_SAMPLE_DARIEN = os.path.join(
    _SAMPLE_PKA_DIR,
    "Darien Etherington_2959573_assignsubmission_file_"
    "Darien Etherington A00322541 CET1000-Midterm-SBA-V2.pka",
)
_SAMPLE_BLAKE = os.path.join(
    _SAMPLE_PKA_DIR,
    "Blake Lapointe_2959570_assignsubmission_file_CET1000-Midterm-SBA-V2.pka",
)
_SAMPLE_KEATEN = os.path.join(
    _SAMPLE_PKA_DIR,
    "Keaten Reuben_2959559_assignsubmission_file_CET1000-Midterm-SBA-V2 - Completed.pka",
)
_SAMPLE_CHHAVI = os.path.join(
    _SAMPLE_PKA_DIR,
    "Chhavi Chhavi_2959583_assignsubmission_file_midterm-A00320667.pka",
)
_HAS_MIDTERM_PKAS = all(
    os.path.isfile(p)
    for p in [_SAMPLE_TIRTH, _SAMPLE_DARIEN, _SAMPLE_BLAKE, _SAMPLE_KEATEN, _SAMPLE_CHHAVI]
)


@pytest.mark.skipif(not _HAS_MIDTERM_PKAS, reason="CET1000 Midterm PKA files not present")
class TestMidtermStudentScores:
    """Verify scoring of CET1000 Midterm SBA student submissions."""

    def test_scores_exact(self):
        """Each student file scores exactly the expected mark."""
        expected = {
            _SAMPLE_TIRTH: (10, "Tirth Bhavsar"),
            _SAMPLE_DARIEN: (86, "Darien Etherington"),
            _SAMPLE_BLAKE: (48, "Blake Lapointe"),
            _SAMPLE_KEATEN: (50, "Keaten Reuben"),
            _SAMPLE_CHHAVI: (85, "Chhavi"),
        }

        for path, (exp_score, exp_name) in expected.items():
            result = parse_pka_file(path)
            assert result["error"] is None, f"{path}: {result['error']}"
            score = int(result["score"])
            max_score = int(result["max_score"])
            assert max_score == 100, (
                f"{os.path.basename(path)}: expected max_score=100, "
                f"got {max_score}"
            )
            assert score == exp_score, (
                f"{os.path.basename(path)}: expected {exp_score}/100, "
                f"got {score}/100"
            )
            pct = float(result["percentage"].rstrip("%"))
            assert pct == float(exp_score), (
                f"{os.path.basename(path)}: expected {exp_score}.0%, "
                f"got {pct}%"
            )
            assert result["user_profile_name"] == exp_name, (
                f"{os.path.basename(path)}: expected name '{exp_name}', "
                f"got '{result['user_profile_name']}'"
            )

    def test_score_ordering(self):
        """Scores should reflect relative student performance."""
        results = {}
        for path in [_SAMPLE_TIRTH, _SAMPLE_BLAKE, _SAMPLE_KEATEN,
                      _SAMPLE_CHHAVI, _SAMPLE_DARIEN]:
            results[path] = parse_pka_file(path)

        pct_tirth = float(results[_SAMPLE_TIRTH]["percentage"].rstrip("%"))
        pct_blake = float(results[_SAMPLE_BLAKE]["percentage"].rstrip("%"))
        pct_keaten = float(results[_SAMPLE_KEATEN]["percentage"].rstrip("%"))
        pct_chhavi = float(results[_SAMPLE_CHHAVI]["percentage"].rstrip("%"))
        pct_darien = float(results[_SAMPLE_DARIEN]["percentage"].rstrip("%"))

        # Tirth (10%) < Blake (48%) < Keaten (50%) < Darien/Chhavi (~85%)
        assert pct_tirth < pct_blake < pct_keaten
        assert pct_keaten < pct_chhavi
        assert pct_keaten < pct_darien

    def test_all_have_different_scores(self):
        """Each student should have a distinct percentage."""
        pcts = set()
        for path in [_SAMPLE_TIRTH, _SAMPLE_DARIEN, _SAMPLE_BLAKE,
                      _SAMPLE_KEATEN, _SAMPLE_CHHAVI]:
            result = parse_pka_file(path)
            pcts.add(result["percentage"])
        assert len(pcts) == 5, f"Expected 5 distinct scores, got {pcts}"


# ---------------------------------------------------------------------------
# Tests for generic answer-key comparison fallback
# ---------------------------------------------------------------------------

class TestGenericPropertyEvaluation:
    """Verify the generic answer-key comparison fallback works correctly."""

    def test_generic_matches_nodevalue_in_answer_config(self):
        """Generic evaluator finds a nodeValue-bearing line in the student config."""
        from pka_parser import _parse_config_sections
        item = {
            "nodeValue": "192.168.10.1",
            "id": "IP Address",
            "name": "IP Address",
            "device": "R1",
            "path": ["Ports", "GigabitEthernet0/0", "IP Address"],
            "path_ids": [],
        }
        student_lines = [
            "interface GigabitEthernet0/0",
            " ip address 192.168.10.1 255.255.255.0",
            " no shutdown",
        ]
        student_set = set(l.strip() for l in student_lines if l)
        sections = _parse_config_sections(student_lines)
        answer_lines = [
            "interface GigabitEthernet0/0",
            " ip address 192.168.10.1 255.255.255.0",
            " no shutdown",
        ]
        initial_lines = [
            "interface GigabitEthernet0/0",
            " shutdown",
        ]
        answer_sections = _parse_config_sections(answer_lines)

        result = _evaluate_ct2_item_generic(
            item, student_lines, student_set, sections,
            answer_lines, initial_lines, answer_sections)
        assert result is True

    def test_generic_fails_when_student_missing_line(self):
        """Generic evaluator returns False when the student doesn't have the line."""
        from pka_parser import _parse_config_sections
        item = {
            "nodeValue": "192.168.10.1",
            "id": "IP Address",
            "name": "IP Address",
            "device": "R1",
            "path": ["Ports", "GigabitEthernet0/0", "IP Address"],
            "path_ids": [],
        }
        student_lines = [
            "interface GigabitEthernet0/0",
            " shutdown",
        ]
        student_set = set(l.strip() for l in student_lines if l)
        sections = _parse_config_sections(student_lines)
        answer_lines = [
            "interface GigabitEthernet0/0",
            " ip address 192.168.10.1 255.255.255.0",
        ]
        initial_lines = []
        answer_sections = _parse_config_sections(answer_lines)

        result = _evaluate_ct2_item_generic(
            item, student_lines, student_set, sections,
            answer_lines, initial_lines, answer_sections)
        assert result is False

    def test_generic_returns_none_for_empty_nodevalue(self):
        """Generic evaluator returns None when nodeValue is empty."""
        from pka_parser import _parse_config_sections
        item = {
            "nodeValue": "",
            "id": "SomeProp",
            "name": "SomeProp",
            "device": "R1",
            "path": ["Section", "SomeProp"],
            "path_ids": [],
        }
        result = _evaluate_ct2_item_generic(
            item, [], set(), _parse_config_sections([]),
            [], [], _parse_config_sections([]))
        assert result is None

    def test_generic_excludes_initial_state_lines(self):
        """Generic evaluator ignores lines already present in initial config."""
        from pka_parser import _parse_config_sections
        item = {
            "nodeValue": "10.0.0.1",
            "id": "IP Address",
            "name": "IP Address",
            "device": "R1",
            "path": ["Section", "IP Address"],
            "path_ids": [],
        }
        config_line = "ip address 10.0.0.1 255.255.255.0"
        # The line is in both answer AND initial — so it's not required.
        student_lines = [config_line]
        student_set = set(student_lines)
        sections = _parse_config_sections(student_lines)
        answer_lines = [config_line]
        initial_lines = [config_line]
        answer_sections = _parse_config_sections(answer_lines)

        result = _evaluate_ct2_item_generic(
            item, student_lines, student_set, sections,
            answer_lines, initial_lines, answer_sections)
        # All matching answer lines were in initial → can't determine → None
        assert result is None


# ---------------------------------------------------------------------------
# Tests for property evaluation with unsupported types (no abort)
# ---------------------------------------------------------------------------

class TestPropertyEvalNoAbort:
    """Verify property evaluation doesn't abort on unsupported property types."""

    def test_property_eval_uses_generic_for_unknown_types(self):
        """Property evaluation returns a score even with unknown property types."""
        import xml.etree.ElementTree as ET
        # Build a minimal XML with 3 PT5 elements and a COMPARISONS tree
        # containing one known item and one unknown item.
        xml_content = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<PACKETTRACER5_ACTIVITY>
  <PACKETTRACER5>
    <NETWORK><DEVICES><DEVICE><ENGINE>
      <NAME>R1</NAME>
      <RUNNINGCONFIG>
        <LINE>hostname R1</LINE>
        <LINE>service password-encryption</LINE>
        <LINE>ip address 10.0.0.1 255.255.255.0</LINE>
      </RUNNINGCONFIG>
    </ENGINE></DEVICE></DEVICES></NETWORK>
  </PACKETTRACER5>
  <PACKETTRACER5>
    <NETWORK><DEVICES><DEVICE><ENGINE>
      <NAME>R1</NAME>
      <RUNNINGCONFIG>
        <LINE>hostname R1</LINE>
      </RUNNINGCONFIG>
    </ENGINE></DEVICE></DEVICES></NETWORK>
  </PACKETTRACER5>
  <PACKETTRACER5>
    <NETWORK><DEVICES><DEVICE><ENGINE>
      <NAME>R1</NAME>
      <RUNNINGCONFIG>
        <LINE>hostname R1</LINE>
        <LINE>service password-encryption</LINE>
        <LINE>ip address 10.0.0.1 255.255.255.0</LINE>
      </RUNNINGCONFIG>
    </ENGINE></DEVICE></DEVICES></NETWORK>
  </PACKETTRACER5>
  <COMPARISONS>
    <NODE>
      <NAME checkType="0">Root</NAME>
      <ID>Root</ID>
      <POINTS></POINTS>
      <NODE>
        <NAME checkType="0">R1</NAME>
        <ID>R1</ID>
        <POINTS></POINTS>
        <NODE>
          <NAME checkType="2" nodeValue="1">Service Password Encryption</NAME>
          <ID>Service Password Encryption</ID>
          <POINTS>1</POINTS>
        </NODE>
        <NODE>
          <NAME checkType="2" nodeValue="10.0.0.1">UnknownCustomProp</NAME>
          <ID>UnknownCustomProp</ID>
          <POINTS>1</POINTS>
        </NODE>
      </NODE>
    </NODE>
  </COMPARISONS>
</PACKETTRACER5_ACTIVITY>
"""
        root = ET.fromstring(xml_content)
        result = _score_by_property_evaluation(root)
        # Should NOT return None (i.e. should not abort).
        assert result is not None
        earned, total = result
        assert total == 2
        # "Service Password Encryption" is known → True
        # "UnknownCustomProp" nv="10.0.0.1" → generic fallback finds the line
        assert earned == 2

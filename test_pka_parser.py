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
    _open_pka_as_zip,
    _score_by_config_comparison,
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
        assert float(result["score"]) > 0
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

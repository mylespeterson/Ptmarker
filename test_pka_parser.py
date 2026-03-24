"""
Tests for pka_parser.py — focused on the ZIP-opening logic that handles
PKA files with proprietary binary headers prepended to the ZIP data.
"""

import io
import os
import tempfile
import zipfile

import pytest

from pka_parser import _open_pka_as_zip, parse_pka_file


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

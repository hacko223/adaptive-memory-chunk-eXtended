# tests/test_writer_reader.py
# Basic write and read tests

import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from amcx import (
    AMCXWriter, AMCXReader, ChunkEntry,
    COMPRESS_NONE, COMPRESS_ZLIB, COMPRESS_LZMA,
    CHUNK_LORE, CHUNK_CHARACTER, CHUNK_ACTIVE,
    AMCXInvalidFileError, AMCXChunkNotFoundError, AMCXCorruptError,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def build_simple_amc() -> bytes:
    """Creates a minimal .amcx in memory with 2 chunks."""
    w = AMCXWriter()
    w.add_text_chunk(0, CHUNK_LORE,      "The world",       "The world is a dark place.",         COMPRESS_ZLIB)
    w.add_text_chunk(1, CHUNK_CHARACTER, "Character Aria",  "Aria is an elven warrior.",           COMPRESS_LZMA)
    w.add_text_chunk(2, CHUNK_ACTIVE,    "Current session", "The group has just arrived at the tavern.", COMPRESS_ZLIB)
    return w.to_bytes()


# ─── Write tests ──────────────────────────────────────────────────────────────

def test_magic_bytes():
    data = build_simple_amc()
    assert data[:4] == b'AMC\x00', "Magic bytes must be AMC\\0"


def test_file_not_empty():
    data = build_simple_amc()
    assert len(data) > 32, "The file must have more than just the header"


def test_three_chunks_written():
    data = build_simple_amc()
    import struct
    num_chunks = struct.unpack('>I', data[6:10])[0]
    assert num_chunks == 3


# ─── Read tests ───────────────────────────────────────────────────────────────

def test_read_index(tmp_path):
    path = tmp_path / "test.amcx"
    path.write_bytes(build_simple_amc())

    with AMCXReader(str(path)) as r:
        entries = r.list_chunks()
        assert len(entries) == 3
        assert entries[0].summary == "The world"
        assert entries[1].summary == "Character Aria"
        assert entries[2].summary == "Current session"


def test_read_chunk_content(tmp_path):
    path = tmp_path / "test.amcx"
    path.write_bytes(build_simple_amc())

    with AMCXReader(str(path)) as r:
        text = r.read_chunk_text(0)
        assert "dark" in text

        text2 = r.read_chunk_text(1)
        assert "elven" in text2


def test_read_active_chunk(tmp_path):
    path = tmp_path / "test.amcx"
    path.write_bytes(build_simple_amc())

    with AMCXReader(str(path)) as r:
        assert r.header.has_active_chunk
        content = r.read_active_chunk()
        assert content is not None
        assert b"tavern" in content


def test_compression_algorithms(tmp_path):
    """Verifies that all three algorithms work correctly."""
    w = AMCXWriter()
    w.add_text_chunk(0, CHUNK_LORE, "Uncompressed", "uncompressed text",  COMPRESS_NONE)
    w.add_text_chunk(1, CHUNK_LORE, "Zlib",         "text with zlib",     COMPRESS_ZLIB)
    w.add_text_chunk(2, CHUNK_LORE, "Lzma",         "text with lzma",     COMPRESS_LZMA)

    path = tmp_path / "compress_test.amcx"
    path.write_bytes(w.to_bytes())

    with AMCXReader(str(path)) as r:
        assert r.read_chunk_text(0) == "uncompressed text"
        assert r.read_chunk_text(1) == "text with zlib"
        assert r.read_chunk_text(2) == "text with lzma"


# ─── Error tests ──────────────────────────────────────────────────────────────

def test_invalid_magic(tmp_path):
    path = tmp_path / "bad.amcx"
    path.write_bytes(b'XXXX' + b'\x00' * 28)
    with pytest.raises(AMCXInvalidFileError):
        AMCXReader(str(path))


def test_chunk_not_found(tmp_path):
    path = tmp_path / "test.amcx"
    path.write_bytes(build_simple_amc())
    with AMCXReader(str(path)) as r:
        with pytest.raises(AMCXChunkNotFoundError):
            r.read_chunk(999)


def test_corrupt_header(tmp_path):
    data = bytearray(build_simple_amc())
    data[5] ^= 0xFF   # corrupt the version minor byte (affects the CRC)
    path = tmp_path / "corrupt.amcx"
    path.write_bytes(bytes(data))
    with pytest.raises(AMCXCorruptError):
        AMCXReader(str(path))


# ─── Summary test ─────────────────────────────────────────────────────────────

def test_summary_output(tmp_path, capsys):
    path = tmp_path / "test.amcx"
    path.write_bytes(build_simple_amc())
    with AMCXReader(str(path)) as r:
        output = r.summary()
        assert "AMC" in output
        assert "The world" in output
        assert "Current session" in output


# ─── Per-chunk CRC32 tests ────────────────────────────────────────────────────

def test_chunk_crc32_stored_in_index(tmp_path):
    """The CRC32 of each chunk must be stored in the index."""
    path = tmp_path / "test.amcx"
    path.write_bytes(build_simple_amc())
    with AMCXReader(str(path)) as r:
        for entry in r.list_chunks():
            assert entry.crc32 != 0, f"Chunk {entry.chunk_id} has no CRC32"

def test_chunk_crc32_detects_corruption(tmp_path):
    """If the content of a chunk is modified, read_chunk must raise AMCXCorruptError."""
    import struct as _struct
    from amcx import AMCXCorruptError

    data = bytearray(build_simple_amc())

    # Read the offset of the first chunk from the index (header=32 bytes, first offset field is at pos 4)
    chunk_offset = _struct.unpack_from('>I', data, 32 + 4)[0]
    data[chunk_offset + 4] ^= 0xFF  # corrupt the first byte of compressed data

    path = tmp_path / 'corrupt_chunk.amcx'
    path.write_bytes(bytes(data))

    with AMCXReader(str(path)) as r:
        with pytest.raises(AMCXCorruptError):
            r.read_chunk(0)

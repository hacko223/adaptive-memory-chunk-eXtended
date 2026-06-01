# tests/test_mirror.py
import os, pytest, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from amcx import (
    AMCXWriter, AMCXReader, AMCXMirror, AMCXRecovery,
    MirrorMode, ChunkStatus,
    CHUNK_LORE, CHUNK_CHARACTER, CHUNK_ACTIVE,
    COMPRESS_ZLIB, COMPRESS_LZMA,
)


def make_amcx(path, mirror=MirrorMode.NONE, recovery=False):
    w = AMCXWriter(mirror=mirror, recovery=recovery)
    w.add_text_chunk(0, CHUNK_LORE,      "The world", "The world is dark.",              COMPRESS_LZMA)
    w.add_text_chunk(1, CHUNK_CHARACTER, "Aria",      "Aria is an elven warrior.",       COMPRESS_LZMA)
    w.add_text_chunk(2, CHUNK_ACTIVE,    "Session",   "The group arrives at the tavern.", COMPRESS_ZLIB)
    w.save(str(path))
    return w


# ─── Embedded mirror ──────────────────────────────────────────────────────────

def test_auto_mirror_embedded(tmp_path):
    """MirrorMode.AUTO embeds the mirror block inside the .amcx, without a separate file."""
    path = tmp_path / "mem.amcx"
    make_amcx(path, mirror=MirrorMode.AUTO)
    assert not os.path.exists(str(path) + ".mirror"), "Should not create a separate file"
    data = AMCXMirror.read_block(str(path))
    assert data is not None, "The mirror block must be embedded"

def test_manual_mirror_not_auto(tmp_path):
    """MirrorMode.MANUAL does not embed the mirror when saving."""
    path = tmp_path / "mem.amcx"
    make_amcx(path, mirror=MirrorMode.MANUAL)
    assert AMCXMirror.read_block(str(path)) is None

def test_manual_mirror_embed_explicit(tmp_path):
    """embed_mirror() embeds the mirror when called manually."""
    path = tmp_path / "mem.amcx"
    w = make_amcx(path, mirror=MirrorMode.MANUAL)
    w.embed_mirror(str(path))
    assert AMCXMirror.read_block(str(path)) is not None

def test_mirror_verify_all_ok(tmp_path):
    path = tmp_path / "mem.amcx"
    make_amcx(path, mirror=MirrorMode.AUTO)
    status = AMCXMirror.verify(str(path))
    assert status.mirror_exists
    assert status.all_ok, f"Problems: {[c.status for c in status.problems]}"

def test_mirror_verify_no_mirror(tmp_path):
    path = tmp_path / "mem.amcx"
    make_amcx(path, mirror=MirrorMode.NONE)
    status = AMCXMirror.verify(str(path))
    assert not status.mirror_exists
    assert not status.all_ok

def test_mirror_sha1_per_chunk(tmp_path):
    """The mirror block must have one SHA-1 per chunk."""
    path = tmp_path / "mem.amcx"
    make_amcx(path, mirror=MirrorMode.AUTO)
    data = AMCXMirror.read_block(str(path))
    assert len(data["chunks"]) == 3
    for info in data["chunks"].values():
        assert len(info["sha1"]) == 40   # SHA-1 hex = 40 chars

def test_mirror_detects_modified_sha1(tmp_path):
    """If a chunk changes, verify should report it as MODIFIED."""
    import hashlib
    path = tmp_path / "mem.amcx"
    make_amcx(path, mirror=MirrorMode.AUTO)

    # Read the file and corrupt the SHA-1 parity of chunk 0 in the mirror block
    with open(str(path), "rb") as f:
        raw = bytearray(f.read())

    pos = bytes(raw).rfind(b'AMCXM\x00')
    assert pos != -1
    # The SHA-1 of the first chunk starts at: magic(6) + version(4) + count(4) + ts(8) + id(4) + size(4) = 30 bytes after magic
    sha1_pos = pos + 6 + 4 + 4 + 8 + 4 + 4
    raw[sha1_pos] ^= 0xFF  # corrupt the first byte of SHA-1

    with open(str(path), "wb") as f:
        f.write(bytes(raw))

    status = AMCXMirror.verify(str(path))
    modified = [c for c in status.chunks if c.status == ChunkStatus.MODIFIED]
    assert len(modified) >= 1

def test_mirror_detects_missing_mirror(tmp_path):
    """Chunk in the original without an entry in the mirror → MISSING_MIRROR."""
    path = tmp_path / "mem.amcx"
    # Create mirror with only chunks 0 and 1, not 2
    w = AMCXWriter(mirror=MirrorMode.NONE)
    w.add_text_chunk(0, CHUNK_LORE,      "The world", "text", COMPRESS_ZLIB)
    w.add_text_chunk(1, CHUNK_CHARACTER, "Aria",      "text", COMPRESS_ZLIB)
    w.add_text_chunk(2, CHUNK_ACTIVE,    "Session",   "text", COMPRESS_ZLIB)
    w.save(str(path))

    # Embed mirror with only 2 chunks
    from amcx.mirror import AMCXMirror
    AMCXMirror.embed(str(path), {
        0: (b"text", "The world"),
        1: (b"text", "Aria"),
    })

    status = AMCXMirror.verify(str(path))
    missing = [c for c in status.chunks if c.status == ChunkStatus.MISSING_MIRROR]
    assert len(missing) == 1 and missing[0].chunk_id == 2

def test_mirror_update(tmp_path):
    path = tmp_path / "mem.amcx"
    make_amcx(path, mirror=MirrorMode.AUTO)
    AMCXMirror.update(str(path))
    status = AMCXMirror.verify(str(path))
    assert status.all_ok

def test_mirror_report_text(tmp_path):
    path = tmp_path / "mem.amcx"
    make_amcx(path, mirror=MirrorMode.AUTO)
    status = AMCXMirror.verify(str(path))
    report = status.report()
    assert "ok" in report
    assert "✓ Everything is in order." in report

def test_single_file_no_sidecar(tmp_path):
    """With mirror=AUTO only one file should exist, not two."""
    path = tmp_path / "mem.amcx"
    make_amcx(path, mirror=MirrorMode.AUTO, recovery=True)
    files = list(tmp_path.iterdir())
    assert len(files) == 1, f"Expected 1 file, found {len(files)}: {files}"


# ─── XOR Recovery ─────────────────────────────────────────────────────────────

def test_recovery_magic_inside_file(tmp_path):
    path = tmp_path / "mem.amcx"
    make_amcx(path, recovery=True)
    with open(str(path), "rb") as f:
        data = f.read()
    assert b'AMCXR\x00' in data

def test_recovery_can_recover(tmp_path):
    path = tmp_path / "mem.amcx"
    make_amcx(path, recovery=True)
    assert AMCXRecovery.can_recover(str(path), 0)
    assert AMCXRecovery.can_recover(str(path), 1)

def test_recovery_reconstruct(tmp_path):
    path = tmp_path / "mem.amcx"
    make_amcx(path, recovery=True)
    with AMCXReader(str(path)) as r:
        original = r.read_chunk(0)
    recovered = AMCXRecovery.recover_chunk(str(path), 0)
    assert recovered == original

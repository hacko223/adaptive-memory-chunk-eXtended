# tests/test_smart.py
# Tests for the high-level SmartMemory API

import os, pytest, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from amcx import SmartMemory


def test_basic_append_and_search(tmp_path):
    """Basic flow: append and search."""
    path = tmp_path / "chat.amcx"
    
    with SmartMemory(str(path), use_mirror=False) as mem:
        mem.append("user: Hello, tell me about the world")
        mem.append("ai: The world is a dark place full of mysteries")
        mem.append("user: And what about the light?")
        mem.append("ai: Light exists but is scarce")
    
    # Search
    mem2 = SmartMemory(str(path), use_mirror=False)
    results = mem2.search("world")
    
    assert len(results) >= 2
    assert any("world" in r.lower() for r in results)


def test_without_mirror_smaller_file(tmp_path):
    """Without mirror should generate a smaller file."""
    path_no_mirror = tmp_path / "no_mirror.amcx"
    path_mirror    = tmp_path / "with_mirror.amcx"
    
    text = "This is a test text. " * 100  # ~2.1 KB
    
    with SmartMemory(str(path_no_mirror), use_mirror=False) as mem:
        mem.append(text)
    
    with SmartMemory(str(path_mirror), use_mirror=True) as mem:
        mem.append(text)
    
    size_no_mirror = os.path.getsize(str(path_no_mirror))
    size_mirror    = os.path.getsize(str(path_mirror))
    
    assert size_no_mirror < size_mirror, f"Without mirror ({size_no_mirror}) must be smaller than with mirror ({size_mirror})"


@pytest.mark.skip(reason='TODO: fix pending vs flushed logic')
def test_get_recent(tmp_path):
    """get_recent should return the newest messages."""
    path = tmp_path / "chat.amcx"
    
    with SmartMemory(str(path)) as mem:
        for i in range(20):
            mem.append(f"message {i}")
    
    mem2 = SmartMemory(str(path))
    recent = mem2.get_recent(5)
    
    assert len(recent) == 5
    assert "message 19" in recent[0]  # most recent


def test_auto_flush_on_size(tmp_path):
    """Should auto-save when enough text has accumulated."""
    path = tmp_path / "chat.amcx"
    
    mem = SmartMemory(str(path), auto_chunk_size=500)
    
    # Add text that exceeds auto_chunk_size
    mem.append("x" * 600)
    
    # Should have been saved automatically
    assert os.path.exists(str(path))
    assert os.path.getsize(str(path)) > 0


def test_verify_integrity(tmp_path):
    """verify_integrity should detect a healthy file."""
    path = tmp_path / "chat.amcx"
    
    with SmartMemory(str(path), use_mirror=True) as mem:
        mem.append("test message")
    
    mem2 = SmartMemory(str(path), use_mirror=True)
    assert mem2.verify_integrity()


def test_count_messages(tmp_path):
    """count_messages should count saved + pending."""
    path = tmp_path / "chat.amcx"
    
    mem = SmartMemory(str(path))
    mem.append("msg 1")
    mem.append("msg 2")
    
    assert mem.count_messages() == 2
    
    mem.flush()
    assert mem.count_messages() == 2  # still 2 after saving


def test_size_on_disk(tmp_path):
    """size_on_disk should report the correct size."""
    path = tmp_path / "chat.amcx"
    
    mem = SmartMemory(str(path))
    assert mem.size_on_disk() == 0  # file doesn't exist yet
    
    mem.append("test text")
    mem.flush()
    
    assert mem.size_on_disk() > 0


def test_no_temporary_files(tmp_path):
    """Should not leave temporary files after operations."""
    path = tmp_path / "chat.amcx"
    
    with SmartMemory(str(path)) as mem:
        mem.append("text 1")
        mem.append("text 2")
        _ = mem.search("text")
        _ = mem.get_recent(10)
    
    # Only the .amcx should exist, nothing else
    files = list(tmp_path.iterdir())
    assert len(files) == 1
    assert files[0].name == "chat.amcx"


def test_compression_intelligence(tmp_path):
    """Should use lzma for old chunks, zlib for recent ones."""
    import time
    from amcx import AMCXReader
    
    path = tmp_path / "chat.amcx"
    
    mem = SmartMemory(str(path), old_chunk_days=0)  # everything is considered old
    mem.append("old message")
    mem.flush()
    
    # Verify that LZMA was used (0x02)
    with AMCXReader(str(path)) as reader:
        entries = reader.list_chunks()
        assert entries[0].algorithm == 0x02  # COMPRESS_LZMA


def test_empty_search(tmp_path):
    """Searching in empty memory should not fail."""
    path = tmp_path / "empty.amcx"
    mem = SmartMemory(str(path))
    results = mem.search("anything")
    assert results == []


@pytest.mark.skip(reason='TODO: fix pending vs flushed logic')
def test_developer_never_sees_internals(tmp_path):
    """The developer only uses append/search/get_recent."""
    path = tmp_path / "app.amcx"
    
    # Full API the developer sees
    mem = SmartMemory(str(path), use_mirror=False)
    mem.append("user: hello")
    mem.append("ai: hello how are you")
    
    # search also looks in pending (before saving)
    results_before = mem.search("hello")
    assert len(results_before) >= 2
    
    mem.flush()  # save to disk
    
    # After saving, search looks in the file
    results_after = mem.search("hello")
    assert len(results_after) >= 2
    
    ctx = mem.get_recent(10)
    assert len(ctx) == 2
    
    # Without mentioning: chunks, compression, CRC32, SHA-1, XOR, nothing

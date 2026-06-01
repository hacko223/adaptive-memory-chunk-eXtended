# amcx/writer.py
# Writing .amcx files

import io
import time
import zlib
import struct
from dataclasses import dataclass, field
from typing import Optional

from .format import (
    MAGIC, VERSION_MAJOR, VERSION_MINOR,
    COMPRESS_NONE, COMPRESS_ZLIB, COMPRESS_LZMA,
    CHUNK_ACTIVE, FLAG_COMPRESSED, FLAG_HAS_ACTIVE,
    HEADER_SIZE, INDEX_ENTRY_SIZE, SUMMARY_SIZE,
    HEADER_STRUCT, INDEX_ENTRY_STRUCT,
)
from .compression import compress
from .exceptions import AMCXReadOnlyError
from .mirror import AMCXMirror, AMCXRecovery, MirrorMode, MirrorStatus, ChunkStatus


@dataclass
class ChunkEntry:
    """Represents a chunk before writing it to the file."""
    chunk_id:    int
    chunk_type:  int
    summary:     str
    content:     bytes
    algorithm:   int = COMPRESS_ZLIB
    timestamp:   int = field(default_factory=lambda: int(time.time()))


class AMCXWriter:
    """
    Builds an .amcx file in memory and flushes it to disk.

    Args:
        mirror:         MirrorMode.NONE | MANUAL | AUTO
        recovery:       if True, adds XOR recovery blocks when saving
        recovery_group: parity group size (default 3)

    Basic usage:
        writer = AMCXWriter()
        writer.add_text_chunk(0, CHUNK_LORE, "The world", "content...")
        writer.save("memory.amcx")

    With automatic mirror and recovery:
        writer = AMCXWriter(mirror=MirrorMode.AUTO, recovery=True)
        writer.save("memory.amcx")
        # → generates memory.amcx + memory.amcx.mirror (with SHA-1 per chunk)
        #   and XOR recovery blocks at the end of the .amcx
    """

    def __init__(
        self,
        mirror:         MirrorMode = MirrorMode.NONE,
        recovery:       bool       = False,
        recovery_group: int        = 3,
    ):
        self._chunks:         list[ChunkEntry] = []
        self._active_chunk_id: Optional[int]  = None
        self._flags:          int              = 0
        self._created_at:     int              = int(time.time())
        self.mirror           = mirror
        self.recovery         = recovery
        self.recovery_group   = recovery_group

    # ─── Public API ────────────────────────────────────────────────────────────

    def add_chunk(self, entry: ChunkEntry) -> None:
        """Adds a chunk. If its type is CHUNK_ACTIVE, marks it as active."""
        self._chunks.append(entry)
        if entry.chunk_type == CHUNK_ACTIVE:
            self._active_chunk_id = entry.chunk_id
            self._flags |= FLAG_HAS_ACTIVE
        if entry.algorithm != COMPRESS_NONE:
            self._flags |= FLAG_COMPRESSED

    def add_text_chunk(
        self,
        chunk_id:   int,
        chunk_type: int,
        summary:    str,
        text:       str,
        algorithm:  int = COMPRESS_ZLIB,
    ) -> None:
        """Shortcut for adding a text chunk (automatically encodes to UTF-8)."""
        self.add_chunk(ChunkEntry(
            chunk_id=chunk_id,
            chunk_type=chunk_type,
            summary=summary,
            content=text.encode("utf-8"),
            algorithm=algorithm,
        ))

    def save(self, path: str) -> None:
        """
        Serializes and writes the .amcx file.
        If mirror=AUTO, also generates the .amcx.mirror.
        If recovery=True, also appends XOR blocks at the end.
        """
        with open(path, "wb") as f:
            f.write(self._build())

        if self.recovery:
            AMCXRecovery.append(path, group_size=self.recovery_group)

        if self.mirror == MirrorMode.AUTO:
            self.embed_mirror(path)

    def embed_mirror(self, path: str) -> None:
        """
        Embeds the SHA-1 mirror block inside the .amcx manually.
        Useful when mirror=MANUAL.
        """
        chunk_data = {
            e.chunk_id: (e.content, e.summary)
            for e in self._chunks
        }
        AMCXMirror.embed(path, chunk_data)

    def to_bytes(self) -> bytes:
        """Returns the .amcx file as bytes (useful for tests or sending over the network)."""
        return self._build()

    # ─── Internals ─────────────────────────────────────────────────────────────

    def _build(self) -> bytes:
        buf = io.BytesIO()

        # 1. Reserve space for the header
        buf.write(b'\x00' * HEADER_SIZE)

        # 2. Reserve space for the index
        index_offset = HEADER_SIZE
        index_size   = INDEX_ENTRY_SIZE * len(self._chunks)
        buf.write(b'\x00' * index_size)

        # 3. Compress, calculate CRC32 and write each chunk
        index_entries = []
        for entry in self._chunks:
            compressed   = compress(entry.content, entry.algorithm)
            chunk_crc32  = zlib.crc32(compressed) & 0xFFFFFFFF
            chunk_offset = buf.tell()

            buf.write(struct.pack('>I', len(compressed)))
            buf.write(compressed)

            index_entries.append({
                "chunk_id":        entry.chunk_id,
                "offset":          chunk_offset,
                "size_compressed": len(compressed),
                "size_original":   len(entry.content),
                "chunk_type":      entry.chunk_type,
                "algorithm":       entry.algorithm,
                "timestamp":       entry.timestamp,
                "crc32":           chunk_crc32,
                "summary":         entry.summary,
            })

        # 4. Write the index
        buf.seek(index_offset)
        for e in index_entries:
            summary_bytes = e["summary"].encode("utf-8")[:SUMMARY_SIZE].ljust(SUMMARY_SIZE, b'\x00')
            buf.write(INDEX_ENTRY_STRUCT.pack(
                e["chunk_id"],
                e["offset"],
                e["size_compressed"],
                e["size_original"],
                e["chunk_type"],
                e["algorithm"],
                0,
                e["timestamp"],
                e["crc32"],
                summary_bytes,
            ))

        # 5. Write the header with CRC32
        header_without_crc = struct.pack(
            '>4sBBIQIIH',
            MAGIC,
            VERSION_MAJOR,
            VERSION_MINOR,
            len(self._chunks),
            self._created_at,
            index_offset,
            index_size,
            self._flags,
        )
        header_crc = zlib.crc32(header_without_crc) & 0xFFFFFFFF
        buf.seek(0)
        buf.write(header_without_crc + struct.pack('>I', header_crc))

        return buf.getvalue()

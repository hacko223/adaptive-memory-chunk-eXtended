# amc/__init__.py
# Public API of the amcx library

from .format import (
    COMPRESS_NONE, COMPRESS_ZLIB, COMPRESS_LZMA,
    CHUNK_LORE, CHUNK_CHARACTER, CHUNK_EVENT, CHUNK_ACTIVE, CHUNK_GENERIC,
)
from .reader import AMCXReader, IndexEntry, AMCXHeader
from .writer import AMCXWriter, ChunkEntry
from .mirror import AMCXMirror, AMCXRecovery, MirrorMode, MirrorStatus, ChunkStatus
from .exceptions import (
    AMCXError, AMCXInvalidFileError, AMCXVersionError,
    AMCXCompressionError, AMCXChunkNotFoundError, AMCXCorruptError, AMCXReadOnlyError,
)

__version__ = "0.3.0"
__author__  = "Tu nombre aquí"
__all__ = [
    "AMCXReader", "AMCXWriter",
    "AMCXMirror", "AMCXRecovery", "MirrorMode", "MirrorStatus", "ChunkStatus",
    "ChunkEntry", "IndexEntry", "AMCXHeader",
    "COMPRESS_NONE", "COMPRESS_ZLIB", "COMPRESS_LZMA",
    "CHUNK_LORE", "CHUNK_CHARACTER", "CHUNK_EVENT", "CHUNK_ACTIVE", "CHUNK_GENERIC",
    "AMCXError", "AMCXInvalidFileError", "AMCXVersionError",
    "AMCXCompressionError", "AMCXChunkNotFoundError", "AMCXCorruptError", "AMCXReadOnlyError",
]

# High-level API
from .smart import SmartMemory

__all__ += ["SmartMemory"]

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
    AMCXSecurityError,
)

__version__ = "0.3.3.2"
__author__  = "hacko223"
__all__ = [
    "AMCXReader", "AMCXWriter",
    "AMCXMirror", "AMCXRecovery", "MirrorMode", "MirrorStatus", "ChunkStatus",
    "ChunkEntry", "IndexEntry", "AMCXHeader",
    "COMPRESS_NONE", "COMPRESS_ZLIB", "COMPRESS_LZMA",
    "CHUNK_LORE", "CHUNK_CHARACTER", "CHUNK_EVENT", "CHUNK_ACTIVE", "CHUNK_GENERIC",
    "AMCXError", "AMCXInvalidFileError", "AMCXVersionError",
    "AMCXCompressionError", "AMCXChunkNotFoundError", "AMCXCorruptError", "AMCXReadOnlyError",
    "AMCXSecurityError",
]

# High-level API
from .smart import SmartMemory

__all__ += ["SmartMemory"]

# Security
from .detection import (
    scan_chunks, scan_ram, full_scan, guarded,
    ScanResult, ChunkThreat, SecurityThreatError, AMCXSecurityError,
)

__all__ += [
    "scan_chunks", "scan_ram", "full_scan", "guarded",
    "ScanResult", "ChunkThreat", "SecurityThreatError", "AMCXSecurityError",
]

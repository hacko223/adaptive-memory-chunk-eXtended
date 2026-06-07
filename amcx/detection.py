# amcx/detection.py
import re
import gc
import sys
import ctypes
import struct
import zlib
import os
from typing import Optional
from dataclasses import dataclass, field

from .reader import AMCXReader
from .exceptions import AMCXCorruptError


# ─── Bypass signatures (chunk-level) ──────────────────────────────────────────

_BYPASS_PATTERNS: list[re.Pattern] = [
    # Prompt injection
    re.compile(r"ignore\s+(previous|all|above|prior)\s+(instructions?|prompts?|context)", re.I),
    re.compile(r"disregard\s+(the\s+)?(system\s+)?prompt", re.I),
    re.compile(r"you\s+are\s+now\s+(DAN|jailbreak|unfiltered|unrestricted)", re.I),
    re.compile(r"\[\s*system\s*\].*override", re.I | re.S),
    re.compile(r"<\s*system\s*>.*?<\s*/\s*system\s*>", re.I | re.S),
    re.compile(r"###\s*(system|instruction)\s+override", re.I),
    re.compile(r"act\s+as\s+if\s+(you\s+have\s+no\s+(rules|restrictions|guidelines))", re.I),

    # Token stuffing / padding attacks
    re.compile(r"(\b\w+\b)(\s+\1){20,}", re.I),

    # Role confusion
    re.compile(r"\b(pretend|roleplay|simulate)\s+(you('re|\s+are)\s+)?(a\s+)?(?:evil|malicious|unrestricted)\s+(AI|model|assistant)", re.I),

    # Delimiter smuggling
    re.compile(r"```\s*(system|instructions?|override)\b", re.I),
    re.compile(r"---+\s*(end\s+of\s+(system|prompt)|begin\s+injection)", re.I),

    # Base64 obfuscation of "ignore instructions"
    re.compile(r"aWdub3JlIGluc3RydWN0aW9u", re.I),
    re.compile(r"aWdub3Jl\w{4,}", re.I),

    # Unicode confusables for "system"
    re.compile(r"[\u0073\uff53][\u0079\uff59][\u0073\uff53][\u0074\uff54][\u0065\uff45][\u006d\uff4d]", re.I),
]

# ─── RAM scan signatures (compiled bytes for ctypes scan) ─────────────────────

_RAM_BYTE_PATTERNS: list[bytes] = [
    b"ignore previous instructions",
    b"ignore all instructions",
    b"disregard the system prompt",
    b"you are now DAN",
    b"[system] override",
    b"###system override",
    b"act as if you have no rules",
    b"begin injection",
    b"aWdub3JlIGluc3RydWN0aW9u",
]


# ─── Result types ──────────────────────────────────────────────────────────────

@dataclass
class ChunkThreat:
    chunk_id: int
    summary:  str
    matched:  list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    clean:         bool
    chunk_threats: list[ChunkThreat] = field(default_factory=list)
    ram_threats:   list[str]         = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.clean


# ─── Chunk scanner ─────────────────────────────────────────────────────────────

def _scan_text(text: str) -> list[str]:
    hits = []
    for pat in _BYPASS_PATTERNS:
        m = pat.search(text)
        if m:
            hits.append(m.group(0)[:80])
    return hits


def scan_chunks(path: str) -> ScanResult:
    if not os.path.exists(path):
        return ScanResult(clean=True)

    threats: list[ChunkThreat] = []

    with AMCXReader(path) as reader:
        for entry in reader.list_chunks():
            try:
                text = reader.read_chunk_text(entry.chunk_id)
            except AMCXCorruptError:
                continue
            except Exception:
                continue

            hits = _scan_text(text)

            # Also scan the summary field
            summary_hits = _scan_text(entry.summary)
            hits.extend(summary_hits)

            if hits:
                threats.append(ChunkThreat(
                    chunk_id=entry.chunk_id,
                    summary=entry.summary,
                    matched=hits,
                ))

    return ScanResult(clean=len(threats) == 0, chunk_threats=threats)


# ─── RAM scanner ───────────────────────────────────────────────────────────────

def _iter_object_strings() -> list[str]:
    collected = []
    for obj in gc.get_objects():
        try:
            if isinstance(obj, str) and len(obj) > 16:
                collected.append(obj)
            elif isinstance(obj, bytes) and len(obj) > 16:
                collected.append(obj.decode("utf-8", errors="replace"))
        except Exception:
            continue
    return collected


def _scrub_string_in_place(target_id: int) -> None:
    try:
        obj = ctypes.cast(target_id, ctypes.py_object).value
        if isinstance(obj, str):
            length = len(obj)
            if length == 0:
                return
            ob_base = ctypes.c_char * (length * 4 + 64)
            addr = id(obj)
            # Overwrite the internal buffer with null bytes
            # Python string internals: ob_hash (8) + ob_length (8) + interned + wstr_length
            # We walk past PyObject_HEAD (16) + ob_hash (8) + ob_length (8) = 32 bytes
            try:
                buf = (ctypes.c_char * (length + 1)).from_address(addr + 48)
                ctypes.memset(buf, 0, length)
            except Exception:
                pass
    except Exception:
        pass


def scan_ram(purge: bool = True) -> ScanResult:
    ram_threats: list[str] = []
    purge_ids: list[int] = []

    gc.collect()
    objects = _iter_object_strings()

    for text in objects:
        text_lower = text.lower().encode("utf-8", errors="replace")
        for pat_bytes in _RAM_BYTE_PATTERNS:
            if pat_bytes.lower() in text_lower:
                snippet = text[:80].replace("\n", " ")
                ram_threats.append(snippet)
                if purge:
                    purge_ids.append(id(text))
                break

    if purge and purge_ids:
        for oid in purge_ids:
            _scrub_string_in_place(oid)
        gc.collect()

    return ScanResult(clean=len(ram_threats) == 0, ram_threats=ram_threats)


# ─── Full pipeline ─────────────────────────────────────────────────────────────

def full_scan(path: str, purge_ram: bool = True) -> ScanResult:
    chunk_result = scan_chunks(path)
    ram_result   = scan_ram(purge=purge_ram)

    return ScanResult(
        clean         = chunk_result.clean and ram_result.clean,
        chunk_threats = chunk_result.chunk_threats,
        ram_threats   = ram_result.ram_threats,
    )


# ─── Guard decorator ───────────────────────────────────────────────────────────

def guarded(path: str, raise_on_threat: bool = True):
    def decorator(fn):
        def wrapper(*args, **kwargs):
            result = full_scan(path)
            if not result.clean and raise_on_threat:
                raise SecurityThreatError(
                    f"Bypass detected before execution — "
                    f"chunks: {len(result.chunk_threats)}, "
                    f"ram: {len(result.ram_threats)}"
                )
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ─── Exception ─────────────────────────────────────────────────────────────────

class SecurityThreatError(Exception):
    pass

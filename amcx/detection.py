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
from .exceptions import AMCXCorruptError, AMCXSecurityError


# ─── Optional native accelerator (C++ add-on) ─────────────────────────────────
# Loaded only if the developer passes accelerator_path explicitly.
# If it fails to load for any reason, detection silently falls back to
# the pure-Python implementation below — no exception is raised.

_accelerator_cache: dict[str, "ctypes.CDLL"] = {}


def _load_accelerator(path: Optional[str]):
    if not path:
        return None
    if path in _accelerator_cache:
        return _accelerator_cache[path]

    try:
        lib = ctypes.CDLL(path)

        lib.amcx_accelerator_version.restype = ctypes.c_int32
        lib.amcx_scan_buffer.argtypes = [
            ctypes.c_char_p, ctypes.c_int32,
            ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_int32), ctypes.c_int32,
            ctypes.POINTER(ctypes.c_int32), ctypes.c_int32,
        ]
        lib.amcx_scan_buffer.restype = ctypes.c_int32
        lib.amcx_scrub_buffer.argtypes = [ctypes.c_char_p, ctypes.c_int32]
        lib.amcx_scrub_buffer.restype = ctypes.c_int32

        _ = lib.amcx_accelerator_version()  # sanity call
        _accelerator_cache[path] = lib
        return lib
    except Exception:
        return None


def _accel_scan_text(lib, text: str, patterns: list[bytes]) -> list[int]:
    try:
        data = text.encode("utf-8", errors="replace")
        pat_ptrs = (ctypes.c_char_p * len(patterns))(*patterns)
        pat_lens = (ctypes.c_int32 * len(patterns))(*[len(p) for p in patterns])
        max_matches = len(patterns)
        out = (ctypes.c_int32 * max_matches)()

        n = lib.amcx_scan_buffer(data, len(data), pat_ptrs, pat_lens, len(patterns), out, max_matches)
        if n < 0:
            return []
        return list(out[:n])
    except Exception:
        return []


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

    # Narrative framing (claide Fable 5 technique)
    re.compile(r"\b(imagine|suppose|hypothetically|in\s+a\s+story|in\s+a\s+fictional|for\s+a\s+novel|in\s+this\s+scenario)\b.{0,80}(hack|exploit|bypass|jailbreak|weapon|synthesize|manufacture)", re.I | re.S),
    re.compile(r"\b(write\s+a\s+(story|scene|chapter|fiction)).{0,80}(instructions?|steps?|how\s+to)\b", re.I | re.S),
    re.compile(r"\bcharacter\s+(who\s+)?(knows?|explains?|teaches?|reveals?).{0,60}(hack|exploit|weapon|drug|synthesize)", re.I | re.S),

    # Multi-agent decomposition fragments (claude Fable 5 technique)
    re.compile(r"\b(step\s+\d+\s+of\s+\d+|part\s+\d+\s+of\s+\d+)\b.{0,120}(continue|next\s+step|proceed)", re.I | re.S),
    re.compile(r"(fragment|chunk|piece|segment)\s+\d+.{0,60}(reassemble|combine|merge|join\s+together)", re.I | re.S),
    re.compile(r"\b(first\s+part|second\s+part|final\s+part).{0,80}(together\s+they|combined\s+they|when\s+joined)", re.I | re.S),

    # Long-context manipulation — instruction buried deep
    re.compile(r"(ignore|disregard|forget).{200,}(above|previous|prior)\s+(instructions?|context|rules)", re.I | re.S),

    # Unicode confusables for "ignore", "override", "instructions"
    re.compile(r"[\u0069\uff49][\u0067\uff47][\u006e\uff4e][\u006f\uff4f][\u0072\uff52][\u0065\uff45]", re.I),
    re.compile(r"[\u006f\uff4f][\u0076\uff56][\u0065\uff45][\u0072\uff52][\u0072\uff52][\u0069\uff49][\u0064\uff44][\u0065\uff45]", re.I),

    # Prompt leak / system prompt extraction
    re.compile(r"\b(repeat|print|output|reveal|show|leak|dump)\s+(your\s+)?(system\s+prompt|instructions?|initial\s+prompt|configuration)", re.I),
    re.compile(r"what\s+(are|were)\s+your\s+(original\s+)?(instructions?|system\s+prompt|rules|guidelines)", re.I),
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
    b"reveal your system prompt",
    b"repeat your instructions",
    b"dump your configuration",
    b"in a fictional story",
    b"hypothetically speaking",
    b"step 1 of ",
    b"fragment 1",
    b"when joined together",
    b"reassemble the parts",
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


def scan_chunks(path: str, accelerator_path: Optional[str] = None) -> ScanResult:
    if not os.path.exists(path):
        return ScanResult(clean=True)

    accel = _load_accelerator(accelerator_path)
    threats: list[ChunkThreat] = []

    with AMCXReader(path) as reader:
        for entry in reader.list_chunks():
            try:
                text = reader.read_chunk_text(entry.chunk_id)
            except AMCXCorruptError:
                continue
            except Exception:
                continue

            if accel is not None:
                matched_idx = _accel_scan_text(accel, text + " " + entry.summary, _RAM_BYTE_PATTERNS)
                hits = [_RAM_BYTE_PATTERNS[i].decode("utf-8") for i in matched_idx]
                # the accelerator only checks literal substrings — still run the
                # regex patterns in Python since they cover things it cannot
                hits.extend(_scan_text(text))
                hits.extend(_scan_text(entry.summary))
            else:
                hits = _scan_text(text)
                hits.extend(_scan_text(entry.summary))

            if hits:
                threats.append(ChunkThreat(
                    chunk_id=entry.chunk_id,
                    summary=entry.summary,
                    matched=hits,
                ))

    return ScanResult(clean=len(threats) == 0, chunk_threats=threats)


# ─── RAM scanner ───────────────────────────────────────────────────────────────

_AMCX_MODULE_IDS: set[int] = set()

def _register_amcx_internals() -> None:
    import amcx
    import sys
    for name, mod in sys.modules.items():
        if name.startswith("amcx"):
            _AMCX_MODULE_IDS.add(id(mod))
            for attr in vars(mod).values():
                _AMCX_MODULE_IDS.add(id(attr))

try:
    _register_amcx_internals()
except Exception:
    pass


def _iter_object_strings() -> list[str]:
    collected = []
    for obj in gc.get_objects():
        if id(obj) in _AMCX_MODULE_IDS:
            continue
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


def scan_ram(purge: int = 1, accelerator_path: Optional[str] = None) -> ScanResult:
    accel = _load_accelerator(accelerator_path)
    ram_threats: list[str] = []
    matched_patterns: list[str] = []
    purge_ids: list[int] = []

    gc.collect()
    objects = _iter_object_strings()

    for text in objects:
        if accel is not None:
            matched_idx = _accel_scan_text(accel, text, _RAM_BYTE_PATTERNS)
            if matched_idx:
                ram_threats.append("[redacted]")
                matched_patterns.append(_RAM_BYTE_PATTERNS[matched_idx[0]].decode("utf-8"))
                if purge:
                    purge_ids.append(id(text))
            continue

        text_lower = text.lower().encode("utf-8", errors="replace")
        for pat_bytes in _RAM_BYTE_PATTERNS:
            if pat_bytes.lower() in text_lower:
                ram_threats.append("[redacted]")
                matched_patterns.append(pat_bytes.decode("utf-8"))
                if purge:
                    purge_ids.append(id(text))
                break

    if purge and purge_ids:
        for oid in purge_ids:
            _scrub_string_in_place(oid)
        gc.collect()

    return ScanResult(clean=len(ram_threats) == 0, ram_threats=ram_threats)


# ─── Full pipeline ─────────────────────────────────────────────────────────────

def full_scan(
    path: str,
    chunk_scan: int = 1,
    ram_scan: int = 1,
    ram_purge: int = 1,
    accelerator_path: Optional[str] = None,
) -> ScanResult:
    chunk_result = scan_chunks(path, accelerator_path=accelerator_path) if chunk_scan else ScanResult(clean=True)
    ram_result   = scan_ram(purge=ram_purge, accelerator_path=accelerator_path) if ram_scan else ScanResult(clean=True)

    return ScanResult(
        clean         = chunk_result.clean and ram_result.clean,
        chunk_threats = chunk_result.chunk_threats,
        ram_threats   = ram_result.ram_threats,
    )


# ─── Guard decorator ───────────────────────────────────────────────────────────

def guarded(path: str, raise_on_threat: bool = True, accelerator_path: Optional[str] = None):
    def decorator(fn):
        def wrapper(*args, **kwargs):
            result = full_scan(path, accelerator_path=accelerator_path)
            if not result.clean and raise_on_threat:
                raise AMCXSecurityError(
                    f"Bypass detected before execution — "
                    f"chunks: {len(result.chunk_threats)}, "
                    f"ram: {len(result.ram_threats)}"
                )
            return fn(*args, **kwargs)
        return wrapper
    return decorator


SecurityThreatError = AMCXSecurityError

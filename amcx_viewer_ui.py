#!/usr/bin/env python3
"""
amcx_viewer_ui.py — Inspector visual de archivos .amcx
Requiere: pip install amcx   y   tkinter (incluido en Python estándar)

Uso:
    python amcx_viewer_ui.py
    python amcx_viewer_ui.py archivo.amcx
"""

from __future__ import annotations

import os
import sys
import tkinter as tk
from datetime import datetime, timezone
from tkinter import filedialog, messagebox, ttk
from typing import Optional

# ── Importar amcx ─────────────────────────────────────────────────────────────
try:
    from amcx import (
        AMCXReader, AMCXHeader, IndexEntry,
        AMCXMirror, AMCXRecovery, MirrorStatus, ChunkStatus,
        CHUNK_LORE, CHUNK_CHARACTER, CHUNK_EVENT, CHUNK_ACTIVE, CHUNK_GENERIC,
        COMPRESS_NONE, COMPRESS_ZLIB, COMPRESS_LZMA,
        AMCXError, AMCXCorruptError, AMCXChunkNotFoundError,
    )
    from amcx.format import (
        FLAG_COMPRESSED, FLAG_ENCRYPTED, FLAG_READONLY,
        FLAG_HAS_ACTIVE, FLAG_HAS_ASSETS,
    )
    from amcx.mirror import RECOVERY_MAGIC, MIRROR_MAGIC, ChunkReport
except ImportError:
    import tkinter as _tk
    _r = _tk.Tk(); _r.withdraw()
    messagebox.showerror(
        "amcx no instalado",
        "Este viewer requiere la librería amcx.\n\nInstálala con:\n    pip install amcx",
    )
    sys.exit(1)


# ─── Constantes de display ────────────────────────────────────────────────────

CHUNK_TYPE_NAME = {
    CHUNK_LORE:      "LORE",
    CHUNK_CHARACTER: "CHARACTER",
    CHUNK_EVENT:     "EVENT",
    CHUNK_ACTIVE:    "ACTIVE",
    CHUNK_GENERIC:   "GENERIC",
}

CHUNK_COLORS = {
    "LORE":      "#4a9eff",
    "CHARACTER": "#c084fc",
    "EVENT":     "#facc15",
    "ACTIVE":    "#4ade80",
    "GENERIC":   "#94a3b8",
}

ALGO_NAME = {
    COMPRESS_NONE: "none",
    COMPRESS_ZLIB: "zlib",
    COMPRESS_LZMA: "lzma",
}

CHUNK_STATUS_DISPLAY = {
    ChunkStatus.OK:             ("✓  ok",             "#4ade80"),
    ChunkStatus.MODIFIED:       ("✗  modificado",      "#f87171"),
    ChunkStatus.MISSING_MIRROR: ("?  sin mirror",      "#facc15"),
    ChunkStatus.MISSING_ORIG:   ("?  chunk ausente",   "#facc15"),
    ChunkStatus.OUTDATED:       ("⚠  desactualizado",  "#fb923c"),
}


# ─── Helpers de display ───────────────────────────────────────────────────────

def _ts(unix: int) -> str:
    if not unix:
        return "—"
    try:
        return datetime.fromtimestamp(unix, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(unix)

def _size(n: int) -> str:
    if n < 1024:      return f"{n} B"
    if n < 1024 ** 2: return f"{n / 1024:.1f} KB"
    return f"{n / 1024 ** 2:.1f} MB"

def _ratio(comp: int, orig: int) -> str:
    if not orig: return "—"
    return f"{(1 - comp / orig) * 100:.0f}% saved"

def _flags_list(flags: int) -> list[str]:
    out = []
    if flags & FLAG_COMPRESSED: out.append("COMPRESSED")
    if flags & FLAG_ENCRYPTED:  out.append("ENCRYPTED")
    if flags & FLAG_READONLY:   out.append("READONLY")
    if flags & FLAG_HAS_ACTIVE: out.append("HAS_ACTIVE")
    if flags & FLAG_HAS_ASSETS: out.append("HAS_ASSETS")
    return out or ["(none)"]

def _hexdump(data: bytes, max_bytes: int = 512) -> str:
    truncated = len(data) > max_bytes
    data = data[:max_bytes]
    lines = []
    for i in range(0, len(data), 16):
        row = data[i:i + 16]
        hex_part   = " ".join(f"{b:02x}" for b in row)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{i:04x}  {hex_part:<48}  {ascii_part}")
    if truncated:
        lines.append(f"... (truncado a {max_bytes} bytes)")
    return "\n".join(lines)


# ─── Modelo de datos del viewer ───────────────────────────────────────────────
# Todo viene de la API de amcx — no parseamos nada a mano.

class ViewerChunk:
    """Wrapper de IndexEntry + bytes leídos con AMCXReader."""

    def __init__(self, entry: IndexEntry, content: Optional[bytes], raw_compressed: bytes):
        self.entry          = entry
        self.content        = content          # descomprimido (bytes) o None si AMCXCorruptError
        self.raw_compressed = raw_compressed   # bytes crudos del chunk para hexdump

    # Shortcuts que usan los campos de IndexEntry directamente
    @property
    def chunk_id(self) -> int: return self.entry.chunk_id
    @property
    def chunk_type_int(self) -> int: return self.entry.chunk_type
    @property
    def chunk_type(self) -> str: return CHUNK_TYPE_NAME.get(self.entry.chunk_type, f"0x{self.entry.chunk_type:02x}")
    @property
    def algorithm(self) -> str: return self.entry.algorithm_name
    @property
    def offset(self) -> int: return self.entry.offset
    @property
    def size_compressed(self) -> int: return self.entry.size_compressed
    @property
    def size_original(self) -> int: return self.entry.size_original
    @property
    def ratio(self) -> str: return _ratio(self.entry.size_compressed, self.entry.size_original)
    @property
    def timestamp(self) -> str: return _ts(self.entry.timestamp)
    @property
    def crc32(self) -> str: return f"{self.entry.crc32:08x}"
    @property
    def summary(self) -> str: return self.entry.summary


class ViewerReport:
    """Todo lo que el viewer necesita, extraído de la API de amcx."""

    def __init__(self, path: str, reader: AMCXReader,
                 chunks: list[ViewerChunk],
                 mirror_status: MirrorStatus,
                 recovery_blocks: list[tuple],
                 file_size: int,
                 warnings: list[str]):
        self.path            = path
        self.header          = reader.header       # AMCXHeader
        self.chunks          = chunks
        self.mirror_status   = mirror_status       # MirrorStatus
        self.recovery_blocks = recovery_blocks     # lista de (gidx, [chunk_ids], parity)
        self.file_size       = file_size
        self.warnings        = warnings

    # Shortcuts de header
    @property
    def version(self) -> str: return self.header.version_str
    @property
    def num_chunks(self) -> int: return self.header.num_chunks
    @property
    def created_at(self) -> str: return _ts(self.header.created_at)
    @property
    def index_offset(self) -> int: return self.header.index_offset
    @property
    def index_size(self) -> int: return self.header.index_size
    @property
    def flags(self) -> list[str]: return _flags_list(self.header.flags)
    @property
    def flags_int(self) -> int: return self.header.flags
    @property
    def has_active(self) -> bool: return self.header.has_active_chunk


def load_report(path: str) -> ViewerReport:
    """
    Abre el archivo con AMCXReader, lee todos los chunks y el estado
    del mirror y recovery usando exclusivamente la API de amcx.
    """
    warnings: list[str] = []
    file_size = os.path.getsize(path)

    with AMCXReader(path) as reader:
        chunks: list[ViewerChunk] = []

        for entry in reader.list_chunks():
            # Leer bytes crudos directamente para el hexdump
            # (read_chunk() devuelve descomprimido; necesitamos ambos)
            try:
                reader._file.seek(entry.offset)
                import struct as _struct
                size_field      = _struct.unpack('>I', reader._file.read(4))[0]
                raw_compressed  = reader._file.read(size_field)
            except Exception:
                raw_compressed = b""

            try:
                content = reader.read_chunk(entry.chunk_id)
            except AMCXCorruptError as e:
                content = None
                warnings.append(f"Chunk {entry.chunk_id}: {e}")
            except Exception as e:
                content = None
                warnings.append(f"Chunk {entry.chunk_id}: {e}")

            chunks.append(ViewerChunk(entry, content, raw_compressed))

    # Mirror — AMCXMirror.verify() devuelve MirrorStatus con la lista de ChunkReport
    try:
        mirror_status = AMCXMirror.verify(path)
    except Exception as e:
        warnings.append(f"No se pudo verificar el mirror: {e}")
        mirror_status = MirrorStatus(mirror_exists=False)

    # Recovery — AMCXRecovery._read_blocks() devuelve [(gidx, [chunk_ids], parity)]
    try:
        recovery_blocks = AMCXRecovery._read_blocks(path)
    except Exception as e:
        warnings.append(f"No se pudo leer el bloque de recovery: {e}")
        recovery_blocks = []

    # Re-abrir solo para extraer el header (se cierra de inmediato)
    with AMCXReader(path) as _r:
        _header = _r.header

    class _FakeReader:
        header = _header

    return ViewerReport(
        path=path,
        reader=_FakeReader(),
        chunks=chunks,
        mirror_status=mirror_status,
        recovery_blocks=recovery_blocks,
        file_size=file_size,
        warnings=warnings,
    )


# ─── UI ───────────────────────────────────────────────────────────────────────

BG       = "#0f1117"
BG2      = "#1a1d27"
BG3      = "#252836"
FG       = "#e2e8f0"
FG_DIM   = "#64748b"
ACCENT   = "#4a9eff"
OK_CLR   = "#4ade80"
ERR_CLR  = "#f87171"
WARN_CLR = "#facc15"
BORDER   = "#2d3148"
MONO     = ("Courier New", 10)
SANS     = ("Segoe UI", 10)
SANS_B   = ("Segoe UI", 10, "bold")
SANS_SM  = ("Segoe UI", 9)


class AMCXViewer(tk.Tk):
    def __init__(self, initial_file: Optional[str] = None):
        super().__init__()
        self.title("amcx viewer")
        self.geometry("1100x760")
        self.minsize(900, 600)
        self.configure(bg=BG)
        self.report: Optional[ViewerReport] = None
        self._build_ui()
        if initial_file:
            self.after(100, lambda: self._load(initial_file))

    # ── Layout ───────────────────────────────────────────────────────────────

    def _build_ui(self):
        toolbar = tk.Frame(self, bg=BG2, pady=8, padx=12)
        toolbar.pack(fill="x", side="top")
        tk.Label(toolbar, text="amcx viewer", font=("Segoe UI", 13, "bold"),
                 bg=BG2, fg=ACCENT).pack(side="left")
        tk.Button(toolbar, text="  Abrir .amcx  ", command=self._open_file,
                  bg=ACCENT, fg="#000", relief="flat", font=SANS_B,
                  activebackground="#3b82f6", cursor="hand2", padx=4,
                  ).pack(side="left", padx=(16, 0))
        self._warn_label = tk.Label(toolbar, text="", font=SANS_SM, bg=BG2, fg=WARN_CLR)
        self._warn_label.pack(side="right")
        self._file_label = tk.Label(toolbar, text="Ningún archivo abierto",
                                    font=SANS_SM, bg=BG2, fg=FG_DIM)
        self._file_label.pack(side="right", padx=12)

        main = tk.Frame(self, bg=BG)
        main.pack(fill="both", expand=True)

        # Sidebar
        sidebar = tk.Frame(main, bg=BG2, width=220)
        sidebar.pack(fill="y", side="left")
        sidebar.pack_propagate(False)
        tk.Label(sidebar, text="Chunks", font=SANS_B, bg=BG2, fg=FG,
                 pady=10).pack(fill="x", padx=12)
        self._chunk_list = tk.Listbox(
            sidebar, bg=BG2, fg=FG, selectbackground=BG3,
            selectforeground=ACCENT, relief="flat", borderwidth=0,
            font=SANS_SM, activestyle="none", highlightthickness=0,
        )
        self._chunk_list.pack(fill="both", expand=True, padx=4, pady=(0, 4))
        self._chunk_list.bind("<<ListboxSelect>>", self._on_chunk_select)

        content = tk.Frame(main, bg=BG)
        content.pack(fill="both", expand=True, side="left")

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TNotebook",     background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG2, foreground=FG_DIM,
                        padding=[14, 6], font=SANS_SM)
        style.map("TNotebook.Tab",
                  background=[("selected", BG3)],
                  foreground=[("selected", FG)])
        style.configure("TFrame", background=BG)
        style.configure("Treeview", background=BG2, fieldbackground=BG2,
                        foreground=FG, rowheight=24, font=SANS_SM, borderwidth=0)
        style.configure("Treeview.Heading", background=BG3, foreground=FG_DIM,
                        font=SANS_SM, relief="flat")
        style.map("Treeview",
                  background=[("selected", BG3)],
                  foreground=[("selected", ACCENT)])
        style.configure("Vertical.TScrollbar", background=BG3,
                        troughcolor=BG2, borderwidth=0, arrowcolor=FG_DIM)

        self._nb = ttk.Notebook(content)
        self._nb.pack(fill="both", expand=True, padx=4, pady=4)

        self._tab_header   = self._make_tab("Header")
        self._tab_chunk    = self._make_tab("Chunk")
        self._tab_mirror   = self._make_tab("Mirror")
        self._tab_recovery = self._make_tab("Recovery")
        self._tab_map      = self._make_tab("Mapa")
        self._tab_hex      = self._make_tab("Hex")

        self._build_header_tab()
        self._build_chunk_tab()
        self._build_mirror_tab()
        self._build_recovery_tab()
        self._build_map_tab()
        self._build_hex_tab()

    def _make_tab(self, title: str) -> ttk.Frame:
        frame = ttk.Frame(self._nb)
        self._nb.add(frame, text=f"  {title}  ")
        return frame

    # ── Header tab ───────────────────────────────────────────────────────────

    def _build_header_tab(self):
        f = self._tab_header
        f.columnconfigure(1, weight=1)
        fields = [
            ("Ruta",        "path"),
            ("Tamaño",      "file_size"),
            ("Versión",     "version"),
            ("Chunks",      "num_chunks"),
            ("Creado",      "created_at"),
            ("idx_offset",  "index_offset"),
            ("idx_size",    "index_size"),
            ("Flags",       "flags"),
        ]
        self._header_vars: dict[str, tk.StringVar] = {}

        for row, (label, key) in enumerate(fields):
            tk.Label(f, text=label, font=SANS_SM, bg=BG, fg=FG_DIM,
                     anchor="e", width=12).grid(row=row, column=0,
                     padx=(16, 8), pady=4, sticky="e")
            var = tk.StringVar(value="—")
            self._header_vars[key] = var
            tk.Label(f, textvariable=var, font=SANS_SM, bg=BG, fg=FG,
                     anchor="w").grid(row=row, column=1,
                     padx=(0, 16), pady=4, sticky="w")

        self._flags_frame = tk.Frame(f, bg=BG)
        self._flags_frame.grid(row=fields.index(("Flags", "flags")),
                               column=1, padx=(0, 16), pady=4, sticky="w")

    def _refresh_header_tab(self, r: ViewerReport):
        self._header_vars["path"].set(r.path)
        self._header_vars["file_size"].set(_size(r.file_size))
        self._header_vars["version"].set(r.version)
        self._header_vars["num_chunks"].set(str(r.num_chunks))
        self._header_vars["created_at"].set(r.created_at)
        self._header_vars["index_offset"].set(f"0x{r.index_offset:04x}  ({r.index_offset} bytes)")
        self._header_vars["index_size"].set(_size(r.index_size))
        self._header_vars["flags"].set("")

        for w in self._flags_frame.winfo_children():
            w.destroy()
        for flag in r.flags:
            tk.Label(self._flags_frame, text=flag, font=SANS_SM,
                     bg=BG3, fg=ACCENT, padx=8, pady=2,
                     ).pack(side="left", padx=4)

    # ── Chunk tab ────────────────────────────────────────────────────────────

    def _build_chunk_tab(self):
        f = self._tab_chunk
        f.columnconfigure(1, weight=1)
        fields = [
            ("ID",         "chunk_id"),
            ("Tipo",       "chunk_type"),
            ("Algoritmo",  "algorithm"),
            ("Offset",     "offset"),
            ("Comprimido", "size_compressed"),
            ("Original",   "size_original"),
            ("Ratio",      "ratio"),
            ("Timestamp",  "timestamp"),
            ("CRC32",      "crc32"),
            ("Resumen",    "summary"),
        ]
        self._chunk_vars: dict[str, tk.StringVar] = {}
        self._chunk_type_lbl: Optional[tk.Label] = None

        for row, (label, key) in enumerate(fields):
            tk.Label(f, text=label, font=SANS_SM, bg=BG, fg=FG_DIM,
                     anchor="e", width=12).grid(row=row, column=0,
                     padx=(16, 8), pady=4, sticky="e")
            var = tk.StringVar(value="—")
            self._chunk_vars[key] = var
            lbl = tk.Label(f, textvariable=var,
                           font=MONO if key == "crc32" else SANS_SM,
                           bg=BG, fg=FG, anchor="w")
            lbl.grid(row=row, column=1, padx=(0, 16), pady=4, sticky="w")
            if key == "chunk_type":
                self._chunk_type_lbl = lbl

        tk.Label(f, text="Preview", font=SANS_SM, bg=BG, fg=FG_DIM,
                 anchor="e", width=12).grid(row=len(fields), column=0,
                 padx=(16, 8), pady=(12, 4), sticky="ne")
        pf = tk.Frame(f, bg=BG2)
        pf.grid(row=len(fields), column=1, padx=(0, 16), pady=(12, 4), sticky="ew")
        f.rowconfigure(len(fields), weight=1)
        self._preview_text = tk.Text(
            pf, wrap="word", height=6, bg=BG2, fg=FG, insertbackground=FG,
            relief="flat", font=SANS_SM, state="disabled", padx=8, pady=6,
            highlightthickness=1, highlightbackground=BORDER,
        )
        self._preview_text.pack(fill="both", expand=True)

    def _refresh_chunk_tab(self, ch: ViewerChunk):
        self._chunk_vars["chunk_id"].set(str(ch.chunk_id))
        self._chunk_vars["chunk_type"].set(ch.chunk_type)
        self._chunk_vars["algorithm"].set(ch.algorithm)
        self._chunk_vars["offset"].set(f"0x{ch.offset:04x}  ({ch.offset} bytes)")
        self._chunk_vars["size_compressed"].set(_size(ch.size_compressed))
        self._chunk_vars["size_original"].set(_size(ch.size_original))
        self._chunk_vars["ratio"].set(ch.ratio)
        self._chunk_vars["timestamp"].set(ch.timestamp)
        self._chunk_vars["crc32"].set(ch.crc32)
        self._chunk_vars["summary"].set(ch.summary)
        if self._chunk_type_lbl:
            self._chunk_type_lbl.config(fg=CHUNK_COLORS.get(ch.chunk_type, FG))

        self._preview_text.config(state="normal")
        self._preview_text.delete("1.0", "end")
        if ch.content:
            try:
                self._preview_text.insert("1.0", ch.content.decode("utf-8", errors="replace")[:2000])
            except Exception:
                self._preview_text.insert("1.0", "(contenido binario — usa la pestaña Hex)")
        else:
            self._preview_text.insert("1.0", "(chunk corrupto o ilegible)")
        self._preview_text.config(state="disabled")

    # ── Mirror tab ───────────────────────────────────────────────────────────

    def _build_mirror_tab(self):
        f = self._tab_mirror
        top = tk.Frame(f, bg=BG)
        top.pack(fill="x", padx=16, pady=12)
        self._mirror_status_lbl = tk.Label(top, text="—", font=SANS_B, bg=BG, fg=FG_DIM)
        self._mirror_status_lbl.pack(side="left")
        self._mirror_ts_lbl = tk.Label(top, text="", font=SANS_SM, bg=BG, fg=FG_DIM)
        self._mirror_ts_lbl.pack(side="left", padx=16)

        cols = ("id", "resumen", "sha1", "estado")
        tf = tk.Frame(f, bg=BG)
        tf.pack(fill="both", expand=True, padx=16, pady=(0, 12))
        self._mirror_tree = ttk.Treeview(tf, columns=cols, show="headings", selectmode="browse")
        self._mirror_tree.heading("id",      text="ID")
        self._mirror_tree.heading("resumen", text="Resumen")
        self._mirror_tree.heading("sha1",    text="SHA-1 (mirror)")
        self._mirror_tree.heading("estado",  text="Estado")
        self._mirror_tree.column("id",       width=50,  anchor="center")
        self._mirror_tree.column("resumen",  width=160)
        self._mirror_tree.column("sha1",     width=320, anchor="w")
        self._mirror_tree.column("estado",   width=150, anchor="center")
        sb = ttk.Scrollbar(tf, orient="vertical", command=self._mirror_tree.yview)
        self._mirror_tree.configure(yscrollcommand=sb.set)
        self._mirror_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self._mirror_tree.tag_configure("ok",   foreground=OK_CLR)
        self._mirror_tree.tag_configure("err",  foreground=ERR_CLR)
        self._mirror_tree.tag_configure("warn", foreground=WARN_CLR)

    def _refresh_mirror_tab(self, r: ViewerReport):
        ms = r.mirror_status
        for item in self._mirror_tree.get_children():
            self._mirror_tree.delete(item)

        if not ms.mirror_exists:
            self._mirror_status_lbl.config(text="— no presente", fg=FG_DIM)
            self._mirror_ts_lbl.config(text="")
            return

        problems = len(ms.problems)
        self._mirror_status_lbl.config(
            text="✓  todo ok" if ms.all_ok else f"✗  {problems} problema(s)",
            fg=OK_CLR if ms.all_ok else ERR_CLR,
        )
        self._mirror_ts_lbl.config(
            text=f"mirror: {_ts(ms.mirror_ts)}" if ms.mirror_ts else ""
        )

        for cr in ms.chunks:          # cr es ChunkReport de amcx
            icon, _ = CHUNK_STATUS_DISPLAY.get(cr.status, ("—", FG_DIM))
            sha1    = cr.sha1_mirror or "—"
            if cr.status == ChunkStatus.OK:
                tag = "ok"
            elif cr.status in (ChunkStatus.MISSING_MIRROR, ChunkStatus.MISSING_ORIG, ChunkStatus.OUTDATED):
                tag = "warn"
            else:
                tag = "err"
            self._mirror_tree.insert("", "end",
                values=(cr.chunk_id, cr.summary, sha1, icon),
                tags=(tag,))

    # ── Recovery tab ─────────────────────────────────────────────────────────

    def _build_recovery_tab(self):
        f = self._tab_recovery
        f.columnconfigure(1, weight=1)
        fields = [
            ("Estado",       "present"),
            ("Grupos XOR",   "num_groups"),
            ("Tamaño grupo", "group_size"),
        ]
        self._rec_vars: dict[str, tk.StringVar] = {}
        self._rec_status_lbl: Optional[tk.Label] = None

        for row, (label, key) in enumerate(fields):
            tk.Label(f, text=label, font=SANS_SM, bg=BG, fg=FG_DIM,
                     anchor="e", width=14).grid(row=row, column=0,
                     padx=(16, 8), pady=6, sticky="e")
            var = tk.StringVar(value="—")
            self._rec_vars[key] = var
            lbl = tk.Label(f, textvariable=var, font=SANS_SM, bg=BG, fg=FG, anchor="w")
            lbl.grid(row=row, column=1, padx=(0, 16), pady=6, sticky="w")
            if key == "present":
                self._rec_status_lbl = lbl

        # Tabla de grupos
        tk.Label(f, text="Grupos", font=SANS_SM, bg=BG, fg=FG_DIM,
                 anchor="e", width=14).grid(row=len(fields), column=0,
                 padx=(16, 8), pady=(16, 4), sticky="ne")
        tf = tk.Frame(f, bg=BG)
        tf.grid(row=len(fields), column=1, padx=(0, 16), pady=(16, 4), sticky="ew")
        f.rowconfigure(len(fields), weight=1)
        cols = ("grupo", "chunks", "parity_size")
        self._rec_tree = ttk.Treeview(tf, columns=cols, show="headings",
                                      selectmode="browse", height=6)
        self._rec_tree.heading("grupo",       text="Grupo")
        self._rec_tree.heading("chunks",      text="Chunk IDs")
        self._rec_tree.heading("parity_size", text="Paridad")
        self._rec_tree.column("grupo",        width=60,  anchor="center")
        self._rec_tree.column("chunks",       width=200)
        self._rec_tree.column("parity_size",  width=100, anchor="center")
        sb = ttk.Scrollbar(tf, orient="vertical", command=self._rec_tree.yview)
        self._rec_tree.configure(yscrollcommand=sb.set)
        self._rec_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        info = tk.Label(
            f, bg=BG, fg=FG_DIM, font=SANS_SM, justify="left",
            text="Paridad XOR: solo un chunk por grupo puede recuperarse.\n"
                 "Si dos del mismo grupo están corruptos, la recuperación falla.",
        )
        info.grid(row=len(fields) + 1, column=0, columnspan=2,
                  padx=16, pady=(12, 0), sticky="w")

    def _refresh_recovery_tab(self, r: ViewerReport):
        for item in self._rec_tree.get_children():
            self._rec_tree.delete(item)

        blocks = r.recovery_blocks  # [(gidx, [chunk_ids], parity_bytes)]
        if not blocks:
            self._rec_vars["present"].set("— no presente")
            if self._rec_status_lbl:
                self._rec_status_lbl.config(fg=FG_DIM)
            self._rec_vars["num_groups"].set("—")
            self._rec_vars["group_size"].set("—")
            return

        self._rec_vars["present"].set("✓  presente")
        if self._rec_status_lbl:
            self._rec_status_lbl.config(fg=OK_CLR)
        self._rec_vars["num_groups"].set(str(len(blocks)))

        sizes = [len(ids) for _, ids, _ in blocks]
        group_size = sizes[0] if sizes else 0
        self._rec_vars["group_size"].set(f"{group_size} chunks por grupo")

        for gidx, chunk_ids, parity in blocks:
            ids_str = ", ".join(str(cid) for cid in chunk_ids)
            self._rec_tree.insert("", "end",
                values=(gidx, ids_str, _size(len(parity))))

    # ── Mapa de memoria ───────────────────────────────────────────────────────

    def _build_map_tab(self):
        f = self._tab_map
        f.rowconfigure(0, weight=1)
        f.columnconfigure(0, weight=1)
        self._map_canvas = tk.Canvas(f, bg=BG, highlightthickness=0)
        sb_v = ttk.Scrollbar(f, orient="vertical",   command=self._map_canvas.yview)
        sb_h = ttk.Scrollbar(f, orient="horizontal", command=self._map_canvas.xview)
        self._map_canvas.configure(yscrollcommand=sb_v.set, xscrollcommand=sb_h.set)
        self._map_canvas.grid(row=0, column=0, sticky="nsew")
        sb_v.grid(row=0, column=1, sticky="ns")
        sb_h.grid(row=1, column=0, sticky="ew")

    def _refresh_map_tab(self, r: ViewerReport):
        c = self._map_canvas
        c.delete("all")

        with open(r.path, "rb") as f:
            raw = f.read()

        regions: list[tuple[str, int, int, str]] = []
        regions.append(("HEADER", 0, 32, "#4a9eff"))
        regions.append(("INDEX", r.index_offset, r.index_size, "#818cf8"))

        for ch in r.chunks:
            regions.append((
                f"CHUNK {ch.chunk_id}\n{ch.chunk_type}\n{ch.summary[:16]}",
                ch.offset, ch.size_compressed,
                CHUNK_COLORS.get(ch.chunk_type, "#94a3b8"),
            ))

        rec_offset = raw.rfind(RECOVERY_MAGIC)
        mir_offset = raw.rfind(MIRROR_MAGIC)

        if rec_offset != -1:
            rec_end = mir_offset if mir_offset != -1 else r.file_size
            regions.append(("RECOVERY\n(XOR)", rec_offset,
                             rec_end - rec_offset, WARN_CLR))
        if mir_offset != -1:
            regions.append(("MIRROR\n(SHA-1)", mir_offset,
                             r.file_size - mir_offset, "#f472b6"))

        regions.sort(key=lambda x: x[1])

        ROW_H = 52; PAD_X = 180; PAD_Y = 20
        TOTAL = r.file_size; max_bar = 500
        c_width = PAD_X + max_bar + 200

        for i, (name, start, size, color) in enumerate(regions):
            y       = PAD_Y + i * ROW_H
            bar_len = max(6, int(size / TOTAL * max_bar)) if TOTAL else 0
            c.create_text(8, y + ROW_H // 2, anchor="w", fill=FG_DIM,
                          font=("Courier New", 9),
                          text=f"0x{start:04x}–0x{start+size-1:04x}")
            c.create_rectangle(PAD_X, y + 6, PAD_X + bar_len, y + ROW_H - 8,
                                fill=color, outline="", width=0)
            c.create_text(PAD_X + bar_len + 10, y + ROW_H // 2, anchor="w",
                          fill=FG, font=("Segoe UI", 9),
                          text=f"{name.replace(chr(10), ' ')}  {_size(size)}")

        c.configure(scrollregion=(0, 0, c_width, PAD_Y * 2 + len(regions) * ROW_H))

    # ── Hex tab ───────────────────────────────────────────────────────────────

    def _build_hex_tab(self):
        f = self._tab_hex
        top = tk.Frame(f, bg=BG)
        top.pack(fill="x", padx=12, pady=8)
        tk.Label(top, text="Chunk:", font=SANS_SM, bg=BG, fg=FG_DIM).pack(side="left")
        self._hex_chunk_var = tk.StringVar()
        self._hex_chunk_cb  = ttk.Combobox(top, textvariable=self._hex_chunk_var,
                                           state="readonly", width=36, font=SANS_SM)
        self._hex_chunk_cb.pack(side="left", padx=8)
        self._hex_chunk_cb.bind("<<ComboboxSelected>>", self._on_hex_select)

        self._hex_text = tk.Text(
            f, wrap="none", bg=BG2, fg=FG, insertbackground=FG,
            relief="flat", font=("Courier New", 10), state="disabled",
            padx=10, pady=8, highlightthickness=0,
        )
        sb_y = ttk.Scrollbar(f, orient="vertical", command=self._hex_text.yview)
        self._hex_text.configure(yscrollcommand=sb_y.set)
        self._hex_text.pack(side="left", fill="both", expand=True, padx=(12, 0), pady=(0, 4))
        sb_y.pack(side="right", fill="y", pady=(40, 4))

    def _refresh_hex_tab(self, r: ViewerReport):
        values = [f"Chunk {ch.chunk_id} — {ch.chunk_type} — {ch.summary}"
                  for ch in r.chunks]
        self._hex_chunk_cb["values"] = values
        if values:
            self._hex_chunk_cb.current(0)
            self._show_hex_for_chunk(r.chunks[0])

    def _on_hex_select(self, _event=None):
        if not self.report: return
        idx = self._hex_chunk_cb.current()
        if 0 <= idx < len(self.report.chunks):
            self._show_hex_for_chunk(self.report.chunks[idx])

    def _show_hex_for_chunk(self, ch: ViewerChunk):
        self._hex_text.config(state="normal")
        self._hex_text.delete("1.0", "end")
        self._hex_text.insert("1.0",
            f"── Comprimido ({_size(ch.size_compressed)}, algo={ch.algorithm}) ──\n"
            + _hexdump(ch.raw_compressed) + "\n\n"
        )
        if ch.content:
            self._hex_text.insert("end",
                f"── Descomprimido ({_size(ch.size_original)}) ──\n"
                + _hexdump(ch.content)
            )
        self._hex_text.config(state="disabled")

    # ── Sidebar chunk list ────────────────────────────────────────────────────

    def _refresh_chunk_list(self, r: ViewerReport):
        self._chunk_list.delete(0, "end")
        for ch in r.chunks:
            self._chunk_list.insert(
                "end", f"  #{ch.chunk_id}  {ch.chunk_type:<10}  {ch.summary[:18]}"
            )
        for i, ch in enumerate(r.chunks):
            self._chunk_list.itemconfig(i, fg=CHUNK_COLORS.get(ch.chunk_type, FG))

    def _on_chunk_select(self, _event=None):
        if not self.report: return
        sel = self._chunk_list.curselection()
        if not sel: return
        idx = sel[0]
        if 0 <= idx < len(self.report.chunks):
            ch = self.report.chunks[idx]
            self._refresh_chunk_tab(ch)
            self._show_hex_for_chunk(ch)
            self._hex_chunk_cb.current(idx)
            self._nb.select(self._tab_chunk)

    # ── Carga ────────────────────────────────────────────────────────────────

    def _open_file(self):
        path = filedialog.askopenfilename(
            title="Abrir archivo .amcx",
            filetypes=[("Archivos AMCX", "*.amcx"), ("Todos", "*.*")],
        )
        if path:
            self._load(path)

    def _load(self, path: str):
        try:
            report = load_report(path)
        except AMCXError as e:
            messagebox.showerror("Error amcx", str(e))
            return
        except Exception as e:
            messagebox.showerror("Error al abrir", str(e))
            return

        self.report = report
        self.title(f"amcx viewer — {os.path.basename(path)}")
        self._file_label.config(text=os.path.basename(path), fg=FG)
        self._warn_label.config(
            text=f"⚠  {len(report.warnings)} advertencia(s)" if report.warnings else ""
        )

        self._refresh_header_tab(report)
        self._refresh_chunk_list(report)
        self._refresh_mirror_tab(report)
        self._refresh_recovery_tab(report)
        self._refresh_map_tab(report)
        self._refresh_hex_tab(report)

        if report.chunks:
            self._chunk_list.selection_set(0)
            self._refresh_chunk_tab(report.chunks[0])
            self._show_hex_for_chunk(report.chunks[0])

        self._nb.select(self._tab_header)


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    initial = sys.argv[1] if len(sys.argv) > 1 else None
    app = AMCXViewer(initial_file=initial)
    app.mainloop()

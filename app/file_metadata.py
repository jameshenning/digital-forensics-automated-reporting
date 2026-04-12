"""
Local metadata extraction for uploaded evidence files.

Stdlib only — no external forensic tools required. The AI analysis
pipeline reads this metadata and synthesizes a narrative; it does NOT
inspect file contents directly. Anything that would need a heavy
parsing dep (PyPDF, exifread, pillow, python-magic) is intentionally
omitted; richer extractors can be added later as separate modules.
"""

from __future__ import annotations

import hashlib
import mimetypes
from pathlib import Path
from typing import Any


def sha256_of(path: Path) -> str:
    """Stream the file and return its SHA-256 hex digest."""
    h = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def guess_mime(filename: str) -> str:
    mime, _ = mimetypes.guess_type(filename)
    return mime or "application/octet-stream"


def extract_metadata(path: Path, mime: str) -> dict[str, Any]:
    """
    Extract lightweight metadata from a file using only stdlib parsers.
    Returns an empty dict on any failure — the caller is expected to
    treat metadata as best-effort.
    """
    meta: dict[str, Any] = {}
    try:
        with path.open("rb") as fp:
            header = fp.read(32)
        meta["magic_hex"] = header[:16].hex()
    except Exception:
        return meta

    if mime.startswith("image/"):
        meta.update(_image_metadata(path))
    elif mime == "application/pdf":
        meta.update(_pdf_metadata(path))
    elif mime in ("application/zip", "application/x-zip-compressed"):
        meta.update({"format": "ZIP"})
    elif mime.startswith("text/") or mime in ("application/json", "application/xml"):
        meta.update(_text_metadata(path))

    return meta


def _image_metadata(path: Path) -> dict[str, Any]:
    """Pull width / height for common image formats using only stdlib."""
    info: dict[str, Any] = {}
    try:
        with path.open("rb") as fp:
            data = fp.read(64)
    except Exception:
        return info

    if data[:8] == b"\x89PNG\r\n\x1a\n":
        info["format"] = "PNG"
        info["width"] = int.from_bytes(data[16:20], "big")
        info["height"] = int.from_bytes(data[20:24], "big")
    elif data[:3] == b"\xff\xd8\xff":
        info["format"] = "JPEG"
    elif data[:6] in (b"GIF87a", b"GIF89a"):
        info["format"] = "GIF"
        info["width"] = int.from_bytes(data[6:8], "little")
        info["height"] = int.from_bytes(data[8:10], "little")
    elif data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        info["format"] = "WEBP"
    elif data[:2] == b"BM":
        info["format"] = "BMP"
    elif data[:4] in (b"II*\x00", b"MM\x00*"):
        info["format"] = "TIFF"
    return info


def _pdf_metadata(path: Path) -> dict[str, Any]:
    info: dict[str, Any] = {"format": "PDF"}
    try:
        with path.open("rb") as fp:
            head = fp.read(1024)
    except Exception:
        return info
    if head.startswith(b"%PDF-"):
        first_line = head.split(b"\n", 1)[0].decode("ascii", errors="replace")
        info["pdf_version"] = first_line.replace("%PDF-", "").strip()
    return info


def _text_metadata(path: Path) -> dict[str, Any]:
    """For small text-like files, capture line count and a leading sample."""
    info: dict[str, Any] = {}
    try:
        size = path.stat().st_size
        if size < 256 * 1024:
            text = path.read_text(encoding="utf-8", errors="replace")
            info["line_count"] = text.count("\n") + 1
            info["char_count"] = len(text)
            info["sample_first_500_chars"] = text[:500]
    except Exception:
        pass
    return info

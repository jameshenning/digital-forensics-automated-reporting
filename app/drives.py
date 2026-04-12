"""
DFARS Desktop - External drive detection and validation.

Forensic best practice: evidence files must never reside on the
examiner's primary / system drive. This module detects removable and
external drives on Windows and validates that a chosen evidence path
is NOT on the system drive.
"""

from __future__ import annotations

import ctypes
import logging
import os
import string
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

log = logging.getLogger(__name__)

# Win32 drive-type constants (GetDriveTypeW return values)
_DRIVE_UNKNOWN = 0
_DRIVE_NO_ROOT_DIR = 1
_DRIVE_REMOVABLE = 2
_DRIVE_FIXED = 3
_DRIVE_REMOTE = 4
_DRIVE_CDROM = 5
_DRIVE_RAMDISK = 6

_DRIVE_TYPE_LABELS = {
    _DRIVE_UNKNOWN: "Unknown",
    _DRIVE_NO_ROOT_DIR: "Invalid",
    _DRIVE_REMOVABLE: "Removable",
    _DRIVE_FIXED: "Fixed",
    _DRIVE_REMOTE: "Network",
    _DRIVE_CDROM: "CD-ROM",
    _DRIVE_RAMDISK: "RAM Disk",
}


@dataclass
class DriveInfo:
    """Describes a mounted drive."""
    letter: str            # e.g. "E"
    root: str              # e.g. "E:\\"
    drive_type: int        # Win32 constant
    type_label: str        # human-readable
    label: str             # volume label (may be empty)
    is_system: bool        # True if this is the Windows system drive
    total_bytes: int
    free_bytes: int

    @property
    def total_gb(self) -> float:
        return self.total_bytes / (1024 ** 3)

    @property
    def free_gb(self) -> float:
        return self.free_bytes / (1024 ** 3)

    @property
    def display_name(self) -> str:
        label = self.label or self.type_label
        return f"{self.letter}: [{label}] — {self.free_gb:.1f} GB free / {self.total_gb:.1f} GB"


def _get_system_drive() -> str:
    """Return the system drive letter (e.g. 'C')."""
    return os.environ.get("SystemDrive", "C:")[:1].upper()


def list_drives() -> List[DriveInfo]:
    """
    Enumerate all mounted drives on the system. Returns DriveInfo for
    each accessible drive. Uses Win32 API on Windows; on other platforms
    returns an empty list (DFARS Desktop is Windows-only).
    """
    if os.name != "nt":
        return []

    system_drive = _get_system_drive()
    drives: List[DriveInfo] = []

    # GetLogicalDrives returns a bitmask: bit 0 = A, bit 1 = B, etc.
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()  # type: ignore[attr-defined]

    for i, letter in enumerate(string.ascii_uppercase):
        if not (bitmask & (1 << i)):
            continue

        root = f"{letter}:\\"
        drive_type = ctypes.windll.kernel32.GetDriveTypeW(root)  # type: ignore[attr-defined]

        # Skip invalid / CD-ROM / RAM disk
        if drive_type in (_DRIVE_NO_ROOT_DIR, _DRIVE_CDROM, _DRIVE_RAMDISK):
            continue

        # Get volume label
        vol_name_buf = ctypes.create_unicode_buffer(261)
        try:
            ctypes.windll.kernel32.GetVolumeInformationW(  # type: ignore[attr-defined]
                root, vol_name_buf, 261,
                None, None, None, None, 0,
            )
            label = vol_name_buf.value
        except Exception:
            label = ""

        # Get disk space
        total = ctypes.c_ulonglong(0)
        free = ctypes.c_ulonglong(0)
        try:
            ctypes.windll.kernel32.GetDiskFreeSpaceExW(  # type: ignore[attr-defined]
                root, None, ctypes.byref(total), ctypes.byref(free),
            )
        except Exception:
            pass

        drives.append(DriveInfo(
            letter=letter,
            root=root,
            drive_type=drive_type,
            type_label=_DRIVE_TYPE_LABELS.get(drive_type, "Unknown"),
            label=label,
            is_system=(letter.upper() == system_drive),
            total_bytes=total.value,
            free_bytes=free.value,
        ))

    return drives


def list_external_drives() -> List[DriveInfo]:
    """
    Return only non-system drives suitable for evidence storage.
    Includes removable drives, non-system fixed drives, and network drives.
    Excludes the system drive (typically C:).
    """
    return [d for d in list_drives() if not d.is_system]


def validate_evidence_drive(path: str) -> tuple[bool, str]:
    """
    Validate that a path is suitable for evidence storage:
    1. Must not be on the system drive
    2. Must be accessible (drive mounted / directory exists or can be created)
    3. Must be writable

    Returns (ok, message).
    """
    if not path or not path.strip():
        return False, "No evidence drive path provided."

    resolved = Path(path).resolve()

    # Check it's not on the system drive
    system_drive = _get_system_drive()
    path_drive = str(resolved)[:1].upper()
    if path_drive == system_drive:
        return False, (
            f"Evidence must not be stored on the system drive ({system_drive}:). "
            f"Select an external or removable drive."
        )

    # Check the drive root is accessible
    drive_root = Path(f"{path_drive}:\\")
    if not drive_root.exists():
        return False, (
            f"Drive {path_drive}: is not accessible. "
            f"Ensure the external drive is connected and mounted."
        )

    # Check/create the target directory
    try:
        resolved.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        return False, f"Cannot create evidence directory at {resolved}: {e}"

    # Check writability
    test_file = resolved / ".dfars_write_test"
    try:
        test_file.write_text("test", encoding="utf-8")
        test_file.unlink()
    except OSError as e:
        return False, f"Evidence directory at {resolved} is not writable: {e}"

    return True, f"Evidence drive {path_drive}: validated successfully."


def is_drive_present(path: str) -> bool:
    """Quick check: is the drive letter in the given path currently mounted?"""
    if not path:
        return False
    try:
        drive_letter = Path(path).resolve().drive[:1].upper()
        return Path(f"{drive_letter}:\\").exists()
    except Exception:
        return False


def evidence_dir_on_drive(drive_path: str, case_id: str, evidence_id: Optional[str] = None) -> Path:
    """
    Build the evidence storage path on the external drive.
    Structure: <drive_path>/DFARS_Evidence/<case_id>/<evidence_id>/
    """
    from .paths import _safe_path_segment
    base = Path(drive_path) / "DFARS_Evidence" / _safe_path_segment(case_id)
    if evidence_id:
        base = base / _safe_path_segment(evidence_id)
    return base

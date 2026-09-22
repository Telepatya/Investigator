"""Stable storage keys for one server-assigned memory upload basename."""

import hashlib
from pathlib import Path

MEMORY_EXTENSIONS = {".raw", ".dmp", ".mem", ".vmem", ".bin", ".img", ".lime", ".dd"}


def is_memory_upload(path: Path) -> bool:
    return path.suffix.lower() in MEMORY_EXTENSIONS or (
        not path.suffix and path.name.lower() in {"physicalmemory", "memory", "ram"}
    )


def memory_upload_key(name: str) -> str:
    return "upload-" + hashlib.sha256(name.encode("utf-8")).hexdigest()

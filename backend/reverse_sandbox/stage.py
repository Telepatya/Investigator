#!/usr/bin/env python3
"""Fixed, bounded host-to-sandbox artifact transport (not model-callable)."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import sys
from pathlib import Path

INPUTS = Path("/workspace/inputs")
CONTEXT = Path("/workspace/context")
ARTIFACT_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.I,
)
MAX_CHUNK = 48 * 1024
PROTOCOL_VERSION = "3"


def fail(message: str) -> None:
    sys.stderr.write(message + "\n")
    raise SystemExit(2)


CONTEXT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def target_for(namespace: str, name: str) -> Path:
    if namespace == "inputs":
        if not ARTIFACT_RE.fullmatch(name):
            fail("Invalid artifact id")
        root = INPUTS.resolve(strict=True)
    elif namespace == "context":
        if not CONTEXT_NAME_RE.fullmatch(name):
            fail("Invalid context filename")
        root = CONTEXT.resolve(strict=True)
    else:
        fail("Invalid staging namespace")
    target = root / name
    try:
        target.resolve(strict=False).relative_to(root)
    except ValueError:
        fail("Artifact path escaped the input directory")
    if target.is_symlink():
        fail("Artifact path is a symlink")
    return target


def write_chunk(namespace: str, name: str, offset_text: str, encoded: str) -> None:
    target = target_for(namespace, name)
    try:
        offset = int(offset_text)
        chunk = base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (ValueError, TypeError):
        fail("Invalid staging chunk")
    if offset < 0 or len(chunk) > MAX_CHUNK:
        fail("Invalid staging bounds")
    current = target.stat().st_size if target.exists() else 0
    if current != offset:
        fail("Unexpected staging offset")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags, 0o600)
    try:
        written = os.write(descriptor, chunk)
        if written != len(chunk):
            fail("Incomplete staging write")
    finally:
        os.close(descriptor)


def seal(namespace: str, name: str, size_text: str, expected_sha256: str) -> None:
    target = target_for(namespace, name)
    try:
        expected_size = int(size_text)
    except ValueError:
        fail("Invalid artifact size")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        fail("Invalid artifact digest")
    if not target.is_file() or target.stat().st_size != expected_size:
        fail("Staged artifact size mismatch")
    digest = hashlib.sha256()
    with target.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    if digest.hexdigest() != expected_sha256:
        fail("Staged artifact digest mismatch")
    target.chmod(0o440)


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1] == "protocol-version":
        print(PROTOCOL_VERSION)
        return
    if os.geteuid() != 0:
        fail("Staging requires the trusted host transport")
    if len(sys.argv) == 2 and sys.argv[1] == "prepare":
        for name in ("inputs", "context", "output", "tools"):
            path = Path("/workspace") / name
            path.mkdir(mode=0o750, exist_ok=True)
            path.chmod(0o770 if name in {"output", "tools"} else 0o750)
        return
    if len(sys.argv) == 6 and sys.argv[1] == "write":
        write_chunk(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
        return
    if len(sys.argv) == 6 and sys.argv[1] == "seal":
        seal(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
        return
    fail("Invalid staging request")


if __name__ == "__main__":
    main()

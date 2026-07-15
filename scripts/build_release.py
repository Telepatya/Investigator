#!/usr/bin/env python3
"""Build deterministic Investigator release assets."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from generate_sbom import write_sbom

ROOT = Path(__file__).resolve().parents[1]
VERSION_RE = re.compile(r"^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")
ROOT_FILES = (
    "README.md", "LICENSE", "NOTICE", "SECURITY.md", "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md", "MAINTAINERS.md", "CHANGELOG.md", "run.py", "run.bat",
)
BACKEND_FILES = (
    "backend/requirements.lock", "backend/requirements-memory.lock",
    "backend/requirements.txt",
)
TREES = ("backend/app", "backend/reverse_sandbox", "frontend/dist", "docs", "demo")


def source_epoch() -> int:
    raw = os.environ.get("SOURCE_DATE_EPOCH", "315532800")
    try:
        epoch = int(raw)
    except ValueError as exc:
        raise ValueError("SOURCE_DATE_EPOCH must be an integer") from exc
    return max(epoch, 315532800)


def release_files() -> Iterator[Path]:
    for name in (*ROOT_FILES, *BACKEND_FILES):
        path = ROOT / name
        if not path.is_file():
            raise FileNotFoundError(f"required release file is missing: {name}")
        yield path
    for tree in TREES:
        root = ROOT / tree
        if not root.is_dir():
            raise FileNotFoundError(f"required release directory is missing: {tree}")
        for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
            if path.is_file() and not path.is_symlink() and "__pycache__" not in path.parts:
                yield path


def zip_info(name: str, epoch: int, executable: bool = False) -> zipfile.ZipInfo:
    stamp = datetime.fromtimestamp(epoch, tz=timezone.utc)
    info = zipfile.ZipInfo(name, stamp.timetuple()[:6])
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = ((0o755 if executable else 0o644) & 0xFFFF) << 16
    return info


def add_bytes(archive: zipfile.ZipFile, name: str, data: bytes, epoch: int, executable: bool = False) -> None:
    archive.writestr(zip_info(name, epoch, executable), data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build(version: str, output: Path) -> list[Path]:
    if not VERSION_RE.fullmatch(version):
        raise ValueError("version must match vMAJOR.MINOR.PATCH with an optional prerelease")
    if not (ROOT / "frontend" / "dist" / "index.html").is_file():
        raise FileNotFoundError("frontend/dist/index.html is missing; run npm ci and npm run build")
    notes = ROOT / "docs" / "releases" / f"{version}.md"
    if not notes.is_file():
        raise FileNotFoundError(f"versioned release notes are missing: {notes.relative_to(ROOT)}")

    output.mkdir(parents=True, exist_ok=True)
    epoch = source_epoch()
    sbom = output / f"Investigator-{version}-sbom.cdx.json"
    notes_asset = output / f"Investigator-{version}-release-notes.md"
    archive_path = output / f"Investigator-{version}-windows.zip"
    checksums = output / "SHA256SUMS.txt"
    write_sbom(version, sbom)
    shutil.copyfile(notes, notes_asset)

    prefix = f"Investigator-{version}"
    files = sorted(set(release_files()), key=lambda path: path.relative_to(ROOT).as_posix())
    with zipfile.ZipFile(archive_path, "w", allowZip64=True) as archive:
        for path in files:
            relative = path.relative_to(ROOT).as_posix()
            executable = relative.endswith((".py", ".sh")) or relative == "run.bat"
            add_bytes(archive, f"{prefix}/{relative}", path.read_bytes(), epoch, executable)
        add_bytes(archive, f"{prefix}/SBOM.cdx.json", sbom.read_bytes(), epoch)
        add_bytes(archive, f"{prefix}/RELEASE_NOTES.md", notes.read_bytes(), epoch)

    assets = [archive_path, sbom, notes_asset]
    checksum_text = "".join(f"{sha256(path)}  {path.name}\n" for path in sorted(assets))
    checksums.write_text(checksum_text, encoding="utf-8", newline="\n")
    return [*assets, checksums]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    for asset in build(args.version, args.output.resolve()):
        print(f"{asset.name}: {sha256(asset)}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as exc:
        print(f"release build failed: {exc}", file=sys.stderr)
        sys.exit(1)

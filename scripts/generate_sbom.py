#!/usr/bin/env python3
"""Generate a deterministic CycloneDX SBOM from committed dependency locks."""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PYTHON_LOCK = ROOT / "backend" / "requirements-memory.lock"
REVERSE_PYTHON_LOCK = ROOT / "backend" / "reverse_sandbox" / "requirements.lock"
NPM_LOCK = ROOT / "frontend" / "package-lock.json"
REVERSE_DOCKERFILE = ROOT / "backend" / "reverse_sandbox" / "Dockerfile"
PYTHON_PACKAGE_RE = re.compile(
    r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)(?:\s*;\s*(.*?))?\s*\\?$"
)


def python_components(path: Path, source_lock: str = "backend/requirements-memory.lock") -> list[dict[str, Any]]:
    components: dict[str, dict[str, Any]] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        match = PYTHON_PACKAGE_RE.match(raw_line.strip())
        if not match:
            continue
        name, version, marker = match.groups()
        normalized = name.lower().replace("_", "-")
        purl = f"pkg:pypi/{urllib.parse.quote(normalized, safe='')}@{urllib.parse.quote(version, safe='.+-')}"
        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": purl,
            "name": normalized,
            "version": version,
            "purl": purl,
            "properties": [
                {"name": "investigator:ecosystem", "value": "python"},
                {"name": "investigator:source-lock", "value": source_lock},
            ],
        }
        if marker:
            component["properties"].append(
                {"name": "investigator:environment-marker", "value": marker.strip()}
            )
        components.setdefault(purl, component)
    return list(components.values())


def _npm_name(package_path: str, entry: dict[str, Any]) -> str:
    if entry.get("name"):
        return str(entry["name"])
    return package_path.rsplit("node_modules/", 1)[-1]


def npm_components(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    packages = data.get("packages")
    if not isinstance(packages, dict):
        raise ValueError("frontend/package-lock.json must contain a packages map")
    components: dict[str, dict[str, Any]] = {}
    for package_path, raw_entry in packages.items():
        if not package_path or not isinstance(raw_entry, dict) or not raw_entry.get("version"):
            continue
        name = _npm_name(package_path, raw_entry)
        version = str(raw_entry["version"])
        encoded_name = urllib.parse.quote(name, safe="/")
        purl = f"pkg:npm/{encoded_name}@{urllib.parse.quote(version, safe='.+-')}"
        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": purl,
            "name": name,
            "version": version,
            "purl": purl,
            "properties": [
                {"name": "investigator:ecosystem", "value": "npm"},
                {"name": "investigator:source-lock", "value": "frontend/package-lock.json"},
                {"name": "investigator:development", "value": str(bool(raw_entry.get("dev"))).lower()},
            ],
        }
        if raw_entry.get("integrity"):
            component["properties"].append(
                {"name": "investigator:npm-integrity", "value": str(raw_entry["integrity"])}
            )
        components.setdefault(purl, component)
    return list(components.values())


def reverse_sandbox_components(path: Path) -> list[dict[str, Any]]:
    """Record the pinned sandbox base image and explicitly locked apt tools."""
    if not path.is_file():
        return []
    match = re.search(
        r"^FROM\s+([^\s:@]+):([^\s@]+)@sha256:([0-9a-f]{64})\s*$",
        path.read_text(encoding="utf-8"),
        flags=re.MULTILINE | re.IGNORECASE,
    )
    if not match:
        raise ValueError("Reverse sandbox Dockerfile must pin its base image by sha256 digest")
    name, version, digest = match.groups()
    purl = (
        f"pkg:docker/{urllib.parse.quote(name, safe='/')}@{urllib.parse.quote(version, safe='.+-')}"
        f"?digest=sha256%3A{digest.lower()}"
    )
    components = [{
        "type": "container",
        "bom-ref": purl,
        "name": name,
        "version": version,
        "purl": purl,
        "hashes": [{"alg": "SHA-256", "content": digest.lower()}],
        "properties": [
            {"name": "investigator:ecosystem", "value": "docker"},
            {"name": "investigator:source", "value": "backend/reverse_sandbox/Dockerfile"},
        ],
    }]
    for package, package_version in re.findall(
        r"^\s{8}([a-z0-9+.-]+)=([^\s\\]+)\s*\\?$",
        path.read_text(encoding="utf-8"),
        flags=re.MULTILINE | re.IGNORECASE,
    ):
        apt_purl = (
            f"pkg:deb/ubuntu/{urllib.parse.quote(package.lower(), safe='')}@"
            f"{urllib.parse.quote(package_version, safe='.+-~:')}?distro=ubuntu-22.04"
        )
        components.append({
            "type": "library",
            "bom-ref": apt_purl,
            "name": package.lower(),
            "version": package_version,
            "purl": apt_purl,
            "properties": [
                {"name": "investigator:ecosystem", "value": "ubuntu-apt"},
                {"name": "investigator:source", "value": "backend/reverse_sandbox/Dockerfile"},
            ],
        })
    return components


def merge_components(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge shared dependencies without losing their lock-file provenance."""
    merged: dict[str, dict[str, Any]] = {}
    for component in items:
        purl = component["purl"]
        current = merged.get(purl)
        if current is None:
            merged[purl] = component
            continue
        properties = current.setdefault("properties", [])
        for prop in component.get("properties", []):
            if prop not in properties:
                properties.append(prop)
    return list(merged.values())


def build_sbom(version: str) -> dict[str, Any]:
    components = merge_components(
        python_components(PYTHON_LOCK)
        + python_components(
            REVERSE_PYTHON_LOCK, "backend/reverse_sandbox/requirements.lock"
        )
        + npm_components(NPM_LOCK)
        + reverse_sandbox_components(REVERSE_DOCKERFILE)
    )
    components.sort(key=lambda item: (item["purl"].casefold(), item["purl"]))
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "Investigator deterministic SBOM generator",
                    "version": "1",
                }]
            },
            "component": {
                "type": "application",
                "bom-ref": f"pkg:github/Telepatya/Investigator@{version}",
                "name": "Investigator",
                "version": version,
                "purl": f"pkg:github/Telepatya/Investigator@{version}",
            },
        },
        "components": components,
    }


def write_sbom(version: str, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(build_sbom(version), indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    write_sbom(args.version, args.output)
    print(args.output)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"SBOM generation failed: {exc}", file=sys.stderr)
        sys.exit(1)

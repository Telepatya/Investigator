#!/usr/bin/env python3
"""Create or update the repository's canonical GitHub labels."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = ROOT / ".github" / "labels.json"
COLOR_RE = re.compile(r"^[0-9a-fA-F]{6}$")


def load_labels(path: Path) -> list[dict[str, str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list) or not data:
        raise ValueError("label config must be a non-empty JSON array")
    seen: set[str] = set()
    labels: list[dict[str, str]] = []
    for item in data:
        if not isinstance(item, dict):
            raise ValueError("each label must be an object")
        name = str(item.get("name", "")).strip()
        color = str(item.get("color", "")).strip().lstrip("#")
        description = str(item.get("description", "")).strip()
        if not name or name.casefold() in seen:
            raise ValueError(f"missing or duplicate label name: {name!r}")
        if not COLOR_RE.fullmatch(color):
            raise ValueError(f"invalid color for {name!r}: {color!r}")
        if len(description) > 100:
            raise ValueError(f"description for {name!r} exceeds 100 characters")
        seen.add(name.casefold())
        labels.append({"name": name, "color": color.lower(), "description": description})
    return labels


def api_request(method: str, url: str, token: str, payload: dict[str, str]) -> None:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "investigator-label-sync",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30):
            return
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub API {method} failed: {exc.code} {detail}") from exc


def label_exists(url: str, token: str) -> bool:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "investigator-label-sync",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30):
            return True
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        raise


def sync(labels: list[dict[str, str]], repository: str, token: str) -> None:
    base = f"https://api.github.com/repos/{repository}/labels"
    for label in labels:
        encoded = urllib.parse.quote(label["name"], safe="")
        item_url = f"{base}/{encoded}"
        exists = label_exists(item_url, token)
        api_request("PATCH" if exists else "POST", item_url if exists else base, token, label)
        print(f"{'updated' if exists else 'created'}: {label['name']}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN"))
    parser.add_argument("--check", action="store_true", help="validate config without API calls")
    args = parser.parse_args()
    labels = load_labels(args.config)
    if args.check:
        print(f"validated {len(labels)} labels")
        return 0
    if not args.repository or not re.fullmatch(r"[^/]+/[^/]+", args.repository):
        parser.error("--repository OWNER/REPO or GITHUB_REPOSITORY is required")
    if not args.token:
        parser.error("--token or GITHUB_TOKEN is required")
    sync(labels, args.repository, args.token)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"label sync failed: {exc}", file=sys.stderr)
        sys.exit(1)

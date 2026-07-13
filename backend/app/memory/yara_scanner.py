"""YARA scanning of memory regions and dumped process images."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.config import load_config

BUNDLED_RULES_DIR = Path(__file__).parent / "yara_rules"


class YaraScanner:
    def __init__(self):
        self.rules = None
        self._load()

    def _load(self) -> None:
        try:
            import yara
        except ImportError:
            self.rules = None
            return

        filepaths: dict[str, str] = {}
        for rule_file in BUNDLED_RULES_DIR.glob("*.yar"):
            filepaths[rule_file.stem] = str(rule_file)

        cfg = load_config()
        user_dir = cfg.yara_rules_dir
        if user_dir and Path(user_dir).is_dir():
            for rule_file in Path(user_dir).glob("**/*.yar"):
                filepaths[f"user_{rule_file.stem}"] = str(rule_file)
            for rule_file in Path(user_dir).glob("**/*.yara"):
                filepaths[f"user_{rule_file.stem}"] = str(rule_file)

        if not filepaths:
            self.rules = None
            return
        try:
            self.rules = yara.compile(filepaths=filepaths)
        except Exception:
            self.rules = None

    def available(self) -> bool:
        return self.rules is not None

    def scan_bytes(self, data: bytes) -> list[dict[str, Any]]:
        if not self.rules or not data:
            return []
        try:
            matches = self.rules.match(data=data, timeout=60)
        except Exception:
            return []
        results = []
        for m in matches:
            results.append({
                "rule": m.rule,
                "tags": list(m.tags),
                "meta": dict(m.meta),
                "strings": [
                    getattr(s, "identifier", str(s))
                    for s in (m.strings or [])
                ][:10],
            })
        return results

    def scan_file(self, path: Path) -> list[dict[str, Any]]:
        if not self.rules:
            return []
        try:
            matches = self.rules.match(str(path), timeout=120)
        except Exception:
            return []
        return [
            {"rule": m.rule, "tags": list(m.tags), "meta": dict(m.meta)}
            for m in matches
        ]


_scanner: YaraScanner | None = None


def get_scanner() -> YaraScanner:
    global _scanner
    if _scanner is None:
        _scanner = YaraScanner()
    return _scanner

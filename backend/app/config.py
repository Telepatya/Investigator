"""Application configuration and secure credential storage."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Literal

import keyring
from pydantic import BaseModel, Field

SERVICE_NAME = "investigator-dfir"
UPLOAD_STAGING_PREFIX = ".investigator-upload-"
DEFAULT_CONFIG_DIR = Path.home() / ".investigator"
DEFAULT_CASES_DIR = DEFAULT_CONFIG_DIR / "cases"
CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.json"
_CASE_ID_COMPONENT_RE = re.compile(r"^[0-9a-fA-F]{8}$")
_UPLOAD_NAME_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ ()%+-]{0,254}$")


ProviderType = Literal["ollama", "openai", "gemini", "anthropic"]


class LLMSettings(BaseModel):
    provider: ProviderType = "ollama"
    model: str = "llama3.2"
    ollama_base_url: str = "http://localhost:11434"
    temperature: float = 0.2
    max_tokens: int = 4096
    analysis_max_tool_calls: int = Field(default=8, ge=0, le=20)
    chat_max_tool_calls: int = Field(default=4, ge=0, le=20)
    entity_max_tool_calls: int = Field(default=5, ge=0, le=20)


class AppConfig(BaseModel):
    llm: LLMSettings = Field(default_factory=LLMSettings)
    cases_dir: str = str(DEFAULT_CASES_DIR)
    yara_rules_dir: str = ""


def ensure_dirs() -> None:
    DEFAULT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    DEFAULT_CASES_DIR.mkdir(parents=True, exist_ok=True)


def load_config() -> AppConfig:
    ensure_dirs()
    if CONFIG_FILE.exists():
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        return AppConfig.model_validate(data)
    cfg = AppConfig()
    save_config(cfg)
    return cfg


def save_config(config: AppConfig) -> None:
    ensure_dirs()
    CONFIG_FILE.write_text(config.model_dump_json(indent=2), encoding="utf-8")


def _key_name(provider: ProviderType) -> str:
    return f"api_key_{provider}"


def save_api_key(provider: ProviderType, api_key: str) -> None:
    keyring.set_password(SERVICE_NAME, _key_name(provider), api_key)


def get_api_key(provider: ProviderType) -> str | None:
    return keyring.get_password(SERVICE_NAME, _key_name(provider))


def delete_api_key(provider: ProviderType) -> None:
    try:
        keyring.delete_password(SERVICE_NAME, _key_name(provider))
    except keyring.errors.PasswordDeleteError:
        return


def has_api_key(provider: ProviderType) -> bool:
    return bool(get_api_key(provider))


def get_cases_dir(config: AppConfig | None = None) -> Path:
    cfg = config or load_config()
    path = Path(cfg.cases_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def validate_case_id_component(case_id: str) -> str:
    value = str(case_id or "")
    if not _CASE_ID_COMPONENT_RE.fullmatch(value):
        raise ValueError("Invalid case_id path component")
    return value


def _ensure_contained(base: Path, target: Path) -> Path:
    """Reject a path that escapes ``base`` after full symlink resolution.

    The guard uses ``os.path.realpath`` and a separator-terminated prefix check
    so both the runtime and static analysis recognize containment before any
    filesystem operation runs on ``target``.
    """
    base_real = os.path.realpath(base)
    target_real = os.path.realpath(target)
    if target_real != base_real and not target_real.startswith(base_real + os.sep):
        raise ValueError("Path escapes its permitted directory")
    return target


def case_dir_path(case_id: str, config: AppConfig | None = None) -> Path:
    root = get_cases_dir(config).resolve()
    path = (root / validate_case_id_component(case_id)).resolve()
    if path.parent != root:
        raise ValueError("Invalid case directory")
    return _ensure_contained(root, path)


def case_db_path(case_id: str, config: AppConfig | None = None) -> Path:
    case_root = case_dir_path(case_id, config)
    path = (case_root / "case.db").resolve()
    if path.parent != case_root:
        raise ValueError("Invalid case database path")
    return _ensure_contained(case_root, path)


def case_uploads_path(case_id: str, config: AppConfig | None = None) -> Path:
    case_root = case_dir_path(case_id, config)
    path = (case_root / "uploads").resolve()
    if path.parent != case_root:
        raise ValueError("Invalid case uploads path")
    _ensure_contained(case_root, path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def case_upload_file_path(
    case_id: str, filename: str, config: AppConfig | None = None,
) -> Path:
    safe_filename = str(filename or "")
    if not _UPLOAD_NAME_COMPONENT_RE.fullmatch(safe_filename):
        raise ValueError("Invalid upload filename path component")
    uploads = case_uploads_path(case_id, config).resolve()
    path = (uploads / safe_filename).resolve()
    if path.parent != uploads:
        raise ValueError("Invalid upload path")
    return _ensure_contained(uploads, path)

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
CONFIG_SCHEMA_VERSION = 4
UPLOAD_STAGING_PREFIX = ".investigator-upload-"
DEFAULT_CONFIG_DIR = Path.home() / ".investigator"
DEFAULT_CASES_DIR = DEFAULT_CONFIG_DIR / "cases"
CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.json"
_CASE_ID_COMPONENT_RE = re.compile(r"^[0-9a-fA-F]{8}$")
_UPLOAD_NAME_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ ()%+-]{0,254}$")


ProviderType = Literal["ollama", "openai", "openrouter", "gemini", "anthropic"]


class LLMSettings(BaseModel):
    provider: ProviderType = "ollama"
    model: str = "llama3.2"
    ollama_base_url: str = "http://localhost:11434"
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    temperature: float = 0.2
    max_tokens: int = 4096
    analysis_max_tool_calls: int = Field(default=8, ge=0, le=20)
    chat_max_tool_calls: int = Field(default=4, ge=0, le=20)
    entity_max_tool_calls: int = Field(default=5, ge=0, le=20)


class ReverseSettings(BaseModel):
    """Non-secret configuration for the static reverse-engineering sandbox."""

    sandbox_image: str = "investigator-reverse:latest"
    sandbox_idle_ttl_minutes: int = Field(default=30, ge=5, le=1440)
    sandbox_memory_limit_mb: int = Field(default=2048, ge=256, le=32768)
    sandbox_cpu_limit: float = Field(default=2.0, ge=0.25, le=16.0)
    sandbox_pids_limit: int = Field(default=128, ge=32, le=1024)
    analysis_max_turns: int = Field(default=25, ge=1, le=100)
    analysis_extension_turns: int = Field(default=10, ge=1, le=50)
    max_upload_bytes: int = Field(default=2 * 1024 ** 3, ge=1024, le=64 * 1024 ** 3)
    max_project_bytes: int = Field(default=8 * 1024 ** 3, ge=1024, le=256 * 1024 ** 3)
    max_tool_output_chars: int = Field(default=20_000, ge=1000, le=200_000)
    enabled_tools: list[str] = Field(
        default_factory=lambda: ["run_cmd", "read_file", "write_file", "list_dir"]
    )


class AppConfig(BaseModel):
    config_version: int = CONFIG_SCHEMA_VERSION
    llm: LLMSettings = Field(default_factory=LLMSettings)
    reverse: ReverseSettings = Field(default_factory=ReverseSettings)
    cases_dir: str = str(DEFAULT_CASES_DIR)
    yara_rules_dir: str = ""


def ensure_dirs() -> None:
    DEFAULT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    DEFAULT_CASES_DIR.mkdir(parents=True, exist_ok=True)


def load_config() -> AppConfig:
    ensure_dirs()
    if CONFIG_FILE.exists():
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        previous_version = int(data.get("config_version", 1))
        cfg = AppConfig.model_validate(data)
        if previous_version < 2:
            for tool_id in ("write_python_tool", "run_python_tool"):
                if tool_id not in cfg.reverse.enabled_tools:
                    cfg.reverse.enabled_tools.append(tool_id)
            cfg.config_version = CONFIG_SCHEMA_VERSION
            save_config(cfg)
        if previous_version < 3:
            cfg.reverse.enabled_tools = ["run_cmd", "read_file", "write_file", "list_dir"]
            cfg.config_version = CONFIG_SCHEMA_VERSION
            save_config(cfg)
        if previous_version < 4:
            cfg.config_version = CONFIG_SCHEMA_VERSION
            save_config(cfg)
        return cfg
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


def get_reverse_dir() -> Path:
    path = DEFAULT_CONFIG_DIR / "reverse"
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_rules_dir() -> Path:
    path = DEFAULT_CONFIG_DIR / "rules"
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

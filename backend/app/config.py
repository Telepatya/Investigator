"""Application configuration and secure credential storage."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Literal

import keyring
from pydantic import BaseModel, Field

SERVICE_NAME = "investigator-dfir"
DEFAULT_CONFIG_DIR = Path.home() / ".investigator"
DEFAULT_CASES_DIR = DEFAULT_CONFIG_DIR / "cases"
CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.json"


ProviderType = Literal["ollama", "openai", "gemini", "anthropic"]


class LLMSettings(BaseModel):
    provider: ProviderType = "ollama"
    model: str = "llama3.2"
    ollama_base_url: str = "http://localhost:11434"
    temperature: float = 0.2
    max_tokens: int = 4096


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
        pass


def has_api_key(provider: ProviderType) -> bool:
    return bool(get_api_key(provider))


def get_cases_dir(config: AppConfig | None = None) -> Path:
    cfg = config or load_config()
    path = Path(cfg.cases_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def case_db_path(case_id: str, config: AppConfig | None = None) -> Path:
    return get_cases_dir(config) / case_id / "case.db"


def case_uploads_path(case_id: str, config: AppConfig | None = None) -> Path:
    path = get_cases_dir(config) / case_id / "uploads"
    path.mkdir(parents=True, exist_ok=True)
    return path

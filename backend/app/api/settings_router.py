"""Settings and LLM configuration endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.config import (
    delete_api_key,
    has_api_key,
    load_config,
    save_api_key,
    save_config,
)
from app.llm.base import list_models_for_provider, test_provider
from app.models.schemas import (
    LLMConfigResponse,
    LLMConfigUpdate,
    ModelInfo,
    ProviderTestResult,
)

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("/llm", response_model=LLMConfigResponse)
async def get_llm_config() -> LLMConfigResponse:
    cfg = load_config()
    models: list[ModelInfo] = []
    try:
        models = await list_models_for_provider(cfg.llm.provider, cfg)
    except Exception:
        models = []
    return LLMConfigResponse(
        provider=cfg.llm.provider,
        model=cfg.llm.model,
        ollama_base_url=cfg.llm.ollama_base_url,
        temperature=cfg.llm.temperature,
        max_tokens=cfg.llm.max_tokens,
        has_api_key=has_api_key(cfg.llm.provider),
        available_models=models,
    )


@router.put("/llm", response_model=LLMConfigResponse)
async def update_llm_config(update: LLMConfigUpdate) -> LLMConfigResponse:
    cfg = load_config()
    if update.provider is not None:
        cfg.llm.provider = update.provider
    if update.model is not None:
        cfg.llm.model = update.model
    if update.ollama_base_url is not None:
        cfg.llm.ollama_base_url = update.ollama_base_url
    if update.temperature is not None:
        cfg.llm.temperature = update.temperature
    if update.max_tokens is not None:
        cfg.llm.max_tokens = update.max_tokens
    save_config(cfg)

    if update.api_key is not None and update.api_key != "":
        save_api_key(cfg.llm.provider, update.api_key)

    models: list[ModelInfo] = []
    try:
        models = await list_models_for_provider(cfg.llm.provider, cfg)
    except Exception:
        models = []

    return LLMConfigResponse(
        provider=cfg.llm.provider,
        model=cfg.llm.model,
        ollama_base_url=cfg.llm.ollama_base_url,
        temperature=cfg.llm.temperature,
        max_tokens=cfg.llm.max_tokens,
        has_api_key=has_api_key(cfg.llm.provider),
        available_models=models,
    )


@router.get("/llm/models/{provider}", response_model=list[ModelInfo])
async def get_models(provider: str) -> list[ModelInfo]:
    if provider not in ("ollama", "openai", "gemini", "anthropic"):
        raise HTTPException(400, "Unknown provider")
    try:
        return await list_models_for_provider(provider)  # type: ignore[arg-type]
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/llm/test/{provider}", response_model=ProviderTestResult)
async def test_llm(provider: str) -> ProviderTestResult:
    if provider not in ("ollama", "openai", "gemini", "anthropic"):
        raise HTTPException(400, "Unknown provider")
    ok, msg, models = await test_provider(provider)  # type: ignore[arg-type]
    return ProviderTestResult(success=ok, message=msg, models=models)


@router.post("/llm/key/{provider}")
async def set_api_key(provider: str, body: dict) -> dict:
    if provider not in ("openai", "gemini", "anthropic"):
        raise HTTPException(400, "This provider does not use an API key")
    key = body.get("api_key", "")
    if not key:
        raise HTTPException(400, "api_key required")
    save_api_key(provider, key)  # type: ignore[arg-type]
    return {"ok": True}


@router.delete("/llm/key/{provider}")
async def remove_api_key(provider: str) -> dict:
    if provider not in ("openai", "gemini", "anthropic"):
        raise HTTPException(400, "This provider does not use an API key")
    delete_api_key(provider)  # type: ignore[arg-type]
    return {"ok": True}


@router.get("/general")
async def get_general_settings() -> dict:
    cfg = load_config()
    return {"cases_dir": cfg.cases_dir, "yara_rules_dir": cfg.yara_rules_dir}


@router.put("/general")
async def update_general_settings(body: dict) -> dict:
    cfg = load_config()
    if "yara_rules_dir" in body:
        cfg.yara_rules_dir = body["yara_rules_dir"] or ""
    save_config(cfg)
    return {"cases_dir": cfg.cases_dir, "yara_rules_dir": cfg.yara_rules_dir}

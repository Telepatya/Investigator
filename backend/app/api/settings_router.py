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
from app.llm.endpoints import ProviderEndpointError, validate_endpoint
from app.models.schemas import (
    APIKeyUpdate,
    GeneralSettingsUpdate,
    LLMConfigResponse,
    LLMConfigUpdate,
    ModelInfo,
    ProviderTestResult,
)
from app.reverse.schemas import ReverseSettingsUpdate
from app.reverse.tools import TOOL_DESCRIPTIONS

router = APIRouter(prefix="/api/settings", tags=["settings"])
LLM_PROVIDERS = ("ollama", "openai", "openrouter", "gemini", "anthropic")
API_KEY_PROVIDERS = ("openai", "openrouter", "gemini", "anthropic")


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
        openrouter_base_url=cfg.llm.openrouter_base_url,
        temperature=cfg.llm.temperature,
        max_tokens=cfg.llm.max_tokens,
        analysis_max_tool_calls=cfg.llm.analysis_max_tool_calls,
        chat_max_tool_calls=cfg.llm.chat_max_tool_calls,
        entity_max_tool_calls=cfg.llm.entity_max_tool_calls,
        has_api_key=has_api_key(cfg.llm.provider),
        available_models=models,
    )


@router.put("/llm", response_model=LLMConfigResponse)
async def update_llm_config(update: LLMConfigUpdate) -> LLMConfigResponse:
    cfg = load_config().model_copy(deep=True)
    try:
        for provider in ("ollama", "openrouter"):
            field = f"{provider}_base_url"
            value = getattr(update, field)
            # Enforce saved configuration too, before key/config mutations.
            validate_endpoint(provider, value if value is not None else getattr(cfg.llm, field))
    except ProviderEndpointError as exc:
        raise HTTPException(422, str(exc)) from exc
    if update.provider is not None:
        cfg.llm.provider = update.provider
    if update.model is not None:
        cfg.llm.model = update.model
    if update.ollama_base_url is not None:
        cfg.llm.ollama_base_url = update.ollama_base_url
    if update.openrouter_base_url is not None:
        cfg.llm.openrouter_base_url = update.openrouter_base_url
    if update.temperature is not None:
        cfg.llm.temperature = update.temperature
    if update.max_tokens is not None:
        cfg.llm.max_tokens = update.max_tokens
    if update.analysis_max_tool_calls is not None:
        cfg.llm.analysis_max_tool_calls = update.analysis_max_tool_calls
    if update.chat_max_tool_calls is not None:
        cfg.llm.chat_max_tool_calls = update.chat_max_tool_calls
    if update.entity_max_tool_calls is not None:
        cfg.llm.entity_max_tool_calls = update.entity_max_tool_calls
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
        openrouter_base_url=cfg.llm.openrouter_base_url,
        temperature=cfg.llm.temperature,
        max_tokens=cfg.llm.max_tokens,
        analysis_max_tool_calls=cfg.llm.analysis_max_tool_calls,
        chat_max_tool_calls=cfg.llm.chat_max_tool_calls,
        entity_max_tool_calls=cfg.llm.entity_max_tool_calls,
        has_api_key=has_api_key(cfg.llm.provider),
        available_models=models,
    )


@router.get("/llm/models/{provider}", response_model=list[ModelInfo])
async def get_models(provider: str) -> list[ModelInfo]:
    if provider not in LLM_PROVIDERS:
        raise HTTPException(400, "Unknown provider")
    try:
        return await list_models_for_provider(provider)  # type: ignore[arg-type]
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/llm/test/{provider}", response_model=ProviderTestResult)
async def test_llm(provider: str) -> ProviderTestResult:
    if provider not in LLM_PROVIDERS:
        raise HTTPException(400, "Unknown provider")
    ok, msg, models = await test_provider(provider)  # type: ignore[arg-type]
    return ProviderTestResult(success=ok, message=msg, models=models)


@router.post("/llm/key/{provider}")
async def set_api_key(provider: str, body: APIKeyUpdate) -> dict:
    if provider not in API_KEY_PROVIDERS:
        raise HTTPException(400, "This provider does not use an API key")
    key = body.api_key
    if not key:
        raise HTTPException(400, "api_key required")
    save_api_key(provider, key)  # type: ignore[arg-type]
    return {"ok": True}


@router.delete("/llm/key/{provider}")
async def remove_api_key(provider: str) -> dict:
    if provider not in API_KEY_PROVIDERS:
        raise HTTPException(400, "This provider does not use an API key")
    delete_api_key(provider)  # type: ignore[arg-type]
    return {"ok": True}


@router.get("/general")
async def get_general_settings() -> dict:
    cfg = load_config()
    return {"cases_dir": cfg.cases_dir, "yara_rules_dir": cfg.yara_rules_dir}


@router.put("/general")
async def update_general_settings(body: GeneralSettingsUpdate) -> dict:
    cfg = load_config()
    if "yara_rules_dir" in body.model_fields_set:
        cfg.yara_rules_dir = body.yara_rules_dir or ""
    save_config(cfg)
    return {"cases_dir": cfg.cases_dir, "yara_rules_dir": cfg.yara_rules_dir}


def _reverse_settings_response() -> dict:
    cfg = load_config()
    return {
        **cfg.reverse.model_dump(),
        "available_tools": [
            {"id": tool_id, "description": description}
            for tool_id, description in TOOL_DESCRIPTIONS.items()
        ],
    }


@router.get("/reverse")
async def get_reverse_settings() -> dict:
    return _reverse_settings_response()


@router.put("/reverse")
async def update_reverse_settings(body: ReverseSettingsUpdate) -> dict:
    cfg = load_config()
    changes = body.model_dump(exclude_unset=True)
    if "enabled_tools" in changes:
        unknown = sorted(set(changes["enabled_tools"] or []) - set(TOOL_DESCRIPTIONS))
        if unknown:
            raise HTTPException(400, f"Unknown Reverse tools: {', '.join(unknown)}")
        changes["enabled_tools"] = list(dict.fromkeys(changes["enabled_tools"] or []))
    for key, value in changes.items():
        setattr(cfg.reverse, key, value)
    save_config(cfg)
    return _reverse_settings_response()

"""One-operation JSON-array tool protocol for Reverse analysis."""

from __future__ import annotations

import json
import re
import shlex
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

from .command_policy import EXECUTABLE_PATHS, validate_tool_request


class StrictToolModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ToolRunCmd(StrictToolModel):
    tool: Literal["run_cmd"]
    cmd: list[str] = Field(min_length=1, max_length=64)
    timeout: int = Field(default=30, ge=1, le=300)
    cwd: str = Field(default="/workspace", max_length=1024)
    stdin_base64: str = Field(default="", max_length=1_400_000)


class ToolReadFile(StrictToolModel):
    tool: Literal["read_file"]
    path: str = Field(min_length=1, max_length=1024)
    max_bytes: int = Field(default=100_000, ge=1, le=10_000_000)


class ToolWriteFile(StrictToolModel):
    tool: Literal["write_file"]
    path: str = Field(min_length=1, max_length=1024)
    content_base64: str = Field(max_length=1_400_000)


class ToolListDir(StrictToolModel):
    tool: Literal["list_dir"]
    path: str = Field(default="/workspace", min_length=1, max_length=1024)


SemanticToolCall = Annotated[
    ToolRunCmd | ToolReadFile | ToolWriteFile | ToolListDir,
    Field(discriminator="tool"),
]
TOOL_ADAPTER = TypeAdapter(SemanticToolCall)

TOOL_DESCRIPTIONS: dict[str, str] = {
    "run_cmd": "Execute one allowlisted static-analysis command as an argv array.",
    "read_file": "Read bounded content from a file within /workspace.",
    "write_file": "Write base64 content below /workspace/output or /workspace/tools.",
    "list_dir": "List directory contents within /workspace.",
}


def tool_protocol(enabled_tools: list[str]) -> str:
    allowed = ", ".join(sorted(EXECUTABLE_PATHS))
    operations = ", ".join(tool for tool in TOOL_DESCRIPTIONS if tool in enabled_tools)
    return f"Enabled operations: {operations}. Allowed run_cmd executables: {allowed}."


def _extract_array(text: str) -> list[Any] | None:
    for match in re.finditer(r"```(?:json)?\s*(\[[\s\S]*?\])\s*```", text, re.I):
        try:
            value = json.loads(match.group(1))
            if isinstance(value, list):
                return value
        except json.JSONDecodeError:
            continue
    decoder = json.JSONDecoder()
    for index, character in enumerate(text):
        if character != "[":
            continue
        try:
            value, _end = decoder.raw_decode(text[index:])
            if isinstance(value, list):
                return value
        except json.JSONDecodeError:
            continue
    return None


_TOOL_ALIASES = {
    "run_command": "run_cmd",
    "execute_command": "run_cmd",
    "shell_command": "run_cmd",
}
# Argument each tool receives when the model uses the shorthand
# {"<tool_name>": <value>} shape instead of {"tool": ..., ...}.
_PRIMARY_ARGUMENT = {
    "run_cmd": "cmd",
    "read_file": "path",
    "write_file": "path",
    "list_dir": "path",
}


def _split_command(value: str) -> list[str] | str:
    try:
        return shlex.split(value)
    except ValueError:
        return value  # schema validation rejects it with a clear reason


def _normalize_request(raw: dict[str, Any]) -> dict[str, Any]:
    if "tool" not in raw and isinstance(raw.get("name"), str):
        raw["tool"] = raw.pop("name")
    if "tool" not in raw:
        # Shorthand shape: {"run_cmd": "strings /workspace/inputs/x"} or
        # {"read_file": {"path": ...}} with the tool name as the only key.
        for key, tool_id in ({t: t for t in _PRIMARY_ARGUMENT} | _TOOL_ALIASES).items():
            if key not in raw:
                continue
            value = raw.pop(key)
            raw["tool"] = tool_id
            if isinstance(value, dict):
                for item_key, item in value.items():
                    raw.setdefault(item_key, item)
            elif value is not None:
                raw.setdefault(_PRIMARY_ARGUMENT[tool_id], value)
            break
    raw["tool"] = _TOOL_ALIASES.get(raw.get("tool"), raw.get("tool"))
    if raw.get("tool") == "run_cmd" and "cmd" not in raw and "command" in raw:
        raw["cmd"] = raw.pop("command")
    if raw.get("tool") == "run_cmd":
        cmd = raw.get("cmd")
        # Accept a whole command line as one string; execution stays shell-free
        # and the argv still passes host and container policy validation.
        if isinstance(cmd, str):
            raw["cmd"] = _split_command(cmd)
        elif isinstance(cmd, list) and len(cmd) == 1 and isinstance(cmd[0], str) and " " in cmd[0]:
            raw["cmd"] = _split_command(cmd[0])
    if raw.get("tool") == "write_file" and "content_base64" not in raw and "content" in raw:
        raw["content_base64"] = raw.pop("content")
    return raw


def _parse_with_reason(text: str) -> tuple[SemanticToolCall | None, str | None]:
    values = _extract_array(text)
    if not values or not isinstance(values[0], dict):
        return None, None
    raw = _normalize_request(dict(values[0]))
    try:
        call = TOOL_ADAPTER.validate_python(raw)
    except ValidationError:
        return None, (
            "Tool request failed schema validation; use the documented key names "
            "and value types exactly."
        )
    allowed, reason = validate_tool_request(call.model_dump())
    if not allowed:
        return None, reason
    return call, None


def parse_tool_call(text: str) -> SemanticToolCall | None:
    """Parse the first operation from the original one-object JSON-array protocol."""
    return _parse_with_reason(text)[0]


def parse_tool_rejection(text: str) -> str | None:
    """Why an attempted tool call was refused (policy or schema), if one was attempted."""
    return _parse_with_reason(text)[1]

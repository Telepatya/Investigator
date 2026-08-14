"""Hardened Docker lifecycle and semantic tool execution."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
from dataclasses import dataclass
from threading import RLock
from typing import Any

from app.config import load_config

from .database import ReverseArtifact, get_reverse_session
from .store import contained_project_path, validate_project_id
from .tools import SemanticToolCall, TOOL_DESCRIPTIONS

logger = logging.getLogger(__name__)


def _bounded_tool_output(value: str, limit: int) -> tuple[str, bool]:
    if len(value) <= limit:
        return value, False
    marker = "\n\n--- output truncated; middle omitted ---\n\n"
    available = max(0, limit - len(marker))
    head = (available * 2) // 3
    tail = available - head
    return value[:head] + marker + (value[-tail:] if tail else ""), True


@dataclass
class ActiveSandbox:
    container_id: str
    project_id: str
    last_used: float
    image_digest: str


class SandboxUnavailable(RuntimeError):
    pass


class ReverseSandboxManager:
    def __init__(self) -> None:
        self._active: dict[str, ActiveSandbox] = {}
        self._lock = RLock()

    @staticmethod
    def _docker():
        try:
            import docker
        except ImportError as exc:
            raise SandboxUnavailable("Docker SDK is not installed") from exc
        try:
            client = docker.from_env()
            client.ping()
            return client
        except Exception as exc:
            raise SandboxUnavailable(f"Docker is unavailable: {exc}") from exc

    def health(self) -> dict[str, Any]:
        cfg = load_config().reverse
        try:
            client = self._docker()
            try:
                image = client.images.get(cfg.sandbox_image)
            except Exception:
                return {
                    "docker_available": True,
                    "image_available": False,
                    "image": cfg.sandbox_image,
                    "image_digest": None,
                    "message": "Build with: python run.py --build-reverse-sandbox",
                }
            return {
                "docker_available": True,
                "image_available": True,
                "image": cfg.sandbox_image,
                "image_digest": self._image_digest(image),
                "message": "Reverse sandbox ready",
            }
        except SandboxUnavailable as exc:
            return {
                "docker_available": False,
                "image_available": False,
                "image": cfg.sandbox_image,
                "image_digest": None,
                "message": str(exc),
            }

    @staticmethod
    def _image_digest(image) -> str:
        digests = image.attrs.get("RepoDigests") or []
        return str(digests[0] if digests else image.id)

    def ensure(self, project_id: str) -> ActiveSandbox:
        project_id = validate_project_id(project_id)
        with self._lock:
            current = self._active.get(project_id)
            if current:
                try:
                    container = self._docker().containers.get(current.container_id)
                    container.reload()
                    if container.status == "running":
                        current.last_used = time.monotonic()
                        return current
                except Exception:
                    self._active.pop(project_id, None)

            cfg = load_config().reverse
            client = self._docker()
            try:
                image = client.images.get(cfg.sandbox_image)
            except Exception as exc:
                raise SandboxUnavailable(
                    "Reverse sandbox image is missing; run python run.py --build-reverse-sandbox"
                ) from exc

            name = f"investigator-reverse-{project_id}"
            try:
                stale = client.containers.get(name)
                stale.remove(force=True, v=True)
            except Exception:
                pass

            # No host paths, credentials, daemon socket, or network are exposed.
            container = client.containers.create(
                cfg.sandbox_image,
                name=name,
                network_mode="none",
                read_only=True,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                mem_limit=f"{cfg.sandbox_memory_limit_mb}m",
                nano_cpus=int(cfg.sandbox_cpu_limit * 1_000_000_000),
                pids_limit=cfg.sandbox_pids_limit,
                tmpfs={
                    "/workspace": (
                        "rw,nosuid,nodev,noexec,uid=10001,gid=10001,mode=0700,"
                        f"size={cfg.sandbox_memory_limit_mb // 2}m"
                    ),
                    "/tmp": "rw,nosuid,nodev,noexec,uid=10001,gid=10001,mode=0700,size=64m",
                },
                environment={"HOME": "/tmp", "PATH": "/usr/local/bin:/usr/bin:/bin"},
                labels={"investigator.reverse": "true", "investigator.project": project_id},
            )
            try:
                container.start()
                for _attempt in range(100):
                    container.reload()
                    if container.status == "running":
                        break
                    if container.status in {"dead", "exited", "removing"}:
                        raise SandboxUnavailable("Reverse sandbox exited during startup")
                    time.sleep(0.05)
                else:
                    raise SandboxUnavailable("Reverse sandbox did not become ready")
                protocol = container.exec_run(
                    ["reverse-stage", "protocol-version"],
                    user="reverse",
                    workdir="/workspace",
                )
                protocol_output = protocol.output
                if isinstance(protocol_output, tuple):
                    protocol_output = protocol_output[0]
                protocol_version = (protocol_output or b"").decode(
                    "utf-8", errors="replace"
                ).strip()
                if protocol.exit_code != 0 or protocol_version != "2":
                    raise SandboxUnavailable(
                        "Reverse sandbox image is outdated or incompatible; "
                        "rebuild investigator-reverse:latest"
                    )
                prepared = container.exec_run(
                    [
                        "mkdir", "-p", "/workspace/inputs", "/workspace/context",
                        "/workspace/output", "/workspace/tools",
                    ],
                    user="reverse",
                    workdir="/workspace",
                )
                if prepared.exit_code != 0:
                    raise SandboxUnavailable("Reverse sandbox workspace could not be prepared")
                self._copy_inputs(container, project_id)
                sealed_inputs = container.exec_run(
                    ["chmod", "0500", "/workspace/inputs", "/workspace/context"],
                    user="reverse",
                    workdir="/workspace",
                )
                if sealed_inputs.exit_code != 0:
                    raise SandboxUnavailable("Reverse sandbox inputs could not be sealed")
            except Exception:
                container.remove(force=True, v=True)
                raise
            active = ActiveSandbox(
                container_id=container.id,
                project_id=project_id,
                last_used=time.monotonic(),
                image_digest=self._image_digest(image),
            )
            self._active[project_id] = active
            return active

    def _copy_inputs(self, container, project_id: str) -> None:
        with get_reverse_session() as db:
            artifacts = list(db.query(ReverseArtifact).filter(
                ReverseArtifact.project_id == project_id,
                ReverseArtifact.artifact_type.in_(("upload", "context")),
            ).order_by(ReverseArtifact.created_at, ReverseArtifact.id))
        for artifact in artifacts:
            namespace = "context" if artifact.artifact_type == "context" else "inputs"
            sandbox_name = artifact.name if namespace == "context" else artifact.id
            source = contained_project_path(project_id, artifact.relative_path, must_exist=True)
            digest = hashlib.sha256()
            offset = 0
            with source.open("rb") as input_file:
                while chunk := input_file.read(48 * 1024):
                    digest.update(chunk)
                    encoded = base64.urlsafe_b64encode(chunk).decode()
                    result = container.exec_run(
                        [
                            "reverse-stage", "write", namespace, sandbox_name,
                            str(offset), encoded,
                        ],
                        user="reverse",
                        workdir="/workspace",
                    )
                    if result.exit_code != 0:
                        raise SandboxUnavailable(f"Failed to stage artifact {artifact.id}")
                    offset += len(chunk)
            if offset != artifact.file_size or digest.hexdigest() != artifact.sha256:
                raise SandboxUnavailable(f"Stored artifact {artifact.id} failed host integrity checks")
            sealed = container.exec_run(
                [
                    "reverse-stage", "seal", namespace, sandbox_name,
                    str(artifact.file_size), artifact.sha256,
                ],
                user="reverse",
                workdir="/workspace",
            )
            if sealed.exit_code != 0:
                raise SandboxUnavailable(f"Failed to verify staged artifact {artifact.id}")

    def execute(self, project_id: str, call: SemanticToolCall) -> dict[str, Any]:
        cfg = load_config().reverse
        tool_id = call.tool
        if tool_id not in cfg.enabled_tools or tool_id not in TOOL_DESCRIPTIONS:
            return {"success": False, "error": f"Tool '{tool_id}' is not enabled"}
        active = self.ensure(project_id)
        container = self._docker().containers.get(active.container_id)
        request = base64.urlsafe_b64encode(
            json.dumps(call.model_dump(), separators=(",", ":")).encode()
        ).decode()
        result = container.exec_run(
            ["reverse-broker", request],
            user="reverse",
            workdir="/workspace",
            demux=True,
        )
        stdout_b, stderr_b = (
            result.output if isinstance(result.output, tuple) else (result.output, b"")
        )
        raw_stdout = (stdout_b or b"").decode("utf-8", errors="replace")
        raw_stderr = (stderr_b or b"").decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw_stdout)
        except json.JSONDecodeError:
            payload = {
                "success": False,
                "error": "Sandbox broker returned malformed output",
                "stdout": raw_stdout,
                "stderr": raw_stderr,
            }
        if not isinstance(payload, dict):
            payload = {"success": False, "error": "Sandbox broker returned a non-object"}
        limit = cfg.max_tool_output_chars
        stdout = str(payload.get("stdout") or "")
        stderr = str(payload.get("stderr") or raw_stderr)
        stdout_original = len(stdout)
        stderr_original = len(stderr)
        stdout, stdout_truncated = _bounded_tool_output(stdout, limit)
        stderr, stderr_truncated = _bounded_tool_output(stderr, limit)
        truncated = bool(payload.get("broker_truncated")) or stdout_truncated or stderr_truncated
        if "stdout" in payload:
            payload["stdout"] = stdout
        if "stderr" in payload or stderr:
            payload["stderr"] = stderr
        active.last_used = time.monotonic()
        payload.update({
            "success": bool(payload.get("success")),
            "output_truncated": truncated,
            "stdout_original_length": stdout_original,
            "stdout_returned_length": len(stdout),
            "stderr_original_length": stderr_original,
            "stderr_returned_length": len(stderr),
            "tool": tool_id,
        })
        if truncated:
            payload["output_note"] = "Output was truncated; use a more targeted command/read."
        return payload

    def tool_versions(self, project_id: str) -> dict[str, str]:
        active = self.ensure(project_id)
        container = self._docker().containers.get(active.container_id)
        result = container.exec_run(["reverse-broker", "--versions"], user="reverse")
        try:
            return json.loads(result.output.decode("utf-8", errors="replace"))
        except Exception:
            return {"broker": "unknown"}

    def stop(self, project_id: str) -> None:
        with self._lock:
            active = self._active.pop(project_id, None)
        if not active:
            return
        try:
            self._docker().containers.get(active.container_id).remove(force=True, v=True)
        except Exception:
            logger.warning("Could not destroy Reverse sandbox %s", active.container_id, exc_info=True)

    def cleanup_idle(self) -> list[str]:
        ttl = load_config().reverse.sandbox_idle_ttl_minutes * 60
        cutoff = time.monotonic() - ttl
        with self._lock:
            expired = [project_id for project_id, item in self._active.items() if item.last_used < cutoff]
        for project_id in expired:
            self.stop(project_id)
        return expired

    def shutdown(self) -> None:
        with self._lock:
            project_ids = list(self._active)
        for project_id in project_ids:
            self.stop(project_id)


sandbox_manager = ReverseSandboxManager()

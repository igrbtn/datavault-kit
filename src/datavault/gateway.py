"""Model gateway over local OpenAI-compatible runtimes (LM Studio, Ollama).

Only loopback endpoints are accepted: a misconfigured remote base_url would
ship case data off the machine, so it is refused at load time.
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import yaml

from .config import models_config_path


class GatewayError(RuntimeError):
    pass


# Ollama "cloud" models are served through the local daemon but run on ollama.com,
# so a loopback URL alone does not prove the data stays here.
_CLOUD_MODEL_RE = re.compile(r"(?i)(^|[-:])cloud($|[-:])")


def _is_cloud_model(model: str) -> bool:
    return bool(_CLOUD_MODEL_RE.search(model))


def _is_loopback(url: str) -> bool:
    host = urlparse(url).hostname or ""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass
class Target:
    provider: str
    model: str

    @classmethod
    def parse(cls, ref: str) -> Target:
        provider, sep, model = ref.partition(":")
        if not sep or not model:
            raise GatewayError(f"bad route entry: {ref!r} (want provider:model)")
        return cls(provider, model)

    def __str__(self) -> str:
        return f"{self.provider}:{self.model}"


@dataclass
class GatewayConfig:
    providers: dict[str, str]
    kinds: dict[str, str]
    routes: dict[str, list[Target]]
    embeddings: list[Target] = field(default_factory=list)
    temperature: float = 0.0
    seed: int = 42
    timeout_s: float = 300.0

    @classmethod
    def load(cls, path: Path | None = None) -> GatewayConfig:
        raw = yaml.safe_load((path or models_config_path()).read_text(encoding="utf-8"))
        providers = {name: p["base_url"].rstrip("/") for name, p in raw["providers"].items()}
        kinds = {name: p.get("kind", "openai") for name, p in raw["providers"].items()}
        for name, url in providers.items():
            if not _is_loopback(url):
                raise GatewayError(f"provider {name} is not loopback: {url}")
        routes = {task: [Target.parse(r) for r in refs] for task, refs in raw["routes"].items()}
        embeddings = [Target.parse(r) for r in raw.get("embeddings", [])]
        for t in [t for ts in routes.values() for t in ts] + embeddings:
            if t.provider not in providers:
                raise GatewayError(f"route {t} uses unknown provider")
            if _is_cloud_model(t.model):
                raise GatewayError(f"route {t} is a cloud model; data would leave the host")
        d = raw.get("defaults", {})
        return cls(providers, kinds, routes, embeddings,
                   float(d.get("temperature", 0)), int(d.get("seed", 42)),
                   float(d.get("timeout_s", 300)))


class ModelGateway:
    def __init__(self, config: GatewayConfig, client: httpx.Client | None = None):
        self.config = config
        self._client = client or httpx.Client(timeout=config.timeout_s)
        self._remote_cache: dict[str, set[str]] = {}

    def _url(self, provider: str, path: str) -> str:
        return f"{self.config.providers[provider]}/{path.lstrip('/')}"

    def _ollama_remote_models(self, provider: str) -> set[str]:
        """Models the Ollama daemon proxies to its cloud (marked by remote_host)."""
        native = self.config.providers[provider].removesuffix("/v1")
        r = self._client.get(f"{native}/api/tags", timeout=5)
        r.raise_for_status()
        return {m["name"] for m in r.json().get("models", [])
                if m.get("remote_host") or m.get("remote_model")}

    def _assert_local(self, t: Target) -> None:
        # a cloud model can be renamed with `ollama cp`, so names alone are not enough
        if self.config.kinds.get(t.provider) != "ollama":
            return
        if t.provider not in self._remote_cache:
            self._remote_cache[t.provider] = self._ollama_remote_models(t.provider)
        if t.model in self._remote_cache[t.provider]:
            raise GatewayError(f"{t} is served by Ollama cloud")

    def health(self) -> dict:
        """Which providers answer and which routed models they actually have."""
        available: dict[str, set[str] | None] = {}
        providers = []
        warnings = []
        for name in self.config.providers:
            try:
                r = self._client.get(self._url(name, "models"), timeout=5)
                r.raise_for_status()
                ids = {m["id"] for m in r.json().get("data", [])}
                remote = {i for i in ids if _is_cloud_model(i)}
                if self.config.kinds.get(name) == "ollama":
                    remote |= self._ollama_remote_models(name)
                if remote:
                    warnings.append(f"{name}: {len(remote)} cloud model(s) present; "
                                    "disable Ollama Cloud in settings")
                ids -= remote
                available[name] = ids
                providers.append({"name": name, "up": True, "models": len(ids),
                                  "cloud_models": len(remote)})
            except (httpx.HTTPError, ValueError, KeyError) as e:
                available[name] = None
                providers.append({"name": name, "up": False, "error": type(e).__name__})

        def status(t: Target) -> dict:
            ids = available.get(t.provider)
            return {"target": str(t), "available": bool(ids) and t.model in ids}

        return {
            "providers": providers,
            "routes": {task: [status(t) for t in ts] for task, ts in self.config.routes.items()},
            "embeddings": [status(t) for t in self.config.embeddings],
            "warnings": warnings,
        }

    def complete_json(self, task: str, messages: list[dict], schema: dict,
                      max_tokens: int = 2048) -> tuple[dict, Target]:
        """Structured completion on the task's route; falls through on error or bad JSON."""
        targets = self.config.routes.get(task)
        if not targets:
            raise GatewayError(f"no route for task {task!r}")
        errors = []
        for t in targets:
            body: dict[str, Any] = {
                "model": t.model,
                "messages": messages,
                "temperature": self.config.temperature,
                "seed": self.config.seed,
                "max_tokens": max_tokens,
                "stream": False,
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {"name": f"dv_{task}", "strict": True, "schema": schema},
                },
            }
            try:
                self._assert_local(t)
                r = self._client.post(self._url(t.provider, "chat/completions"), json=body)
                r.raise_for_status()
                msg = r.json()["choices"][0]["message"]
                # LM Studio + thinking models (qwen3.8) under a JSON grammar: the answer is
                # parsed as reasoning and content comes back empty
                content = msg.get("content") or msg.get("reasoning_content") or ""
                data = json.loads(content)
                if not isinstance(data, dict):
                    raise ValueError("top-level JSON is not an object")
                return data, t
            except (httpx.HTTPError, KeyError, IndexError, ValueError, GatewayError) as e:
                errors.append(f"{t}: {type(e).__name__}")
        raise GatewayError("all targets failed: " + "; ".join(errors))

    def embed(self, texts: list[str], only: str | None = None) -> tuple[list[list[float]], Target]:
        """only: "provider:model" - vectors of different models are not comparable, so a
        query must use the model the corpus was embedded with, without fallback."""
        errors = []
        targets = [t for t in self.config.embeddings if only is None or str(t) == only]
        if only is not None and not targets:
            targets = [Target.parse(only)]
        for t in targets:
            try:
                self._assert_local(t)
                r = self._client.post(self._url(t.provider, "embeddings"),
                                      json={"model": t.model, "input": texts})
                r.raise_for_status()
                rows = sorted(r.json()["data"], key=lambda d: d["index"])
                return [d["embedding"] for d in rows], t
            except (httpx.HTTPError, KeyError, ValueError, GatewayError) as e:
                errors.append(f"{t}: {type(e).__name__}")
        raise GatewayError("all embedding targets failed: " + "; ".join(errors))

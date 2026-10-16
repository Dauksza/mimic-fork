"""Small Ollama HTTP client. No cloud provider or API key is used."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


class OllamaError(RuntimeError):
    """Raised when Ollama is unavailable or returns an invalid response."""


class Ollama:
    def __init__(self, base_url: str | None = None, model: str | None = None, timeout: int = 600):
        host = (base_url or os.environ.get("OLLAMA_HOST") or "http://127.0.0.1:11434").strip().rstrip("/")
        self.base_url = host if host.startswith(("http://", "https://")) else "http://" + host
        self.model = model or os.environ.get("MIMIC_OLLAMA_MODEL") or "qwen2.5-coder:14b"
        self.timeout = timeout

    def _request(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.base_url + path, data=data,
            headers={"Content-Type": "application/json"} if data is not None else {},
            method="POST" if data is not None else "GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                result = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise OllamaError(f"Ollama HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise OllamaError(
                f"Cannot reach Ollama at {self.base_url}: {exc}. Start Ollama and verify OLLAMA_HOST."
            ) from exc
        if not isinstance(result, dict):
            raise OllamaError("Ollama returned an unexpected response.")
        return result

    def models(self) -> list[str]:
        result = self._request("/api/tags")
        return [m.get("name", "") for m in result.get("models", []) if m.get("name")]

    def model_info(self, model: str | None = None) -> dict[str, Any]:
        """Return Ollama model metadata, including capabilities where supported."""
        return self._request("/api/show", {"name": model or self.model, "verbose": False})

    def chat(self, messages: list[dict[str, Any]], *, format: str | dict | None = None,
             temperature: float = 0.15, num_ctx: int = 16384) -> str:
        options = {"temperature": temperature, "num_ctx": num_ctx}
        payload: dict[str, Any] = {
            "model": self.model, "messages": messages, "stream": False,
            "options": options,
        }
        if format is not None:
            payload["format"] = format
        result = self._request("/api/chat", payload)
        try:
            return result["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise OllamaError(f"Unexpected Ollama chat response: {result}") from exc

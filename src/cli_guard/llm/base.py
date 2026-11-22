"""Provider-agnostic LLM interfaces for structured triage and tool-using investigation."""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]


@dataclass(slots=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(slots=True)
class ChatMessage:
    role: str  # "system" | "user" | "assistant" | "tool"
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str | None = None
    name: str | None = None


@dataclass(slots=True)
class LLMResponse:
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    model: str = ""
    raw_usage: dict[str, Any] = field(default_factory=dict)


class LLMError(RuntimeError):
    """Raised when an LLM backend request fails or returns unparseable output."""


_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def extract_json_object(text: str) -> dict[str, Any]:
    """Parse a JSON object from raw model output, tolerating fenced code blocks."""
    stripped = text.strip()
    if not stripped:
        raise LLMError("Model returned empty response when JSON was expected.")
    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    fence_match = _FENCE_RE.search(stripped)
    if fence_match:
        try:
            parsed = json.loads(fence_match.group(1))
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    start = stripped.find("{")
    end = stripped.rfind("}")
    if start != -1 and end > start:
        try:
            parsed = json.loads(stripped[start : end + 1])
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError as exc:
            raise LLMError(f"Failed to parse JSON from model response: {exc}") from exc

    raise LLMError(f"Model response did not contain a valid JSON object: {stripped[:200]}")


class LLMProvider(ABC):
    """Abstract base class implemented by all pluggable model providers."""

    name: str = "base"

    @abstractmethod
    def chat(
        self,
        messages: list[ChatMessage],
        *,
        model: str,
        tools: list[ToolSpec] | None = None,
        json_mode: bool = False,
        max_tokens: int = 512,
        temperature: float = 0.0,
    ) -> LLMResponse:
        """Execute a single chat completion turn, optionally with tool calling or JSON mode."""

    def complete_json(
        self,
        messages: list[ChatMessage],
        *,
        model: str,
        max_tokens: int = 400,
        temperature: float = 0.0,
    ) -> dict[str, Any]:
        resp = self.chat(
            messages,
            model=model,
            tools=None,
            json_mode=True,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        return extract_json_object(resp.content)

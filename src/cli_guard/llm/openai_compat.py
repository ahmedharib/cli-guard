"""OpenAI-compatible Chat Completions adapter (Meta Model API, OpenAI, Ollama, vLLM, etc.)."""

from __future__ import annotations

import json
import uuid
from typing import Any

import httpx

from cli_guard.llm.base import ChatMessage, LLMError, LLMProvider, LLMResponse, ToolCall, ToolSpec


class OpenAICompatProvider(LLMProvider):
    """Supports Meta Model API (https://api.meta.ai/v1), OpenAI, Ollama, vLLM, and OpenRouter."""

    def __init__(
        self,
        *,
        name: str,
        base_url: str,
        api_key: str | None = None,
        timeout: float = 45.0,
    ) -> None:
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _serialize_messages(self, messages: list[ChatMessage]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for msg in messages:
            if msg.role == "tool":
                out.append(
                    {
                        "role": "tool",
                        "tool_call_id": msg.tool_call_id or "call_0",
                        "content": msg.content,
                    }
                )
            elif msg.role == "assistant" and msg.tool_calls:
                out.append(
                    {
                        "role": "assistant",
                        "content": msg.content or None,
                        "tool_calls": [
                            {
                                "id": tc.id,
                                "type": "function",
                                "function": {
                                    "name": tc.name,
                                    "arguments": json.dumps(tc.arguments),
                                },
                            }
                            for tc in msg.tool_calls
                        ],
                    }
                )
            else:
                out.append({"role": msg.role, "content": msg.content})
        return out

    def _serialize_tools(self, tools: list[ToolSpec]) -> list[dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                },
            }
            for t in tools
        ]

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
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload: dict[str, Any] = {
            "model": model,
            "messages": self._serialize_messages(messages),
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = self._serialize_tools(tools)
            payload["tool_choice"] = "auto"
        elif json_mode:
            payload["response_format"] = {"type": "json_object"}

        url = f"{self.base_url}/chat/completions"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, headers=headers, json=payload)
                # Some OpenAI-compat backends reject response_format; retry once without it.
                if resp.status_code == 400 and json_mode and "response_format" in payload:
                    payload.pop("response_format", None)
                    resp = client.post(url, headers=headers, json=payload)
                # Reasoning models (e.g. Meta Muse Spark) count reasoning_tokens toward max_tokens;
                # if finish_reason=='length' with empty content & no tool calls, retry with higher cap.
                if resp.status_code == 200:
                    probe = resp.json()
                    ch0 = (probe.get("choices") or [{}])[0]
                    msg0 = ch0.get("message") or {}
                    if (
                        ch0.get("finish_reason") == "length"
                        and not (msg0.get("content") or "")
                        and not (msg0.get("tool_calls") or [])
                    ):
                        payload["max_tokens"] = max(max_tokens * 2, 4096)
                        resp = client.post(url, headers=headers, json=payload)
        except httpx.HTTPError as exc:
            raise LLMError(f"[{self.name}] HTTP error calling {url}: {exc}") from exc

        if resp.status_code >= 400:
            raise LLMError(
                f"[{self.name}] API error {resp.status_code} from {url}: {resp.text[:400]}"
            )

        data = resp.json()
        choices = data.get("choices") or []
        if not choices:
            raise LLMError(f"[{self.name}] Empty choices in response: {data}")

        message = choices[0].get("message") or {}
        content = message.get("content") or ""
        if isinstance(content, list):
            content = "".join(
                part.get("text", "") for part in content if isinstance(part, dict)
            )

        parsed_calls: list[ToolCall] = []
        for raw_tc in message.get("tool_calls") or []:
            fn = raw_tc.get("function") or {}
            raw_args = fn.get("arguments", "{}")
            if isinstance(raw_args, str):
                try:
                    args = json.loads(raw_args) if raw_args.strip() else {}
                except json.JSONDecodeError:
                    args = {}
            elif isinstance(raw_args, dict):
                args = raw_args
            else:
                args = {}
            parsed_calls.append(
                ToolCall(
                    id=str(raw_tc.get("id") or f"call_{uuid.uuid4().hex[:8]}"),
                    name=str(fn.get("name", "")),
                    arguments=args if isinstance(args, dict) else {},
                )
            )

        return LLMResponse(
            content=str(content),
            tool_calls=parsed_calls,
            model=str(data.get("model") or model),
            raw_usage=data.get("usage") or {},
        )

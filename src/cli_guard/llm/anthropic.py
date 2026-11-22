"""Native Anthropic Messages API adapter."""

from __future__ import annotations

import uuid
from typing import Any

import httpx

from cli_guard.llm.base import ChatMessage, LLMError, LLMProvider, LLMResponse, ToolCall, ToolSpec


class AnthropicProvider(LLMProvider):
    """Calls Anthropic `/v1/messages` directly via httpx."""

    name = "anthropic"

    def __init__(
        self,
        *,
        base_url: str = "https://api.anthropic.com/v1",
        api_key: str | None = None,
        timeout: float = 45.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

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
        if not self.api_key:
            raise LLMError("[anthropic] ANTHROPIC_API_KEY is required.")

        system_parts: list[str] = []
        serialized: list[dict[str, Any]] = []
        for msg in messages:
            if msg.role == "system":
                system_parts.append(msg.content)
            elif msg.role == "tool":
                serialized.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": msg.tool_call_id or "call_0",
                                "content": msg.content,
                            }
                        ],
                    }
                )
            elif msg.role == "assistant" and msg.tool_calls:
                blocks: list[dict[str, Any]] = []
                if msg.content:
                    blocks.append({"type": "text", "text": msg.content})
                for tc in msg.tool_calls:
                    blocks.append(
                        {
                            "type": "tool_use",
                            "id": tc.id,
                            "name": tc.name,
                            "input": tc.arguments,
                        }
                    )
                serialized.append({"role": "assistant", "content": blocks})
            else:
                serialized.append({"role": msg.role, "content": msg.content})

        payload: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": serialized,
        }
        if system_parts:
            sys_text = "\n\n".join(system_parts)
            if json_mode:
                sys_text += "\nRespond ONLY with a valid JSON object and no surrounding prose."
            payload["system"] = sys_text
        if tools:
            payload["tools"] = [
                {
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.parameters,
                }
                for t in tools
            ]

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        url = f"{self.base_url}/messages"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, headers=headers, json=payload)
        except httpx.HTTPError as exc:
            raise LLMError(f"[anthropic] HTTP error calling {url}: {exc}") from exc

        if resp.status_code >= 400:
            raise LLMError(f"[anthropic] API error {resp.status_code}: {resp.text[:400]}")

        data = resp.json()
        text_chunks: list[str] = []
        tool_calls: list[ToolCall] = []
        for block in data.get("content") or []:
            if not isinstance(block, dict):
                continue
            btype = block.get("type")
            if btype == "text":
                text_chunks.append(str(block.get("text", "")))
            elif btype == "tool_use":
                tool_calls.append(
                    ToolCall(
                        id=str(block.get("id") or f"call_{uuid.uuid4().hex[:8]}"),
                        name=str(block.get("name", "")),
                        arguments=block.get("input") or {},
                    )
                )

        return LLMResponse(
            content="\n".join(text_chunks).strip(),
            tool_calls=tool_calls,
            model=str(data.get("model") or model),
            raw_usage=data.get("usage") or {},
        )

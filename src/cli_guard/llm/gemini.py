"""Native Google Gemini GenerateContent API adapter."""

from __future__ import annotations

import uuid
from typing import Any

import httpx

from cli_guard.llm.base import ChatMessage, LLMError, LLMProvider, LLMResponse, ToolCall, ToolSpec


class GeminiProvider(LLMProvider):
    """Calls Gemini `/v1beta/models/{model}:generateContent` via httpx."""

    name = "gemini"

    def __init__(
        self,
        *,
        base_url: str = "https://generativelanguage.googleapis.com/v1beta",
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
            raise LLMError("[gemini] GEMINI_API_KEY is required.")

        system_parts: list[str] = []
        contents: list[dict[str, Any]] = []
        for msg in messages:
            if msg.role == "system":
                system_parts.append(msg.content)
            elif msg.role == "tool":
                contents.append(
                    {
                        "role": "user",
                        "parts": [
                            {
                                "functionResponse": {
                                    "name": msg.name or "tool",
                                    "response": {"result": msg.content},
                                }
                            }
                        ],
                    }
                )
            elif msg.role == "assistant" and msg.tool_calls:
                parts: list[dict[str, Any]] = []
                if msg.content:
                    parts.append({"text": msg.content})
                for tc in msg.tool_calls:
                    parts.append(
                        {"functionCall": {"name": tc.name, "args": tc.arguments}}
                    )
                contents.append({"role": "model", "parts": parts})
            else:
                role = "model" if msg.role == "assistant" else "user"
                contents.append({"role": role, "parts": [{"text": msg.content}]})

        gen_config: dict[str, Any] = {
            "temperature": temperature,
            "maxOutputTokens": max_tokens,
        }
        if json_mode and not tools:
            gen_config["responseMimeType"] = "application/json"

        payload: dict[str, Any] = {
            "contents": contents,
            "generationConfig": gen_config,
        }
        if system_parts:
            payload["systemInstruction"] = {
                "parts": [{"text": "\n\n".join(system_parts)}]
            }
        if tools:
            payload["tools"] = [
                {
                    "functionDeclarations": [
                        {
                            "name": t.name,
                            "description": t.description,
                            "parameters": t.parameters,
                        }
                        for t in tools
                    ]
                }
            ]

        url = f"{self.base_url}/models/{model}:generateContent"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(
                    url,
                    params={"key": self.api_key},
                    json=payload,
                )
        except httpx.HTTPError as exc:
            raise LLMError(f"[gemini] HTTP error calling {url}: {exc}") from exc

        if resp.status_code >= 400:
            raise LLMError(f"[gemini] API error {resp.status_code}: {resp.text[:400]}")

        data = resp.json()
        candidates = data.get("candidates") or []
        if not candidates:
            raise LLMError(f"[gemini] No candidates returned: {data}")

        parts = (candidates[0].get("content") or {}).get("parts") or []
        text_chunks: list[str] = []
        tool_calls: list[ToolCall] = []
        for part in parts:
            if "text" in part:
                text_chunks.append(str(part["text"]))
            elif "functionCall" in part:
                fc = part["functionCall"]
                tool_calls.append(
                    ToolCall(
                        id=f"call_{uuid.uuid4().hex[:8]}",
                        name=str(fc.get("name", "")),
                        arguments=fc.get("args") or {},
                    )
                )

        return LLMResponse(
            content="\n".join(text_chunks).strip(),
            tool_calls=tool_calls,
            model=model,
            raw_usage=data.get("usageMetadata") or {},
        )

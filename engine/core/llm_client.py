"""LLM client — unified async interface for Claude and GPT-4o with retries."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, AsyncIterator

import anthropic
import openai

from engine.core.config import get_settings


class LLMClient:
    """Unified async client for LLM-powered smart contract analysis.

    Features:
    - Primary (Claude) + fallback (GPT-4o) with automatic failover
    - Exponential backoff retries on rate limits / transient errors
    - Streaming support for long analysis
    - Fast model tier for quick classification tasks
    - Token usage tracking
    """

    def __init__(self) -> None:
        settings = get_settings()
        self._anthropic = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
        self._openai = openai.AsyncOpenAI(api_key=settings.openai_api_key)
        self._primary_model = settings.primary_llm_model
        self._fallback_model = settings.fallback_llm_model
        self._fast_model = settings.llm_fast_model
        self._max_retries = settings.llm_max_retries
        self._retry_base_delay = settings.llm_retry_base_delay
        self._total_input_tokens = 0
        self._total_output_tokens = 0

    @property
    def token_usage(self) -> dict[str, int]:
        return {
            "input_tokens": self._total_input_tokens,
            "output_tokens": self._total_output_tokens,
        }

    async def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: dict[str, Any] | None = None,
        temperature: float = 0.1,
        max_tokens: int = 8192,
        fast: bool = False,
    ) -> dict[str, Any]:
        """Send analysis prompt to LLM and return structured response.

        Tries primary (Claude) first, falls back to GPT-4o on failure.
        Each call is retried with exponential backoff on transient errors.

        Args:
            system_prompt: System instructions
            user_prompt: User/analysis prompt
            response_format: OpenAI response format (ignored for Claude)
            temperature: Sampling temperature
            max_tokens: Max output tokens
            fast: Use fast model tier for quick classification
        """
        model = self._fast_model if fast else self._primary_model
        try:
            return await self._retry(
                self._call_claude, model, system_prompt, user_prompt,
                temperature, max_tokens,
            )
        except Exception as e:
            print(f"Claude API failed after retries: {e}, falling back to GPT-4o")
            return await self._retry(
                self._call_openai, self._fallback_model, system_prompt,
                user_prompt, response_format, temperature, max_tokens,
            )

    async def analyze_batch(
        self,
        prompts: list[tuple[str, str]],
        temperature: float = 0.1,
        max_tokens: int = 4096,
        max_concurrent: int = 5,
        fast: bool = False,
    ) -> list[dict[str, Any]]:
        """Run multiple analyses concurrently with rate limiting.

        Args:
            prompts: List of (system_prompt, user_prompt) tuples
            temperature: Sampling temperature
            max_tokens: Max output tokens per call
            max_concurrent: Max concurrent API calls
            fast: Use fast model tier

        Returns:
            List of parsed responses (same order as prompts)
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def _analyze_one(sys_p: str, usr_p: str) -> dict[str, Any]:
            async with semaphore:
                return await self.analyze(
                    sys_p, usr_p, temperature=temperature,
                    max_tokens=max_tokens, fast=fast,
                )

        tasks = [_analyze_one(s, u) for s, u in prompts]
        return await asyncio.gather(*tasks, return_exceptions=False)

    async def stream_analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 8192,
    ) -> AsyncIterator[str]:
        """Stream analysis response from Claude, yielding chunks."""
        async with self._anthropic.messages.stream(
            model=self._primary_model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        ) as stream:
            async for text in stream.text_stream:
                yield text

    async def _retry(self, fn, *args, **kwargs) -> dict[str, Any]:
        """Retry a function with exponential backoff."""
        last_error = None
        for attempt in range(self._max_retries):
            try:
                return await fn(*args, **kwargs)
            except (
                anthropic.RateLimitError,
                anthropic.APIConnectionError,
                anthropic.InternalServerError,
                openai.RateLimitError,
                openai.APIConnectionError,
                openai.InternalServerError,
            ) as e:
                last_error = e
                delay = self._retry_base_delay * (2 ** attempt)
                print(f"  Retry {attempt + 1}/{self._max_retries} after {delay:.1f}s: {e}")
                await asyncio.sleep(delay)
            except Exception as e:
                raise
        raise last_error  # type: ignore[misc]

    async def _call_claude(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float,
        max_tokens: int,
    ) -> dict[str, Any]:
        """Call Claude API (async)."""
        message = await self._anthropic.messages.create(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        self._total_input_tokens += message.usage.input_tokens
        self._total_output_tokens += message.usage.output_tokens
        content = message.content[0].text
        return self._parse_json_response(content)

    async def _call_openai(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        response_format: dict[str, Any] | None,
        temperature: float,
        max_tokens: int,
    ) -> dict[str, Any]:
        """Call OpenAI API (async)."""
        kwargs: dict[str, Any] = {
            "model": model,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        if response_format:
            kwargs["response_format"] = response_format

        response = await self._openai.chat.completions.create(**kwargs)
        usage = response.usage
        if usage:
            self._total_input_tokens += usage.prompt_tokens
            self._total_output_tokens += usage.completion_tokens
        content = response.choices[0].message.content or "{}"
        return self._parse_json_response(content)

    def _parse_json_response(self, content: str) -> dict[str, Any]:
        """Extract JSON from LLM response, handling markdown code blocks."""
        content = content.strip()

        # Handle ```json ... ``` blocks
        if content.startswith("```"):
            lines = content.split("\n")
            json_lines: list[str] = []
            in_block = False
            for line in lines:
                if line.startswith("```") and not in_block:
                    in_block = True
                    continue
                elif line.startswith("```") and in_block:
                    break
                elif in_block:
                    json_lines.append(line)
            content = "\n".join(json_lines)

        try:
            return json.loads(content)
        except json.JSONDecodeError:
            # Try to find JSON object in text
            start = content.find("{")
            end = content.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(content[start:end])
                except json.JSONDecodeError:
                    pass
            # Try JSON array
            start = content.find("[")
            end = content.rfind("]") + 1
            if start >= 0 and end > start:
                try:
                    parsed = json.loads(content[start:end])
                    return {"items": parsed}
                except json.JSONDecodeError:
                    pass
            return {"raw_response": content, "parse_error": True}

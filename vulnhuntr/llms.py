import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import anthropic
import dotenv
import openai
import requests
from pydantic import BaseModel, ValidationError

dotenv.load_dotenv()

log = logging.getLogger(__name__)


# =============================================================================
# Token Usage Tracking
# =============================================================================


@dataclass
class LLMUsage:
    """Token usage from an LLM API call."""

    input_tokens: int
    output_tokens: int
    model: str

    @property
    def total_tokens(self) -> int:
        """Total tokens for this call."""
        return self.input_tokens + self.output_tokens


# Type alias for cost tracking callback
CostCallback = Callable[[int, int, str, str | None, str], None]


class LLMError(Exception):
    """Base class for all LLM-related exceptions."""

    pass


class RateLimitError(LLMError):
    pass


class APIConnectionError(LLMError):
    pass


class APIStatusError(LLMError):
    def __init__(self, status_code: int, response: Any):
        self.status_code = status_code
        self.response = response
        super().__init__(f"Received non-200 status code: {status_code}")


# =============================================================================
# Base LLM Class
# =============================================================================


# Base LLM class to handle common functionality
class LLM:
    def __init__(
        self,
        system_prompt: str = "",
        cost_callback: CostCallback | None = None,
    ) -> None:
        """Initialize LLM.

        Args:
            system_prompt: System prompt to use for all requests
            cost_callback: Optional callback for cost tracking.
                           Called with (input_tokens, output_tokens, model, file_path, call_type)
        """
        self.system_prompt = system_prompt
        self.history: list[dict[str, str]] = []
        self.prev_prompt: str | None = None
        self.prev_response: str | None = None
        self.prefill: str | None = None
        self.model: str = ""
        self._cost_callback = cost_callback
        self._current_file: str | None = None
        self._current_call_type: str = "analysis"
        self._last_usage: LLMUsage | None = None

    def set_context(self, file_path: str | None = None, call_type: str = "analysis") -> None:
        """Set context for cost tracking.

        Args:
            file_path: Path to file being analyzed
            call_type: Type of call ('readme', 'initial', 'secondary')
        """
        self._current_file = file_path
        self._current_call_type = call_type

    @property
    def last_usage(self) -> LLMUsage | None:
        """Get token usage from the last API call."""
        return self._last_usage

    def _validate_response(self, response_text: str, response_model: type[BaseModel]) -> BaseModel:
        try:
            # Early check for empty response
            if not response_text or not response_text.strip():
                raise LLMError("LLM returned empty response")

            if self.prefill:
                response_text = self.prefill + response_text

            # Strip markdown code blocks if present (e.g., ```json ... ```)
            match = re.search(r"\{.*\}", response_text, re.DOTALL)
            if match:
                response_text = match.group(0)

            # Fix common JSON issues from LLM responses
            # 1. Fix invalid escape sequences (e.g., \' from SQL/code snippets)
            #    Valid JSON escapes: \" \\ \/ \b \f \n \r \t \uXXXX
            #    Remove backslash from any other escape sequence
            response_text = re.sub(r'(?<!\\)\\(?!["\\/bfnrtu\\])', "", response_text)

            # 2. Replace Python None with JSON null
            response_text = re.sub(r"\b(None)\b", "null", response_text)

            # 3. Replace Python True/False with JSON true/false (if needed)
            response_text = re.sub(r"\b(True)\b", "true", response_text)
            response_text = re.sub(r"\b(False)\b", "false", response_text)

            return response_model.model_validate_json(response_text)
        except ValidationError as e:
            log.warning("[-] Response validation failed\n", exc_info=e)

            # Save failed response for debugging
            import os
            import tempfile

            debug_file = os.path.join(
                tempfile.gettempdir(),
                f"vulnhuntr_failed_response_{int(time.time())}.json",
            )
            try:
                with open(debug_file, "w") as f:
                    f.write(response_text)
                log.error(f"Failed response saved to: {debug_file}")
            except OSError as debug_err:
                # Don't let debug logging break the error flow
                log.debug(f"Failed to save debug file: {debug_err}")

            # Try to provide helpful error message
            error_msg = str(e)
            if "invalid escape" in error_msg.lower():
                log.error("JSON contains invalid escape sequences (likely from code snippets)")
                log.error("This is a known issue when LLMs include code with backslashes")
                log.error("Try re-running the analysis - LLM responses can vary")
            elif "None" in response_text or "True" in response_text or "False" in response_text:
                log.error("JSON contains Python syntax (None/True/False instead of null/true/false)")
                log.error("Applied automatic fixes but still failed - check saved response")

            raise LLMError("Validation failed") from e

    def _add_to_history(self, role: str, content: str) -> None:
        self.history.append({"role": role, "content": content})

    def _handle_error(self, e: Exception, attempt: int) -> None:
        log.error(f"An error occurred on attempt {attempt}: {str(e)}", exc_info=e)
        raise e

    def _extract_usage(self, response: Any) -> LLMUsage:
        """Extract token usage from API response. Override in subclasses."""
        # Default implementation - subclasses should override
        return LLMUsage(input_tokens=0, output_tokens=0, model=self.model)

    def _log_response(self, response: Any) -> None:
        """Log response and track costs."""
        usage = self._extract_usage(response)
        self._last_usage = usage

        log.debug(
            "Received chat response",
            extra={
                "usage": {
                    "input_tokens": usage.input_tokens,
                    "output_tokens": usage.output_tokens,
                    "total_tokens": usage.total_tokens,
                    "model": usage.model,
                }
            },
        )

        # Call cost callback if set
        if self._cost_callback:
            self._cost_callback(
                usage.input_tokens,
                usage.output_tokens,
                usage.model,
                self._current_file,
                self._current_call_type,
            )

    def chat(
        self, user_prompt: str, response_model: type[BaseModel] | None = None, max_tokens: int = 4096
    ) -> BaseModel | str:
        self._add_to_history("user", user_prompt)
        messages = self.create_messages(user_prompt)
        response = self.send_message(messages, max_tokens, response_model)
        self._log_response(response)

        response_text = self.get_response(response)
        if response_model:
            response_text = self._validate_response(response_text, response_model)
        self._add_to_history("assistant", str(response_text))
        return response_text

    def create_messages(self, user_prompt: str) -> Any:
        """Create messages for the LLM API. Override in subclasses."""
        raise NotImplementedError

    def send_message(self, messages: Any, max_tokens: int, response_model: Any = None) -> Any:
        """Send messages to the LLM API. Override in subclasses."""
        raise NotImplementedError

    def get_response(self, response: Any) -> str:
        """Extract response text from API response. Override in subclasses."""
        raise NotImplementedError


# =============================================================================
# Claude (Anthropic)
# =============================================================================


class Claude(LLM):
    def __init__(
        self,
        model: str,
        base_url: str,
        system_prompt: str = "",
        cost_callback: CostCallback | None = None,
    ) -> None:
        super().__init__(system_prompt, cost_callback)
        import os

        api_key = os.getenv("ANTHROPIC_API_KEY")
        # Initialize client without base_url initially to avoid httpx issues
        if base_url and base_url != "https://api.anthropic.com":
            self.client = anthropic.Anthropic(api_key=api_key, max_retries=3, base_url=base_url)
        else:
            self.client = anthropic.Anthropic(api_key=api_key, max_retries=3)
        self.model = model

    def create_messages(self, user_prompt: str) -> list[dict[str, str]]:
        if "Provide a very concise summary of the README.md content" in user_prompt:
            messages = [{"role": "user", "content": user_prompt}]
        else:
            self.prefill = '{    "scratchpad": "1.'
            messages = [
                {"role": "user", "content": user_prompt},
                {"role": "assistant", "content": self.prefill},
            ]
        return messages

    def send_message(
        self, messages: list[dict[str, str]], max_tokens: int, response_model: BaseModel
    ) -> dict[str, Any]:
        try:
            # response_model is not used here, only in ChatGPT
            return self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=self.system_prompt,
                messages=messages,
            )
        except anthropic.APIConnectionError as e:
            raise APIConnectionError("Server could not be reached") from e
        except anthropic.RateLimitError as e:
            raise RateLimitError("Request was rate-limited") from e
        except anthropic.APIStatusError as e:
            raise APIStatusError(e.status_code, e.response) from e

    def get_response(self, response: Any) -> str:
        return response.content[0].text.replace("\n", "")

    def _extract_usage(self, response: Any) -> LLMUsage:
        """Extract token usage from Claude response."""
        return LLMUsage(
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            model=self.model,
        )


# =============================================================================
# ChatGPT (OpenAI)
# =============================================================================


class ChatGPT(LLM):
    def __init__(
        self,
        model: str,
        base_url: str,
        system_prompt: str = "",
        cost_callback: CostCallback | None = None,
    ) -> None:
        super().__init__(system_prompt, cost_callback)
        import os

        self.client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"), base_url=base_url)
        self.model = model

    def create_messages(self, user_prompt: str) -> list[dict[str, str]]:
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        return messages

    def send_message(
        self,
        messages: list[dict[str, str]],
        max_tokens: int,
        response_model=None,
        *,
        _max_retries: int = 3,
        _base_delay: float = 2.0,
    ) -> dict[str, Any]:
        params = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
        }

        # Add response format configuration if a model is provided
        if response_model:
            params["response_format"] = {"type": "json_object"}

        last_exc: Exception | None = None
        for attempt in range(_max_retries):
            try:
                return self.client.chat.completions.create(**params)  # type: ignore[call-overload]
            except openai.RateLimitError as e:
                last_exc = e
                delay = _base_delay * (2**attempt)
                log.warning(
                    "Rate-limited, retrying",
                    extra={"attempt": attempt + 1, "max_retries": _max_retries, "delay_s": delay, "model": self.model},
                )
                time.sleep(delay)
            except openai.APIConnectionError as e:
                raise APIConnectionError("The server could not be reached") from e
            except openai.APIStatusError as e:
                raise APIStatusError(e.status_code, e.response) from e
            except Exception as e:
                raise LLMError(f"An unexpected error occurred: {str(e)}") from e

        raise RateLimitError(
            f"Request was rate-limited after {_max_retries} retries; consider backing off"
        ) from last_exc

    def get_response(self, response: Any) -> str:
        return response.choices[0].message.content

    def _extract_usage(self, response: Any) -> LLMUsage:
        """Extract token usage from ChatGPT response."""
        return LLMUsage(
            input_tokens=response.usage.prompt_tokens,
            output_tokens=response.usage.completion_tokens,
            model=self.model,
        )


# =============================================================================
# OpenRouter (Multi-provider)
# =============================================================================


class OpenRouter(LLM):
    """OpenRouter client - access multiple LLM providers via single API.

    OpenRouter provides access to Claude, GPT, Llama, Mistral, and many other
    models through a unified OpenAI-compatible API. Includes free model tiers.

    Environment variables:
        OPENROUTER_API_KEY: Your OpenRouter API key
        OPENROUTER_MODEL: Model to use (default: qwen/qwen3-coder:free)
        OPENROUTER_BASE_URL: API base URL (default: https://openrouter.ai/api/v1)

    Example free models:
        - qwen/qwen3-coder:free
        - meta-llama/llama-3.3-70b-instruct:free
        - google/gemma-3-27b-it:free
        - deepseek/deepseek-r1-0528:free
    """

    def __init__(
        self,
        model: str,
        base_url: str,
        system_prompt: str = "",
        cost_callback: CostCallback | None = None,
    ) -> None:
        super().__init__(system_prompt, cost_callback)
        import os

        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            raise LLMError("OPENROUTER_API_KEY environment variable is required for OpenRouter")

        self.client = openai.OpenAI(
            api_key=api_key,
            base_url=base_url,
            default_headers={
                "HTTP-Referer": "https://github.com/protectai/vulnhuntr",
                "X-Title": "Vulnhuntr Security Scanner",
            },
        )
        self.model = model

    def create_messages(self, user_prompt: str) -> list[dict[str, str]]:
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        return messages

    def send_message(
        self,
        messages: list[dict[str, str]],
        max_tokens: int,
        response_model=None,
        *,
        _max_retries: int = 3,
        _base_delay: float = 2.0,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
        }

        # OpenRouter free models generally don't support json_object mode.
        # Only enable it for known-compatible paid models to avoid errors.
        # The validation pipeline handles raw text via regex extraction anyway.
        if response_model and ":free" not in self.model:
            model_lower = self.model.lower()
            supports_json = any(
                x in model_lower for x in ["gpt-4", "gpt-3.5", "claude", "mistral-large", "mistral-medium"]
            )
            if supports_json:
                params["response_format"] = {"type": "json_object"}

        last_exc: Exception | None = None
        for attempt in range(_max_retries):
            try:
                return self.client.chat.completions.create(**params)  # type: ignore[call-overload]
            except openai.RateLimitError as e:
                last_exc = e
                delay = _base_delay * (2**attempt)
                log.warning(
                    "OpenRouter rate-limited, retrying",
                    extra={
                        "attempt": attempt + 1,
                        "max_retries": _max_retries,
                        "delay_s": delay,
                        "model": self.model,
                    },
                )
                time.sleep(delay)
            except openai.APIConnectionError as e:
                raise APIConnectionError(f"OpenRouter server could not be reached: {e}") from e
            except openai.APIStatusError as e:
                # Provide more helpful error messages for common issues
                if e.status_code == 401:
                    raise LLMError("OpenRouter authentication failed. Check your OPENROUTER_API_KEY.") from e
                elif e.status_code == 402:
                    raise LLMError(
                        "OpenRouter credits exhausted. Add credits or use a free model (e.g., qwen/qwen3-coder:free)"
                    ) from e
                elif e.status_code == 404:
                    raise LLMError(
                        f"OpenRouter model not found: {self.model}. Check model name at https://openrouter.ai/models"
                    ) from e
                elif e.status_code == 400:
                    # Common when a model doesn't support a requested feature
                    raise LLMError(
                        f"OpenRouter bad request for model {self.model}: {e.message if hasattr(e, 'message') else e}"
                    ) from e
                raise APIStatusError(e.status_code, e.response) from e
            except Exception as e:
                raise LLMError(f"OpenRouter unexpected error: {str(e)}") from e

        raise RateLimitError(
            f"OpenRouter rate-limited after {_max_retries} retries; consider backing off"
        ) from last_exc

    def get_response(self, response: Any) -> str:
        return response.choices[0].message.content

    def _extract_usage(self, response: Any) -> LLMUsage:
        """Extract token usage from OpenRouter response."""
        return LLMUsage(
            input_tokens=response.usage.prompt_tokens,
            output_tokens=response.usage.completion_tokens,
            model=self.model,
        )


# =============================================================================
# Ollama (Local)
# =============================================================================


# =============================================================================
# Fallback LLM Wrapper
# =============================================================================


class FallbackLLM:
    """Wraps a primary LLM with up to 2 fallback LLMs for resilience.

    When the active LLM fails (timeout, rate-limit, API error), automatically
    switches to the next fallback. Conversation history is transferred to
    maintain analysis continuity.

    All attribute access is transparently delegated to the currently active LLM,
    so this class can be used as a drop-in replacement for any LLM instance.

    Example:
        >>> primary = Claude(model, base_url, system_prompt)
        >>> fallback1 = OpenRouter(model, base_url, system_prompt)
        >>> llm = FallbackLLM(primary, [fallback1])
        >>> llm.chat(prompt, response_model=Response)  # tries primary, then fallback1
    """

    def __init__(self, primary: LLM, fallbacks: list[LLM]) -> None:
        self._primary = primary
        self._fallbacks = fallbacks
        self._active: LLM = primary
        self._all_llms: list[LLM] = [primary] + fallbacks

    def __getattr__(self, name: str) -> Any:
        """Delegate attribute access to the active LLM."""
        # Avoid infinite recursion for our own attributes
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self._active, name)

    def set_context(self, file_path: str | None = None, call_type: str = "analysis") -> None:
        """Set context on all LLMs so fallbacks have correct context."""
        for llm in self._all_llms:
            llm.set_context(file_path, call_type)

    def chat(
        self, user_prompt: str, response_model: type[BaseModel] | None = None, max_tokens: int = 4096
    ) -> BaseModel | str:
        """Send chat request with automatic fallback on failure.

        Tries the active LLM first. On failure, syncs conversation history
        to the next fallback and retries. Raises if all LLMs fail.
        """
        active_idx = self._all_llms.index(self._active)

        for i in range(active_idx, len(self._all_llms)):
            llm = self._all_llms[i]
            try:
                # Sync history and system prompt from active to fallback
                if llm is not self._active:
                    llm.history = self._active.history.copy()
                    llm.system_prompt = self._active.system_prompt
                    llm.prev_prompt = self._active.prev_prompt
                    llm.prev_response = self._active.prev_response
                    log.warning(
                        f"Primary LLM failed, falling back to {llm.model}",
                        extra={"fallback_index": i, "model": llm.model},
                    )

                result = llm.chat(user_prompt, response_model, max_tokens)
                self._active = llm
                return result

            except (LLMError, Exception) as e:
                log.error(
                    f"LLM {llm.model} failed: {e}",
                    extra={"model": llm.model, "fallback_index": i},
                )
                if i == len(self._all_llms) - 1:
                    raise LLMError(
                        f"All LLMs failed (primary + {len(self._fallbacks)} fallbacks). Last error: {e}"
                    ) from e
                continue

        raise LLMError("All LLMs (primary + fallbacks) exhausted")


class Ollama(LLM):
    def __init__(
        self,
        model: str,
        base_url: str,
        system_prompt: str = "",
        cost_callback: CostCallback | None = None,
    ) -> None:
        super().__init__(system_prompt, cost_callback)
        self.api_url = base_url
        self.model = model

    def create_messages(self, user_prompt: str) -> str:
        return user_prompt

    def send_message(self, user_prompt: str, max_tokens: int, response_model: BaseModel) -> Any:
        payload = {
            "model": self.model,
            "prompt": user_prompt,
            "options": {
                "temperature": 1,
                "system": self.system_prompt,
            },
            "stream": False,
        }

        try:
            response = requests.post(self.api_url, json=payload, timeout=120)
            return response
        except requests.exceptions.RequestException as e:
            if hasattr(e, "response") and e.response is not None:
                if e.response.status_code == 429:
                    raise RateLimitError("Request was rate-limited") from e
                elif e.response.status_code >= 500:
                    raise APIConnectionError("Server could not be reached") from e
                else:
                    raise APIStatusError(e.response.status_code, e.response.json()) from e
            raise APIConnectionError(f"Request failed: {str(e)}") from e

    def get_response(self, response: Any) -> str:
        return response.json()["response"]

    def _extract_usage(self, response: Any) -> LLMUsage:
        """Extract token usage from Ollama response (local, no cost)."""
        # Ollama may include usage info in some versions
        data = response.json()
        return LLMUsage(
            input_tokens=data.get("prompt_eval_count", 0),
            output_tokens=data.get("eval_count", 0),
            model=self.model,
        )

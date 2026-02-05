import logging
import re
from dataclasses import dataclass
from typing import Callable, Dict, Any, List, Optional, Union

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
CostCallback = Callable[[int, int, str, Optional[str], str], None]

class LLMError(Exception):
    """Base class for all LLM-related exceptions."""
    pass

class RateLimitError(LLMError):
    pass

class APIConnectionError(LLMError):
    pass

class APIStatusError(LLMError):
    def __init__(self, status_code: int, response: Dict[str, Any]):
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
        cost_callback: Optional[CostCallback] = None,
    ) -> None:
        """Initialize LLM.
        
        Args:
            system_prompt: System prompt to use for all requests
            cost_callback: Optional callback for cost tracking.
                           Called with (input_tokens, output_tokens, model, file_path, call_type)
        """
        self.system_prompt = system_prompt
        self.history: List[Dict[str, str]] = []
        self.prev_prompt: Union[str, None] = None
        self.prev_response: Union[str, None] = None
        self.prefill: Optional[str] = None
        self.model: str = ""
        self._cost_callback = cost_callback
        self._current_file: Optional[str] = None
        self._current_call_type: str = "analysis"
        self._last_usage: Optional[LLMUsage] = None
    
    def set_context(self, file_path: Optional[str] = None, call_type: str = "analysis") -> None:
        """Set context for cost tracking.
        
        Args:
            file_path: Path to file being analyzed
            call_type: Type of call ('readme', 'initial', 'secondary')
        """
        self._current_file = file_path
        self._current_call_type = call_type
    
    @property
    def last_usage(self) -> Optional[LLMUsage]:
        """Get token usage from the last API call."""
        return self._last_usage

    def _validate_response(self, response_text: str, response_model: BaseModel) -> BaseModel:
        try:
            if self.prefill:
                response_text = self.prefill + response_text
            
            # Strip markdown code blocks if present (e.g., ```json ... ```)
            match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if match:
                response_text = match.group(0)
            
            return response_model.model_validate_json(response_text)
        except ValidationError as e:
            log.warning("[-] Response validation failed\n", exc_info=e)
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
            }
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

    def chat(self, user_prompt: str, response_model: BaseModel = None, max_tokens: int = 4096) -> Union[BaseModel, str]:
        self._add_to_history("user", user_prompt)
        messages = self.create_messages(user_prompt)
        response = self.send_message(messages, max_tokens, response_model)
        self._log_response(response)

        response_text = self.get_response(response)
        if response_model:
            response_text = self._validate_response(response_text, response_model)
        self._add_to_history("assistant", str(response_text))
        return response_text


# =============================================================================
# Claude (Anthropic)
# =============================================================================

class Claude(LLM):
    def __init__(
        self,
        model: str,
        base_url: str,
        system_prompt: str = "",
        cost_callback: Optional[CostCallback] = None,
    ) -> None:
        super().__init__(system_prompt, cost_callback)
        import os
        self.client = anthropic.Anthropic(api_key=api_key, max_retries=3, base_url=base_url)
        self.model = model

    def create_messages(self, user_prompt: str) -> List[Dict[str, str]]:
        if "Provide a very concise summary of the README.md content" in user_prompt:
            messages = [{"role": "user", "content": user_prompt}]
        else:
            self.prefill = "{    \"scratchpad\": \"1."
            messages = [{"role": "user", "content": user_prompt}, 
                        {"role": "assistant", "content": self.prefill}]
        return messages

    def send_message(self, messages: List[Dict[str, str]], max_tokens: int, response_model: BaseModel) -> Dict[str, Any]:
        try:
            # response_model is not used here, only in ChatGPT
            return self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=self.system_prompt,
                messages=messages
            )
        except anthropic.APIConnectionError as e:
            raise APIConnectionError("Server could not be reached") from e
        except anthropic.RateLimitError as e:
            raise RateLimitError("Request was rate-limited") from e
        except anthropic.APIStatusError as e:
            raise APIStatusError(e.status_code, e.response) from e

    def get_response(self, response: Any) -> str:
        return response.content[0].text.replace('\n', '')
    
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
        cost_callback: Optional[CostCallback] = None,
    ) -> None:
        super().__init__(system_prompt, cost_callback)
        import os
        self.client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"), base_url=base_url)
        self.model = model

    def create_messages(self, user_prompt: str) -> List[Dict[str, str]]:
        messages = [{"role": "system", "content": self.system_prompt}, 
                    {"role": "user", "content": user_prompt}]
        return messages

    def send_message(self, messages: List[Dict[str, str]], max_tokens: int, response_model=None) -> Dict[str, Any]:
        try:
            params = {
                "model": self.model,
                "messages": messages,
                "max_tokens": max_tokens,
            }

            # Add response format configuration if a model is provided
            if response_model:
                params["response_format"] = {
                    "type": "json_object"
                }

            return self.client.chat.completions.create(**params)
        except openai.APIConnectionError as e:
            raise APIConnectionError("The server could not be reached") from e
        except openai.RateLimitError as e:
            raise RateLimitError("Request was rate-limited; consider backing off") from e
        except openai.APIStatusError as e:
            raise APIStatusError(e.status_code, e.response) from e
        except Exception as e:
            raise LLMError(f"An unexpected error occurred: {str(e)}") from e

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
# Ollama (Local)
# =============================================================================

class Ollama(LLM):
    def __init__(
        self,
        model: str,
        base_url: str,
        system_prompt: str = "",
        cost_callback: Optional[CostCallback] = None,
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
            response = requests.post(self.api_url, json=payload)
            return response
        except requests.exceptions.RequestException as e:
            if hasattr(e, 'response') and e.response is not None:
                if e.response.status_code == 429:
                    raise RateLimitError("Request was rate-limited") from e
                elif e.response.status_code >= 500:
                    raise APIConnectionError("Server could not be reached") from e
                else:
                    raise APIStatusError(e.response.status_code, e.response.json()) from e
            raise APIConnectionError(f"Request failed: {str(e)}") from e

    def get_response(self, response: Any) -> str:
        return response.json()['response']

    def _extract_usage(self, response: Any) -> LLMUsage:
        """Extract token usage from Ollama response (local, no cost)."""
        # Ollama may include usage info in some versions
        data = response.json()
        return LLMUsage(
            input_tokens=data.get('prompt_eval_count', 0),
            output_tokens=data.get('eval_count', 0),
            model=self.model,
        )


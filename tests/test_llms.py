"""
Tests for vulnhuntr.LLMs
=========================

Covers the shared validation pipeline (_validate_response), per-provider
message construction, error wrapping, usage extraction, cost callback
plumbing, and the chat() orchestration method.  No real API calls are made.
"""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from pydantic import BaseModel, Field

from vulnhuntr.LLMs import (
    LLM,
    LLMError,
    LLMUsage,
    APIConnectionError,
    APIStatusError,
    RateLimitError,
    Claude,
    ChatGPT,
    Ollama,
)


# ---------------------------------------------------------------------------
# Tiny Pydantic model used exclusively in these tests
# ---------------------------------------------------------------------------

class _Stub(BaseModel):
    scratchpad: str = Field(min_length=1)
    value: int = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_llm(**kw):
    """Create a bare LLM instance (not a real provider)."""
    return LLM(**kw)


def _valid_json(**overrides) -> str:
    payload = {"scratchpad": "step 1", "value": 42}
    payload.update(overrides)
    return json.dumps(payload)


# ═══════════════════════════════════════════════════════════════════════════
# _validate_response
# ═══════════════════════════════════════════════════════════════════════════


class TestValidateResponseJSONExtraction:
    """The regex should strip markdown wrappers and grab the first JSON obj."""

    def test_clean_json(self):
        llm = _make_llm()
        result = llm._validate_response(_valid_json(), _Stub)
        assert result.scratchpad == "step 1"
        assert result.value == 42

    def test_markdown_wrapped(self):
        raw = '```json\n' + _valid_json() + '\n```'
        result = _make_llm()._validate_response(raw, _Stub)
        assert result.value == 42

    def test_leading_garbage(self):
        raw = "Here is the result:\n\n" + _valid_json()
        result = _make_llm()._validate_response(raw, _Stub)
        assert result.value == 42


class TestValidateResponsePrefill:
    """When *prefill* is set the LLM prepends it before extraction."""

    def test_prefill_prepended(self):
        llm = _make_llm()
        llm.prefill = '{"scratchpad": "'
        # The LLM "continues" from the prefill
        continuation = 'analysis done", "value": 99}'
        result = llm._validate_response(continuation, _Stub)
        assert result.scratchpad == "analysis done"
        assert result.value == 99


class TestValidateResponseEscapeFixes:
    """The pipeline should neutralise common LLM JSON mistakes."""

    def test_invalid_backslash_removed(self):
        """Stray backslashes like \\' should be stripped."""
        raw = r'{"scratchpad": "it\'s fine", "value": 1}'
        result = _make_llm()._validate_response(raw, _Stub)
        assert "it" in result.scratchpad

    def test_none_replaced_with_null(self):
        raw = '{"scratchpad": "ok", "value": 0, "extra": None}'
        # _Stub ignores 'extra', but the JSON must still parse
        result = _make_llm()._validate_response(raw, _Stub)
        assert result.value == 0

    def test_true_false_replaced(self):
        raw = '{"scratchpad": "ok", "value": 1, "flag": True, "other": False}'
        result = _make_llm()._validate_response(raw, _Stub)
        assert result.value == 1


class TestValidateResponseFailure:
    def test_raises_llm_error_on_bad_json(self):
        with pytest.raises(LLMError, match="Validation failed"):
            _make_llm()._validate_response("not json at all", _Stub)

    def test_raises_on_missing_required_field(self):
        raw = '{"value": 1}'  # missing 'scratchpad'
        with pytest.raises(LLMError):
            _make_llm()._validate_response(raw, _Stub)


# ═══════════════════════════════════════════════════════════════════════════
# LLMUsage dataclass
# ═══════════════════════════════════════════════════════════════════════════


class TestLLMUsage:
    def test_total_tokens(self):
        u = LLMUsage(input_tokens=100, output_tokens=50, model="m")
        assert u.total_tokens == 150

    def test_zero_tokens(self):
        u = LLMUsage(input_tokens=0, output_tokens=0, model="x")
        assert u.total_tokens == 0


# ═══════════════════════════════════════════════════════════════════════════
# Error hierarchy
# ═══════════════════════════════════════════════════════════════════════════


class TestErrors:
    def test_llm_error_is_base(self):
        assert issubclass(RateLimitError, LLMError)
        assert issubclass(APIConnectionError, LLMError)
        assert issubclass(APIStatusError, LLMError)

    def test_api_status_error_fields(self):
        err = APIStatusError(404, {"detail": "not found"})
        assert err.status_code == 404
        assert "404" in str(err)


# ═══════════════════════════════════════════════════════════════════════════
# LLM base class – chat() orchestration
# ═══════════════════════════════════════════════════════════════════════════


class TestLLMChatOrchestration:
    """Verify that chat() calls create_messages → send_message →
    _log_response → get_response → _validate_response in the right order
    and returns the validated model when response_model is given."""

    def _subclass(self, raw_response_text, response_obj=None):
        """Build a concrete LLM subclass that returns canned data."""

        class _Fake(LLM):
            def create_messages(self, user_prompt):
                return [{"role": "user", "content": user_prompt}]

            def send_message(self, messages, max_tokens, response_model):
                return response_obj or SimpleNamespace()

            def get_response(self, response):
                return raw_response_text

            def _extract_usage(self, response):
                return LLMUsage(input_tokens=10, output_tokens=5, model="fake")

        return _Fake()

    def test_returns_validated_model(self):
        fake = self._subclass(_valid_json())
        result = fake.chat("hi", response_model=_Stub, max_tokens=100)
        assert isinstance(result, _Stub)
        assert result.value == 42

    def test_returns_raw_string_without_model(self):
        fake = self._subclass("hello world")
        result = fake.chat("hi")
        assert result == "hello world"

    def test_history_updated(self):
        fake = self._subclass("text")
        fake.chat("prompt")
        assert len(fake.history) == 2
        assert fake.history[0]["role"] == "user"
        assert fake.history[1]["role"] == "assistant"


class TestCostCallback:
    def test_callback_invoked(self):
        calls = []

        def cb(inp, out, model, fp, ct):
            calls.append((inp, out, model, fp, ct))

        class _Fake(LLM):
            def create_messages(self, user_prompt):
                return []

            def send_message(self, messages, max_tokens, response_model):
                return SimpleNamespace()

            def get_response(self, response):
                return "ok"

            def _extract_usage(self, response):
                return LLMUsage(input_tokens=100, output_tokens=50, model="m")

        fake = _Fake(cost_callback=cb)
        fake.set_context(file_path="app.py", call_type="initial")
        fake.chat("go")

        assert len(calls) == 1
        assert calls[0] == (100, 50, "m", "app.py", "initial")


# ═══════════════════════════════════════════════════════════════════════════
# Claude
# ═══════════════════════════════════════════════════════════════════════════


class TestClaudeMessages:
    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    @patch("vulnhuntr.LLMs.anthropic.Anthropic")
    def test_readme_prompt_has_no_prefill(self, mock_cls):
        c = Claude(model="claude-test", base_url="https://api.anthropic.com")
        msgs = c.create_messages(
            "Provide a very concise summary of the README.md content below"
        )
        assert len(msgs) == 1
        assert msgs[0]["role"] == "user"

    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    @patch("vulnhuntr.LLMs.anthropic.Anthropic")
    def test_analysis_prompt_has_prefill(self, mock_cls):
        c = Claude(model="claude-test", base_url="https://api.anthropic.com")
        msgs = c.create_messages("Analyze this code for vulnerabilities")
        assert len(msgs) == 2
        assert msgs[1]["role"] == "assistant"
        assert c.prefill == '{    "scratchpad": "1.'

    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    @patch("vulnhuntr.LLMs.anthropic.Anthropic")
    def test_get_response_strips_newlines(self, mock_cls):
        c = Claude(model="m", base_url="https://api.anthropic.com")
        fake_resp = SimpleNamespace(
            content=[SimpleNamespace(text="line1\nline2\nline3")]
        )
        assert c.get_response(fake_resp) == "line1line2line3"


class TestClaudeErrors:
    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    @patch("vulnhuntr.LLMs.anthropic.Anthropic")
    def test_connection_error_wrapped(self, mock_cls):
        import anthropic as anth

        c = Claude(model="m", base_url="https://api.anthropic.com")
        c.client.messages.create.side_effect = anth.APIConnectionError(
            request=MagicMock()
        )
        with pytest.raises(APIConnectionError):
            c.send_message([], 100, None)

    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    @patch("vulnhuntr.LLMs.anthropic.Anthropic")
    def test_rate_limit_wrapped(self, mock_cls):
        import anthropic as anth

        c = Claude(model="m", base_url="https://api.anthropic.com")
        c.client.messages.create.side_effect = anth.RateLimitError(
            message="slow down",
            response=MagicMock(status_code=429),
            body=None,
        )
        with pytest.raises(RateLimitError):
            c.send_message([], 100, None)


class TestClaudeUsage:
    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    @patch("vulnhuntr.LLMs.anthropic.Anthropic")
    def test_extract_usage(self, mock_cls):
        c = Claude(model="claude-test", base_url="https://api.anthropic.com")
        resp = SimpleNamespace(
            usage=SimpleNamespace(input_tokens=200, output_tokens=80)
        )
        usage = c._extract_usage(resp)
        assert usage.input_tokens == 200
        assert usage.output_tokens == 80
        assert usage.model == "claude-test"


# ═══════════════════════════════════════════════════════════════════════════
# ChatGPT
# ═══════════════════════════════════════════════════════════════════════════


class TestChatGPTMessages:
    @patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"})
    @patch("vulnhuntr.LLMs.openai.OpenAI")
    def test_system_prompt_in_messages(self, mock_cls):
        g = ChatGPT(
            model="gpt-test", base_url="https://api.openai.com/v1",
            system_prompt="You are helpful.",
        )
        msgs = g.create_messages("analyze code")
        assert msgs[0]["role"] == "system"
        assert msgs[0]["content"] == "You are helpful."
        assert msgs[1]["role"] == "user"

    @patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"})
    @patch("vulnhuntr.LLMs.openai.OpenAI")
    def test_json_mode_when_response_model(self, mock_cls):
        g = ChatGPT(model="gpt-test", base_url="https://api.openai.com/v1")
        g.client.chat.completions.create = MagicMock(
            return_value=SimpleNamespace(
                choices=[SimpleNamespace(
                    message=SimpleNamespace(content='{"scratchpad":"x","value":1}')
                )],
                usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5),
            )
        )
        g.send_message([{"role": "user", "content": "x"}], 100, _Stub)
        call_kwargs = g.client.chat.completions.create.call_args[1]
        assert call_kwargs["response_format"] == {"type": "json_object"}

    @patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"})
    @patch("vulnhuntr.LLMs.openai.OpenAI")
    def test_no_json_mode_without_response_model(self, mock_cls):
        g = ChatGPT(model="gpt-test", base_url="https://api.openai.com/v1")
        g.client.chat.completions.create = MagicMock(
            return_value=SimpleNamespace(
                choices=[SimpleNamespace(
                    message=SimpleNamespace(content="just text")
                )],
                usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5),
            )
        )
        g.send_message([{"role": "user", "content": "x"}], 100, None)
        call_kwargs = g.client.chat.completions.create.call_args[1]
        assert "response_format" not in call_kwargs


class TestChatGPTErrors:
    @patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"})
    @patch("vulnhuntr.LLMs.openai.OpenAI")
    def test_connection_error_wrapped(self, mock_cls):
        import openai as oai

        g = ChatGPT(model="m", base_url="https://api.openai.com/v1")
        g.client.chat.completions.create.side_effect = oai.APIConnectionError(
            request=MagicMock()
        )
        with pytest.raises(APIConnectionError):
            g.send_message([], 100, None)


class TestChatGPTUsage:
    @patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"})
    @patch("vulnhuntr.LLMs.openai.OpenAI")
    def test_extract_usage(self, mock_cls):
        g = ChatGPT(model="gpt-test", base_url="https://api.openai.com/v1")
        resp = SimpleNamespace(
            usage=SimpleNamespace(prompt_tokens=300, completion_tokens=120)
        )
        usage = g._extract_usage(resp)
        assert usage.input_tokens == 300
        assert usage.output_tokens == 120


# ═══════════════════════════════════════════════════════════════════════════
# Ollama
# ═══════════════════════════════════════════════════════════════════════════


class TestOllamaMessages:
    def test_create_messages_returns_string(self):
        o = Ollama(model="llama3", base_url="http://localhost:11434/api/generate")
        result = o.create_messages("analyze this")
        assert result == "analyze this"

    def test_get_response_extracts_field(self):
        o = Ollama(model="llama3", base_url="http://localhost:11434/api/generate")
        fake_resp = MagicMock()
        fake_resp.json.return_value = {"response": "hello world"}
        assert o.get_response(fake_resp) == "hello world"


class TestOllamaUsage:
    def test_extract_usage_with_fields(self):
        o = Ollama(model="llama3", base_url="http://localhost:11434/api/generate")
        fake_resp = MagicMock()
        fake_resp.json.return_value = {
            "prompt_eval_count": 50,
            "eval_count": 25,
        }
        usage = o._extract_usage(fake_resp)
        assert usage.input_tokens == 50
        assert usage.output_tokens == 25

    def test_extract_usage_missing_fields(self):
        o = Ollama(model="llama3", base_url="http://localhost:11434/api/generate")
        fake_resp = MagicMock()
        fake_resp.json.return_value = {}
        usage = o._extract_usage(fake_resp)
        assert usage.input_tokens == 0
        assert usage.output_tokens == 0


class TestOllamaSendMessage:
    @patch("vulnhuntr.LLMs.requests.post")
    def test_sends_correct_payload(self, mock_post):
        mock_post.return_value = MagicMock(
            json=lambda: {"response": "ok"},
            status_code=200,
        )
        o = Ollama(
            model="llama3",
            base_url="http://localhost:11434/api/generate",
            system_prompt="be helpful",
        )
        o.send_message("test prompt", 1024, None)

        call_kwargs = mock_post.call_args
        payload = call_kwargs[1]["json"]
        assert payload["model"] == "llama3"
        assert payload["prompt"] == "test prompt"
        assert payload["stream"] is False
        assert payload["options"]["system"] == "be helpful"

    @patch("vulnhuntr.LLMs.requests.post")
    def test_request_exception_wrapped(self, mock_post):
        import requests as req

        mock_post.side_effect = req.exceptions.ConnectionError("refused")
        o = Ollama(model="m", base_url="http://localhost:11434/api/generate")
        with pytest.raises(APIConnectionError):
            o.send_message("x", 100, None)


# ═══════════════════════════════════════════════════════════════════════════
# set_context / last_usage
# ═══════════════════════════════════════════════════════════════════════════


class TestContextTracking:
    def test_set_context(self):
        llm = _make_llm()
        llm.set_context(file_path="api.py", call_type="secondary")
        assert llm._current_file == "api.py"
        assert llm._current_call_type == "secondary"

    def test_last_usage_none_initially(self):
        llm = _make_llm()
        assert llm.last_usage is None

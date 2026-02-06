"""
Tests for vulnhuntr.core.models
================================

Covers VulnType enum values, ContextCode validation, and the Response
Pydantic model including edge cases for optional fields, serialization
round-trips, and constraint enforcement.
"""

import pytest
from pydantic import ValidationError

from vulnhuntr.core.models import ContextCode, Response, VulnType


# ── VulnType enum ──────────────────────────────────────────────────────────


class TestVulnType:
    """Verify all vulnerability type identifiers are present and behave correctly."""

    EXPECTED_MEMBERS = {"LFI", "RCE", "SSRF", "AFO", "SQLI", "XSS", "IDOR"}

    def test_all_members_exist(self):
        actual = {v.value for v in VulnType}
        assert actual == self.EXPECTED_MEMBERS

    def test_member_count(self):
        assert len(VulnType) == 7

    def test_string_coercion(self):
        """VulnType inherits from str so it should compare directly."""
        assert VulnType.SQLI == "SQLI"
        assert VulnType.RCE == "RCE"

    def test_construction_from_value(self):
        assert VulnType("LFI") is VulnType.LFI

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            VulnType("NOT_A_VULN")


# ── ContextCode model ──────────────────────────────────────────────────────


class TestContextCode:
    """Validate the model used by the LLM to request additional code context."""

    def test_valid_construction(self):
        cc = ContextCode(
            name="db_query",
            reason="Need to check if parameterized",
            code_line="result = db_query(user_input)",
        )
        assert cc.name == "db_query"
        assert cc.reason == "Need to check if parameterized"

    def test_missing_required_field(self):
        with pytest.raises(ValidationError):
            ContextCode(name="func")  # missing reason and code_line

    def test_json_round_trip(self):
        original = ContextCode(
            name="validate",
            reason="Check sanitization",
            code_line="validate(data)",
        )
        dumped = original.model_dump_json()
        restored = ContextCode.model_validate_json(dumped)
        assert restored == original


# ── Response model ─────────────────────────────────────────────────────────


class TestResponse:
    """Validate the core LLM response model used throughout analysis."""

    def test_minimal_valid_response(self):
        r = Response(
            scratchpad="Analyzed code.",
            analysis="No issues found.",
            confidence_score=0,
            vulnerability_types=[],
            context_code=[],
        )
        assert r.poc is None
        assert r.confidence_score == 0

    def test_full_response(self):
        r = Response(
            scratchpad="Step 1: read. Step 2: trace.",
            analysis="SQL injection found.",
            poc="curl http://x/?q=' OR 1=1--",
            confidence_score=9,
            vulnerability_types=[VulnType.SQLI],
            context_code=[
                ContextCode(
                    name="run_query",
                    reason="Verify sink",
                    code_line="run_query(q)",
                )
            ],
        )
        assert r.confidence_score == 9
        assert len(r.vulnerability_types) == 1
        assert len(r.context_code) == 1

    def test_poc_is_optional(self):
        """poc can be None when the LLM hasn't confirmed the vuln yet."""
        r = Response(
            scratchpad="Investigating.",
            analysis="Needs more context.",
            poc=None,
            confidence_score=3,
            vulnerability_types=[VulnType.RCE],
            context_code=[],
        )
        assert r.poc is None

    def test_multiple_vuln_types(self):
        r = Response(
            scratchpad="Found both.",
            analysis="Two vulns confirmed.",
            confidence_score=8,
            vulnerability_types=[VulnType.SQLI, VulnType.XSS],
            context_code=[],
        )
        assert len(r.vulnerability_types) == 2

    def test_json_round_trip(self):
        original = Response(
            scratchpad="analysis",
            analysis="result",
            poc="exploit",
            confidence_score=7,
            vulnerability_types=[VulnType.SSRF],
            context_code=[],
        )
        dumped = original.model_dump_json()
        restored = Response.model_validate_json(dumped)
        assert restored == original

    def test_model_validate_from_dict(self):
        data = {
            "scratchpad": "s",
            "analysis": "a",
            "poc": None,
            "confidence_score": 5,
            "vulnerability_types": ["LFI"],
            "context_code": [],
        }
        r = Response.model_validate(data)
        assert r.vulnerability_types == [VulnType.LFI]

    def test_invalid_vuln_type_rejects(self):
        with pytest.raises(ValidationError):
            Response(
                scratchpad="s",
                analysis="a",
                confidence_score=1,
                vulnerability_types=["INVALID"],
                context_code=[],
            )

    def test_missing_scratchpad_rejects(self):
        with pytest.raises(ValidationError):
            Response(
                analysis="a",
                confidence_score=0,
                vulnerability_types=[],
                context_code=[],
            )

    def test_context_code_nested_validation(self):
        """Embedded ContextCode items must also pass validation."""
        with pytest.raises(ValidationError):
            Response(
                scratchpad="s",
                analysis="a",
                confidence_score=2,
                vulnerability_types=[],
                context_code=[{"name": "only_name"}],  # missing required fields
            )

    def test_json_schema_generation(self):
        """Confirm the model can produce a JSON schema (used in prompts)."""
        schema = Response.model_json_schema()
        assert "properties" in schema
        assert "scratchpad" in schema["properties"]

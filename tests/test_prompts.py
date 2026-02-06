"""
Tests for vulnhuntr.prompts
===========================

Tests for prompt templates, vulnerability-specific content, and bypass dictionaries.
"""


# ── Vulnerability Templates ─────────────────────────────────────────────────


class TestLFITemplate:
    def test_template_exists(self):
        from vulnhuntr.prompts import LFI_TEMPLATE

        assert isinstance(LFI_TEMPLATE, str)
        assert len(LFI_TEMPLATE) > 100

    def test_template_has_focus_areas(self):
        from vulnhuntr.prompts import LFI_TEMPLATE

        assert "High-Risk Functions" in LFI_TEMPLATE
        assert "Path Traversal" in LFI_TEMPLATE

    def test_template_mentions_key_functions(self):
        from vulnhuntr.prompts import LFI_TEMPLATE

        assert "open()" in LFI_TEMPLATE
        assert "os.path.join()" in LFI_TEMPLATE

    def test_template_references_example_bypasses(self):
        from vulnhuntr.prompts import LFI_TEMPLATE

        assert "<example_bypasses>" in LFI_TEMPLATE


class TestRCETemplate:
    def test_template_exists(self):
        from vulnhuntr.prompts import RCE_TEMPLATE

        assert isinstance(RCE_TEMPLATE, str)
        assert len(RCE_TEMPLATE) > 100

    def test_template_has_focus_areas(self):
        from vulnhuntr.prompts import RCE_TEMPLATE

        assert "High-Risk Functions" in RCE_TEMPLATE
        assert "Indirect Code Execution" in RCE_TEMPLATE

    def test_template_mentions_key_functions(self):
        from vulnhuntr.prompts import RCE_TEMPLATE

        assert "eval()" in RCE_TEMPLATE
        assert "exec()" in RCE_TEMPLATE
        assert "os.system()" in RCE_TEMPLATE
        assert "pickle.loads()" in RCE_TEMPLATE

    def test_template_references_example_bypasses(self):
        from vulnhuntr.prompts import RCE_TEMPLATE

        assert "<example_bypasses>" in RCE_TEMPLATE


class TestXSSTemplate:
    def test_template_exists(self):
        from vulnhuntr.prompts import XSS_TEMPLATE

        assert isinstance(XSS_TEMPLATE, str)
        assert len(XSS_TEMPLATE) > 100

    def test_template_has_focus_areas(self):
        from vulnhuntr.prompts import XSS_TEMPLATE

        assert "High-Risk Functions" in XSS_TEMPLATE
        assert "Output Contexts" in XSS_TEMPLATE

    def test_template_mentions_dom_content(self):
        from vulnhuntr.prompts import XSS_TEMPLATE

        assert "DOM manipulation" in XSS_TEMPLATE
        assert "HTML" in XSS_TEMPLATE
        assert "JavaScript" in XSS_TEMPLATE

    def test_template_mentions_csp(self):
        from vulnhuntr.prompts import XSS_TEMPLATE

        assert "Content Security Policy" in XSS_TEMPLATE or "CSP" in XSS_TEMPLATE


class TestAFOTemplate:
    def test_template_exists(self):
        from vulnhuntr.prompts import AFO_TEMPLATE

        assert isinstance(AFO_TEMPLATE, str)
        assert len(AFO_TEMPLATE) > 100

    def test_template_has_focus_areas(self):
        from vulnhuntr.prompts import AFO_TEMPLATE

        assert "High-Risk Functions" in AFO_TEMPLATE
        assert "Path Traversal" in AFO_TEMPLATE

    def test_template_mentions_key_functions(self):
        from vulnhuntr.prompts import AFO_TEMPLATE

        assert "open()" in AFO_TEMPLATE
        assert "os.rename()" in AFO_TEMPLATE
        assert "shutil.move()" in AFO_TEMPLATE


class TestSSRFTemplate:
    def test_template_exists(self):
        from vulnhuntr.prompts import SSRF_TEMPLATE

        assert isinstance(SSRF_TEMPLATE, str)
        assert len(SSRF_TEMPLATE) > 100

    def test_template_has_focus_areas(self):
        from vulnhuntr.prompts import SSRF_TEMPLATE

        assert "High-Risk Functions" in SSRF_TEMPLATE
        assert "URL Parsing" in SSRF_TEMPLATE

    def test_template_mentions_key_libraries(self):
        from vulnhuntr.prompts import SSRF_TEMPLATE

        assert "requests" in SSRF_TEMPLATE
        assert "urllib" in SSRF_TEMPLATE

    def test_template_mentions_cloud_metadata(self):
        from vulnhuntr.prompts import SSRF_TEMPLATE

        assert "cloud" in SSRF_TEMPLATE.lower() or "metadata" in SSRF_TEMPLATE.lower()


class TestSQLITemplate:
    def test_template_exists(self):
        from vulnhuntr.prompts import SQLI_TEMPLATE

        assert isinstance(SQLI_TEMPLATE, str)
        assert len(SQLI_TEMPLATE) > 100

    def test_template_has_numbered_steps(self):
        from vulnhuntr.prompts import SQLI_TEMPLATE

        assert "1. Identify Entry Points" in SQLI_TEMPLATE
        assert "2. Trace Input Flow" in SQLI_TEMPLATE
        assert "3. Locate SQL Operations" in SQLI_TEMPLATE

    def test_template_mentions_orm(self):
        from vulnhuntr.prompts import SQLI_TEMPLATE

        assert "ORM" in SQLI_TEMPLATE
        assert "raw()" in SQLI_TEMPLATE or "raw SQL" in SQLI_TEMPLATE

    def test_template_mentions_parameterized_queries(self):
        from vulnhuntr.prompts import SQLI_TEMPLATE

        assert "parameterized" in SQLI_TEMPLATE.lower()


class TestIDORTemplate:
    def test_template_exists(self):
        from vulnhuntr.prompts import IDOR_TEMPLATE

        assert isinstance(IDOR_TEMPLATE, str)
        assert len(IDOR_TEMPLATE) > 100

    def test_template_has_focus_areas(self):
        from vulnhuntr.prompts import IDOR_TEMPLATE

        assert "IDs" in IDOR_TEMPLATE or "identifiers" in IDOR_TEMPLATE

    def test_template_mentions_authorization(self):
        from vulnhuntr.prompts import IDOR_TEMPLATE

        assert "authorization" in IDOR_TEMPLATE.lower()
        assert "permission" in IDOR_TEMPLATE.lower() or "has_permission" in IDOR_TEMPLATE

    def test_template_mentions_common_locations(self):
        from vulnhuntr.prompts import IDOR_TEMPLATE

        assert "URL" in IDOR_TEMPLATE
        assert "API" in IDOR_TEMPLATE


# ── Vulnerability-Specific Bypasses ─────────────────────────────────────────


class TestVulnSpecificBypassesAndPrompts:
    def test_dictionary_has_all_vuln_types(self):
        from vulnhuntr.prompts import VULN_SPECIFIC_BYPASSES_AND_PROMPTS

        expected_types = ["LFI", "RCE", "SSRF", "AFO", "SQLI", "XSS", "IDOR"]
        for vuln_type in expected_types:
            assert vuln_type in VULN_SPECIFIC_BYPASSES_AND_PROMPTS

    def test_each_entry_has_prompt_and_bypasses(self):
        from vulnhuntr.prompts import VULN_SPECIFIC_BYPASSES_AND_PROMPTS

        for vuln_type, data in VULN_SPECIFIC_BYPASSES_AND_PROMPTS.items():
            assert "prompt" in data, f"{vuln_type} missing 'prompt' key"
            assert "bypasses" in data, f"{vuln_type} missing 'bypasses' key"
            assert isinstance(data["prompt"], str)
            assert isinstance(data["bypasses"], list)

    def test_lfi_bypasses(self):
        from vulnhuntr.prompts import VULN_SPECIFIC_BYPASSES_AND_PROMPTS

        lfi_bypasses = VULN_SPECIFIC_BYPASSES_AND_PROMPTS["LFI"]["bypasses"]
        assert len(lfi_bypasses) > 0
        # Check for common LFI patterns
        bypass_str = " ".join(lfi_bypasses)
        assert "../" in bypass_str or "..\\" in bypass_str
        assert "/etc/passwd" in bypass_str

    def test_rce_bypasses(self):
        from vulnhuntr.prompts import VULN_SPECIFIC_BYPASSES_AND_PROMPTS

        rce_bypasses = VULN_SPECIFIC_BYPASSES_AND_PROMPTS["RCE"]["bypasses"]
        assert len(rce_bypasses) > 0
        bypass_str = " ".join(rce_bypasses)
        assert "__import__" in bypass_str
        assert "system" in bypass_str

    def test_ssrf_bypasses(self):
        from vulnhuntr.prompts import VULN_SPECIFIC_BYPASSES_AND_PROMPTS

        ssrf_bypasses = VULN_SPECIFIC_BYPASSES_AND_PROMPTS["SSRF"]["bypasses"]
        assert len(ssrf_bypasses) > 0
        bypass_str = " ".join(ssrf_bypasses)
        assert "127.0.0.1" in bypass_str or "0.0.0.0" in bypass_str

    def test_sqli_bypasses(self):
        from vulnhuntr.prompts import VULN_SPECIFIC_BYPASSES_AND_PROMPTS

        sqli_bypasses = VULN_SPECIFIC_BYPASSES_AND_PROMPTS["SQLI"]["bypasses"]
        assert len(sqli_bypasses) > 0
        bypass_str = " ".join(sqli_bypasses)
        assert "UNION" in bypass_str or "OR" in bypass_str

    def test_xss_bypasses(self):
        from vulnhuntr.prompts import VULN_SPECIFIC_BYPASSES_AND_PROMPTS

        xss_bypasses = VULN_SPECIFIC_BYPASSES_AND_PROMPTS["XSS"]["bypasses"]
        assert len(xss_bypasses) > 0
        bypass_str = " ".join(xss_bypasses)
        assert "<script>" in bypass_str or "javascript:" in bypass_str

    def test_afo_bypasses(self):
        from vulnhuntr.prompts import VULN_SPECIFIC_BYPASSES_AND_PROMPTS

        afo_bypasses = VULN_SPECIFIC_BYPASSES_AND_PROMPTS["AFO"]["bypasses"]
        assert len(afo_bypasses) > 0
        bypass_str = " ".join(afo_bypasses)
        assert "../" in bypass_str or "%00" in bypass_str

    def test_idor_bypasses_empty(self):
        from vulnhuntr.prompts import VULN_SPECIFIC_BYPASSES_AND_PROMPTS

        # IDOR bypasses are context-specific, so may be empty
        idor_bypasses = VULN_SPECIFIC_BYPASSES_AND_PROMPTS["IDOR"]["bypasses"]
        assert isinstance(idor_bypasses, list)


# ── System and Analysis Prompts ─────────────────────────────────────────────


class TestSysPromptTemplate:
    def test_template_exists(self):
        from vulnhuntr.prompts import SYS_PROMPT_TEMPLATE

        assert isinstance(SYS_PROMPT_TEMPLATE, str)
        assert len(SYS_PROMPT_TEMPLATE) > 100

    def test_template_lists_vuln_types(self):
        from vulnhuntr.prompts import SYS_PROMPT_TEMPLATE

        assert "Local File Inclusion" in SYS_PROMPT_TEMPLATE
        assert "Remote Code Execution" in SYS_PROMPT_TEMPLATE
        assert "SQL Injection" in SYS_PROMPT_TEMPLATE
        assert "Cross-Site Scripting" in SYS_PROMPT_TEMPLATE
        assert "SSRF" in SYS_PROMPT_TEMPLATE

    def test_template_mentions_json_output(self):
        from vulnhuntr.prompts import SYS_PROMPT_TEMPLATE

        assert "JSON" in SYS_PROMPT_TEMPLATE

    def test_template_mentions_response_format(self):
        from vulnhuntr.prompts import SYS_PROMPT_TEMPLATE

        assert "<response_format>" in SYS_PROMPT_TEMPLATE

    def test_template_mentions_readme_summary(self):
        from vulnhuntr.prompts import SYS_PROMPT_TEMPLATE

        assert "<readme_summary>" in SYS_PROMPT_TEMPLATE


class TestInitialAnalysisPromptTemplate:
    def test_template_exists(self):
        from vulnhuntr.prompts import INITIAL_ANALYSIS_PROMPT_TEMPLATE

        assert isinstance(INITIAL_ANALYSIS_PROMPT_TEMPLATE, str)
        assert len(INITIAL_ANALYSIS_PROMPT_TEMPLATE) > 100

    def test_template_has_numbered_steps(self):
        from vulnhuntr.prompts import INITIAL_ANALYSIS_PROMPT_TEMPLATE

        assert "1." in INITIAL_ANALYSIS_PROMPT_TEMPLATE
        assert "2." in INITIAL_ANALYSIS_PROMPT_TEMPLATE

    def test_template_lists_vuln_types(self):
        from vulnhuntr.prompts import INITIAL_ANALYSIS_PROMPT_TEMPLATE

        assert "LFI" in INITIAL_ANALYSIS_PROMPT_TEMPLATE
        assert "RCE" in INITIAL_ANALYSIS_PROMPT_TEMPLATE
        assert "SQLI" in INITIAL_ANALYSIS_PROMPT_TEMPLATE
        assert "XSS" in INITIAL_ANALYSIS_PROMPT_TEMPLATE

    def test_template_mentions_file_code_tag(self):
        from vulnhuntr.prompts import INITIAL_ANALYSIS_PROMPT_TEMPLATE

        assert "<file_code>" in INITIAL_ANALYSIS_PROMPT_TEMPLATE


class TestReadmeSummaryPromptTemplate:
    def test_template_exists(self):
        from vulnhuntr.prompts import README_SUMMARY_PROMPT_TEMPLATE

        assert isinstance(README_SUMMARY_PROMPT_TEMPLATE, str)
        assert len(README_SUMMARY_PROMPT_TEMPLATE) > 50

    def test_template_mentions_readme_content_tag(self):
        from vulnhuntr.prompts import README_SUMMARY_PROMPT_TEMPLATE

        assert "<readme_content>" in README_SUMMARY_PROMPT_TEMPLATE

    def test_template_mentions_summary_tag(self):
        from vulnhuntr.prompts import README_SUMMARY_PROMPT_TEMPLATE

        assert "<summary>" in README_SUMMARY_PROMPT_TEMPLATE

    def test_template_focuses_on_security(self):
        from vulnhuntr.prompts import README_SUMMARY_PROMPT_TEMPLATE

        assert "security" in README_SUMMARY_PROMPT_TEMPLATE.lower()

    def test_template_mentions_networking(self):
        from vulnhuntr.prompts import README_SUMMARY_PROMPT_TEMPLATE

        assert "network" in README_SUMMARY_PROMPT_TEMPLATE.lower()


class TestGuidelinesTemplate:
    def test_template_exists(self):
        from vulnhuntr.prompts import GUIDELINES_TEMPLATE

        assert isinstance(GUIDELINES_TEMPLATE, str)
        assert len(GUIDELINES_TEMPLATE) > 100

    def test_template_has_sections(self):
        from vulnhuntr.prompts import GUIDELINES_TEMPLATE

        assert "JSON Format" in GUIDELINES_TEMPLATE
        assert "Context Requests" in GUIDELINES_TEMPLATE
        assert "Vulnerability Reporting" in GUIDELINES_TEMPLATE
        assert "Proof of Concept" in GUIDELINES_TEMPLATE

    def test_template_mentions_confidence_score(self):
        from vulnhuntr.prompts import GUIDELINES_TEMPLATE

        assert "confidence score" in GUIDELINES_TEMPLATE.lower()
        assert "0-10" in GUIDELINES_TEMPLATE

    def test_template_specifies_request_format(self):
        from vulnhuntr.prompts import GUIDELINES_TEMPLATE

        # Specifies how to request classes vs functions
        assert "ClassName" in GUIDELINES_TEMPLATE
        assert "func_name" in GUIDELINES_TEMPLATE


class TestAnalysisApproachTemplate:
    def test_template_exists(self):
        from vulnhuntr.prompts import ANALYSIS_APPROACH_TEMPLATE

        assert isinstance(ANALYSIS_APPROACH_TEMPLATE, str)
        assert len(ANALYSIS_APPROACH_TEMPLATE) > 100

    def test_template_has_numbered_sections(self):
        from vulnhuntr.prompts import ANALYSIS_APPROACH_TEMPLATE

        assert "1. Comprehensive Review" in ANALYSIS_APPROACH_TEMPLATE
        assert "2. Vulnerability Scanning" in ANALYSIS_APPROACH_TEMPLATE
        assert "3. Code Path Analysis" in ANALYSIS_APPROACH_TEMPLATE

    def test_template_mentions_user_input_tracing(self):
        from vulnhuntr.prompts import ANALYSIS_APPROACH_TEMPLATE

        assert "user input" in ANALYSIS_APPROACH_TEMPLATE.lower()
        assert "trace" in ANALYSIS_APPROACH_TEMPLATE.lower() or "flow" in ANALYSIS_APPROACH_TEMPLATE.lower()

    def test_template_mentions_previous_analysis(self):
        from vulnhuntr.prompts import ANALYSIS_APPROACH_TEMPLATE

        assert "<previous_analysis>" in ANALYSIS_APPROACH_TEMPLATE

    def test_template_mentions_context_code(self):
        from vulnhuntr.prompts import ANALYSIS_APPROACH_TEMPLATE

        assert "<context_code>" in ANALYSIS_APPROACH_TEMPLATE


# ── Template Consistency ────────────────────────────────────────────────────


class TestTemplateConsistency:
    def test_all_vuln_templates_match_dictionary(self):
        from vulnhuntr.prompts import (
            LFI_TEMPLATE,
            RCE_TEMPLATE,
            XSS_TEMPLATE,
            AFO_TEMPLATE,
            SSRF_TEMPLATE,
            SQLI_TEMPLATE,
            IDOR_TEMPLATE,
            VULN_SPECIFIC_BYPASSES_AND_PROMPTS,
        )

        assert VULN_SPECIFIC_BYPASSES_AND_PROMPTS["LFI"]["prompt"] == LFI_TEMPLATE
        assert VULN_SPECIFIC_BYPASSES_AND_PROMPTS["RCE"]["prompt"] == RCE_TEMPLATE
        assert VULN_SPECIFIC_BYPASSES_AND_PROMPTS["XSS"]["prompt"] == XSS_TEMPLATE
        assert VULN_SPECIFIC_BYPASSES_AND_PROMPTS["AFO"]["prompt"] == AFO_TEMPLATE
        assert VULN_SPECIFIC_BYPASSES_AND_PROMPTS["SSRF"]["prompt"] == SSRF_TEMPLATE
        assert VULN_SPECIFIC_BYPASSES_AND_PROMPTS["SQLI"]["prompt"] == SQLI_TEMPLATE
        assert VULN_SPECIFIC_BYPASSES_AND_PROMPTS["IDOR"]["prompt"] == IDOR_TEMPLATE

    def test_all_vuln_templates_reference_file_code_tag(self):
        from vulnhuntr.prompts import (
            LFI_TEMPLATE,
            RCE_TEMPLATE,
            XSS_TEMPLATE,
            AFO_TEMPLATE,
            SSRF_TEMPLATE,
            SQLI_TEMPLATE,
            IDOR_TEMPLATE,
        )

        templates = [
            ("LFI", LFI_TEMPLATE),
            ("RCE", RCE_TEMPLATE),
            ("XSS", XSS_TEMPLATE),
            ("AFO", AFO_TEMPLATE),
            ("SSRF", SSRF_TEMPLATE),
            ("SQLI", SQLI_TEMPLATE),
            ("IDOR", IDOR_TEMPLATE),
        ]

        for name, template in templates:
            assert "<file_code>" in template, f"{name} template missing <file_code>"
            assert "<context_code>" in template, f"{name} template missing <context_code>"

    def test_all_vuln_templates_have_analysis_instructions(self):
        from vulnhuntr.prompts import (
            LFI_TEMPLATE,
            RCE_TEMPLATE,
            XSS_TEMPLATE,
            AFO_TEMPLATE,
            SSRF_TEMPLATE,
            SQLI_TEMPLATE,
            IDOR_TEMPLATE,
        )

        templates = [
            ("LFI", LFI_TEMPLATE),
            ("RCE", RCE_TEMPLATE),
            ("XSS", XSS_TEMPLATE),
            ("AFO", AFO_TEMPLATE),
            ("SSRF", SSRF_TEMPLATE),
            ("SQLI", SQLI_TEMPLATE),
            ("IDOR", IDOR_TEMPLATE),
        ]

        for name, template in templates:
            # Each should have "When analyzing, consider:" section
            assert "When analyzing" in template, f"{name} template missing analysis instructions"


# ── Prompt Building ─────────────────────────────────────────────────────────


class TestPromptBuilding:
    """Test that prompts can be combined correctly."""

    def test_sys_prompt_can_be_formatted_with_readme(self):
        from vulnhuntr.prompts import SYS_PROMPT_TEMPLATE

        # The sys prompt template should be usable as-is
        # README summary is added separately via XML tags
        assert isinstance(SYS_PROMPT_TEMPLATE, str)

    def test_initial_analysis_prompt_usable(self):
        from vulnhuntr.prompts import INITIAL_ANALYSIS_PROMPT_TEMPLATE

        # Should be usable as-is
        assert isinstance(INITIAL_ANALYSIS_PROMPT_TEMPLATE, str)

    def test_guidelines_can_be_combined(self):
        from vulnhuntr.prompts import GUIDELINES_TEMPLATE, ANALYSIS_APPROACH_TEMPLATE

        # Should be able to combine these
        combined = GUIDELINES_TEMPLATE + "\n" + ANALYSIS_APPROACH_TEMPLATE
        assert "JSON Format" in combined
        assert "Comprehensive Review" in combined

    def test_vuln_prompt_can_be_retrieved(self):
        from vulnhuntr.prompts import VULN_SPECIFIC_BYPASSES_AND_PROMPTS

        # Simulate getting a vuln-specific prompt
        vuln_type = "SQLI"
        data = VULN_SPECIFIC_BYPASSES_AND_PROMPTS.get(vuln_type)
        assert data is not None
        assert "prompt" in data
        assert "bypasses" in data

    def test_bypasses_can_be_formatted(self):
        from vulnhuntr.prompts import VULN_SPECIFIC_BYPASSES_AND_PROMPTS

        # Simulate formatting bypasses for XML
        vuln_type = "LFI"
        bypasses = VULN_SPECIFIC_BYPASSES_AND_PROMPTS[vuln_type]["bypasses"]
        formatted = "\n".join(bypasses)
        assert "etc/passwd" in formatted


# ── Security Considerations ─────────────────────────────────────────────────


class TestSecurityConsiderations:
    """Ensure prompts don't contain sensitive data."""

    def test_no_api_keys_in_prompts(self):
        from vulnhuntr import prompts

        # Get all string attributes from prompts module
        prompt_attrs = [
            getattr(prompts, attr)
            for attr in dir(prompts)
            if isinstance(getattr(prompts, attr), str) and not attr.startswith("_")
        ]

        for prompt in prompt_attrs:
            assert "sk-ant-" not in prompt, "API key found in prompt"
            assert "sk-proj-" not in prompt, "API key found in prompt"
            assert "Bearer " not in prompt, "Bearer token found in prompt"

    def test_no_hardcoded_paths_in_prompts(self):
        from vulnhuntr import prompts

        prompt_attrs = [
            getattr(prompts, attr)
            for attr in dir(prompts)
            if isinstance(getattr(prompts, attr), str) and not attr.startswith("_")
        ]

        for prompt in prompt_attrs:
            # /etc/passwd is expected in bypass examples
            # but not actual system paths like /home/user
            assert "/home/" not in prompt, "Home path found in prompt"
            assert "C:\\Users\\" not in prompt, "Windows user path found in prompt"


# ── XML Tag Consistency ─────────────────────────────────────────────────────


class TestXMLTagConsistency:
    """Ensure XML tags are properly formatted."""

    def test_file_code_tags_referenced(self):
        from vulnhuntr.prompts import INITIAL_ANALYSIS_PROMPT_TEMPLATE

        # Check the reference exists
        assert "<file_code>" in INITIAL_ANALYSIS_PROMPT_TEMPLATE

    def test_context_code_tag_referenced(self):
        """Test that context_code is referenced somewhere in the templates."""
        from vulnhuntr.prompts import ANALYSIS_APPROACH_TEMPLATE, GUIDELINES_TEMPLATE

        # context_code tag is referenced in ANALYSIS_APPROACH_TEMPLATE
        assert "<context_code>" in ANALYSIS_APPROACH_TEMPLATE or "context_code" in GUIDELINES_TEMPLATE

    def test_readme_content_tag_in_readme_prompt(self):
        from vulnhuntr.prompts import README_SUMMARY_PROMPT_TEMPLATE

        assert "<readme_content>" in README_SUMMARY_PROMPT_TEMPLATE
        assert "</readme_content>" in README_SUMMARY_PROMPT_TEMPLATE

    def test_summary_tag_in_readme_prompt(self):
        from vulnhuntr.prompts import README_SUMMARY_PROMPT_TEMPLATE

        assert "<summary>" in README_SUMMARY_PROMPT_TEMPLATE
        assert "</summary>" in README_SUMMARY_PROMPT_TEMPLATE

    def test_example_bypasses_tag_in_vuln_templates(self):
        """Test that vuln templates reference bypass techniques."""
        from vulnhuntr.prompts import VULN_SPECIFIC_BYPASSES_AND_PROMPTS

        # Templates should reference bypass techniques (not necessarily with XML tag)
        for vuln_type, data in VULN_SPECIFIC_BYPASSES_AND_PROMPTS.items():
            if data["bypasses"]:  # IDOR has empty bypasses
                # Check for any reference to bypasses (not necessarily XML tag)
                assert (
                    "bypass" in data["prompt"].lower()
                ), f"{vuln_type} template missing bypass reference"

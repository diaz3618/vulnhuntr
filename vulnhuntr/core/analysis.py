"""
Vulnerability Analysis Engine
=============================

Core analysis logic for detecting security vulnerabilities in Python code.

The VulnerabilityAnalyzer class orchestrates:
- Initial file analysis with LLM
- Secondary vulnerability-specific analysis
- Context expansion via symbol extraction
- Iterative refinement of findings
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, cast

import structlog

from .models import Response, VulnType
from .xml_models import (
    AnalysisApproach,
    CodeDefinitions,
    ExampleBypasses,
    FileCode,
    Guidelines,
    Instructions,
    PreviousAnalysis,
    ReadmeContent,
    ResponseFormat,
    to_xml_bytes,
)

if TYPE_CHECKING:
    from ..llms import ChatGPT, Claude, Ollama
    from ..symbol_finder import SymbolExtractor

    # Type alias for any LLM client
    LLMClient = Claude | ChatGPT | Ollama

log = structlog.get_logger()


class AnalysisConfig:
    """Configuration for vulnerability analysis.

    Attributes:
        max_iterations: Maximum secondary analysis iterations per vuln type
        min_confidence_for_finding: Minimum confidence score to report finding
        verbosity: Output verbosity level (0=minimal, 1=info, 2=debug)
    """

    def __init__(
        self,
        max_iterations: int = 7,
        min_confidence_for_finding: int = 5,
        verbosity: int = 0,
    ) -> None:
        self.max_iterations = max_iterations
        self.min_confidence_for_finding = min_confidence_for_finding
        self.verbosity = verbosity


class AnalysisResult:
    """Result from analyzing a single file.

    Attributes:
        file_path: Path to the analyzed file
        initial_report: Initial analysis response
        findings: Dict mapping vuln type to final analysis report
        context_code: All code definitions retrieved during analysis
    """

    def __init__(
        self,
        file_path: Path,
        initial_report: Response,
        findings: dict[VulnType, Response] | None = None,
        context_code: dict[str, str] | None = None,
    ) -> None:
        self.file_path = file_path
        self.initial_report = initial_report
        self.findings = findings or {}
        self.context_code = context_code or {}

    @property
    def has_vulnerabilities(self) -> bool:
        """Check if any vulnerabilities were found."""
        return len(self.findings) > 0


class VulnerabilityAnalyzer:
    """Orchestrates vulnerability analysis using LLM.

    The analyzer performs a two-phase analysis:
    1. Initial analysis: General scan for potential vulnerabilities
    2. Secondary analysis: Deep dive into each identified vuln type
       with iterative context expansion

    Attributes:
        llm: LLM client for analysis
        code_extractor: Symbol extractor for context resolution
        config: Analysis configuration
        prompt_templates: Prompt templates for analysis

    Example:
        >>> analyzer = VulnerabilityAnalyzer(llm, extractor)
        >>> result = analyzer.analyze_file(Path("app.py"), all_files)
        >>> if result.has_vulnerabilities:
        ...     for vuln_type, report in result.findings.items():
        ...         print(f"{vuln_type}: confidence={report.confidence_score}")
    """

    def __init__(
        self,
        llm: LLMClient,
        code_extractor: SymbolExtractor,
        config: AnalysisConfig | None = None,
        prompt_templates: dict[str, str] | None = None,
        vuln_specific_data: dict[VulnType, dict] | None = None,
    ) -> None:
        """Initialize the analyzer.

        Args:
            llm: Configured LLM client
            code_extractor: Symbol extractor for context lookups
            config: Analysis configuration (uses defaults if None)
            prompt_templates: Custom prompt templates (optional)
            vuln_specific_data: Bypasses and prompts per vuln type
        """
        self.llm = llm
        self.code_extractor = code_extractor
        self.config = config or AnalysisConfig()
        self.prompt_templates = prompt_templates or {}
        self.vuln_specific_data = vuln_specific_data or {}

        # Callbacks
        self._on_iteration: Callable | None = None
        self._should_continue: Callable | None = None

    def set_iteration_callback(self, callback: Callable) -> None:
        """Set callback for each analysis iteration."""
        self._on_iteration = callback

    def set_continue_check(self, callback: Callable[..., bool]) -> None:
        """Set callback to check if analysis should continue (e.g., budget check)."""
        self._should_continue = callback

    def summarize_readme(self, readme_content: str) -> str:
        """Summarize README content for context.

        Args:
            readme_content: Raw README text

        Returns:
            Summarized README text
        """
        from ..prompts import README_SUMMARY_PROMPT_TEMPLATE

        log.info("Summarizing project README")
        self.llm.set_context(file_path=None, call_type="readme")

        prompt = (
            to_xml_bytes(ReadmeContent(content=readme_content))
            + b"\n"
            + to_xml_bytes(Instructions(instructions=README_SUMMARY_PROMPT_TEMPLATE))
        ).decode()

        response = self.llm.chat(prompt)
        summary = self._extract_between_tags("summary", str(response))

        if summary:
            summary = summary[0]
            log.info("README summary complete", summary=summary)
        else:
            summary = ""
            log.warning("Failed to extract README summary")

        return summary

    def analyze_file(
        self,
        file_path: Path,
        all_files: list[Path],
    ) -> AnalysisResult:
        """Perform full vulnerability analysis on a file.

        Args:
            file_path: Path to the file to analyze
            all_files: List of all project files (for context resolution)

        Returns:
            AnalysisResult containing initial and secondary analysis
        """
        # Import prompt templates
        from ..prompts import (
            ANALYSIS_APPROACH_TEMPLATE,
            GUIDELINES_TEMPLATE,
            INITIAL_ANALYSIS_PROMPT_TEMPLATE,
            VULN_SPECIFIC_BYPASSES_AND_PROMPTS,
        )

        # Read file content
        try:
            with file_path.open(encoding="utf-8") as f:
                content = f.read()
        except (OSError, UnicodeDecodeError) as e:
            log.error("Failed to read file", file=str(file_path), error=str(e))
            raise

        if not content:
            raise ValueError(f"Empty file: {file_path}")

        # Phase 1: Initial Analysis
        log.info("Performing initial analysis", file=str(file_path))
        self.llm.set_context(file_path=str(file_path), call_type="initial")

        initial_prompt = self._build_initial_prompt(
            file_path,
            content,
            INITIAL_ANALYSIS_PROMPT_TEMPLATE,
            ANALYSIS_APPROACH_TEMPLATE,
            GUIDELINES_TEMPLATE,
        )

        initial_report = cast(Response, self.llm.chat(initial_prompt, response_model=Response, max_tokens=8192))
        log.info("Initial analysis complete", report=initial_report.model_dump())

        result = AnalysisResult(file_path=file_path, initial_report=initial_report)

        # Phase 2: Secondary Analysis (if vulnerabilities found)
        if initial_report.confidence_score > 0 and initial_report.vulnerability_types:
            for vuln_type in initial_report.vulnerability_types:
                if self._should_continue and not self._should_continue():
                    log.info("Analysis stopped by callback", vuln_type=vuln_type.value)
                    break

                final_report, context_code = self._secondary_analysis(
                    file_path=file_path,
                    content=content,
                    vuln_type=vuln_type,
                    all_files=all_files,
                    vuln_data=VULN_SPECIFIC_BYPASSES_AND_PROMPTS.get(vuln_type, {}),
                    analysis_approach=ANALYSIS_APPROACH_TEMPLATE,
                    guidelines=GUIDELINES_TEMPLATE,
                )

                # Store findings that meet confidence threshold
                if final_report.confidence_score >= self.config.min_confidence_for_finding:
                    result.findings[vuln_type] = final_report
                    result.context_code.update(context_code)

        return result

    def _secondary_analysis(
        self,
        file_path: Path,
        content: str,
        vuln_type: VulnType,
        all_files: list[Path],
        vuln_data: dict,
        analysis_approach: str,
        guidelines: str,
    ) -> tuple[Response, dict[str, str]]:
        """Perform secondary vulnerability-specific analysis.

        Iteratively refines analysis by expanding context based on
        LLM requests for additional code definitions.

        Args:
            file_path: Path to file being analyzed
            content: File content
            vuln_type: Specific vulnerability type to analyze
            all_files: All project files for context lookup
            vuln_data: Vuln-specific bypasses and prompts
            analysis_approach: Analysis approach template
            guidelines: Guidelines template

        Returns:
            Tuple of (final Response, dict of context code)
        """
        stored_code_definitions: dict[str, str] = {}
        definitions = CodeDefinitions(definitions=[])
        previous_analysis = ""
        previous_context_amount = 0
        same_context_count = 0

        bypasses = vuln_data.get("bypasses", [])
        prompt = vuln_data.get("prompt", "")

        report = None

        for iteration in range(self.config.max_iterations):
            log.info(
                "Performing vuln-specific analysis",
                iteration=iteration,
                vuln_type=vuln_type.value,
                file=str(file_path),
            )

            # Check if we should continue
            if self._should_continue and not self._should_continue():
                log.info("Secondary analysis stopped by callback")
                break

            self.llm.set_context(file_path=str(file_path), call_type="secondary")

            # After first iteration, expand context
            if iteration > 0 and report is not None:
                previous_context_amount = len(stored_code_definitions)
                previous_analysis = report.analysis

                # Resolve requested context code
                for context_item in report.context_code:
                    if context_item.name not in stored_code_definitions:
                        match = self.code_extractor.extract(
                            context_item.name,
                            context_item.code_line,
                            all_files,
                        )
                        if match:
                            stored_code_definitions[context_item.name] = match

                definitions = CodeDefinitions(definitions=list(stored_code_definitions.values()))

            # Build and send prompt
            secondary_prompt = self._build_secondary_prompt(
                file_path=file_path,
                content=content,
                definitions=definitions,
                bypasses=bypasses,
                vuln_prompt=prompt,
                analysis_approach=analysis_approach,
                previous_analysis=previous_analysis,
                guidelines=guidelines,
            )

            report = cast(
                Response,
                self.llm.chat(
                    secondary_prompt,
                    response_model=Response,
                    max_tokens=8192,
                ),
            )
            log.info(
                "Secondary analysis iteration complete",
                iteration=iteration,
                report=report.model_dump(),
            )

            # Call iteration callback if set
            if self._on_iteration:
                self._on_iteration(iteration, report)

            # Termination conditions
            if not report.context_code:
                log.debug("No context code requested, stopping iterations")
                break

            # Check for repeated context requests
            if iteration > 0 and previous_context_amount >= len(stored_code_definitions):
                same_context_count += 1
                if same_context_count >= 2:
                    log.debug("Same context requested twice, stopping iterations")
                    break
            else:
                same_context_count = 0

        return report or Response(), stored_code_definitions

    def _build_initial_prompt(
        self,
        file_path: Path,
        content: str,
        initial_prompt_template: str,
        analysis_approach: str,
        guidelines: str,
    ) -> str:
        """Build the initial analysis prompt."""
        return (
            to_xml_bytes(FileCode(file_path=str(file_path), file_source=content))
            + b"\n"
            + to_xml_bytes(Instructions(instructions=initial_prompt_template))
            + b"\n"
            + to_xml_bytes(AnalysisApproach(analysis_approach=analysis_approach))
            + b"\n"
            + to_xml_bytes(PreviousAnalysis(previous_analysis=""))
            + b"\n"
            + to_xml_bytes(Guidelines(guidelines=guidelines))
            + b"\n"
            + to_xml_bytes(ResponseFormat(response_format=json.dumps(Response.model_json_schema(), indent=4)))
        ).decode()

    def _build_secondary_prompt(
        self,
        file_path: Path,
        content: str,
        definitions: CodeDefinitions,
        bypasses: list[str],
        vuln_prompt: str,
        analysis_approach: str,
        previous_analysis: str,
        guidelines: str,
    ) -> str:
        """Build secondary analysis prompt."""
        return (
            to_xml_bytes(FileCode(file_path=str(file_path), file_source=content))
            + b"\n"
            + to_xml_bytes(definitions)
            + b"\n"
            + to_xml_bytes(ExampleBypasses(example_bypasses="\n".join(bypasses)))
            + b"\n"
            + to_xml_bytes(Instructions(instructions=vuln_prompt))
            + b"\n"
            + to_xml_bytes(AnalysisApproach(analysis_approach=analysis_approach))
            + b"\n"
            + to_xml_bytes(PreviousAnalysis(previous_analysis=previous_analysis))
            + b"\n"
            + to_xml_bytes(Guidelines(guidelines=guidelines))
            + b"\n"
            + to_xml_bytes(ResponseFormat(response_format=json.dumps(Response.model_json_schema(), indent=4)))
        ).decode()

    @staticmethod
    def _extract_between_tags(tag: str, string: str, strip: bool = False) -> list[str]:
        """Extract content between XML tags.

        Based on:
        https://github.com/anthropics/anthropic-cookbook/blob/main/misc/how_to_enable_json_mode.ipynb
        """
        import re

        ext_list = re.findall(f"<{tag}>(.+?)</{tag}>", string, re.DOTALL)
        if strip:
            ext_list = [e.strip() for e in ext_list]
        return ext_list

"""
XML Models for LLM Prompts
==========================

Pydantic-XML models used for structuring prompts sent to LLMs.

These models serialize to XML format which helps structure the
prompts in a way that LLMs can parse more reliably than plain text.
"""

from pydantic_xml import BaseXmlModel, element


def to_xml_bytes(model: BaseXmlModel) -> bytes:
    """Convert a pydantic-xml model to XML bytes.

    Wrapper around BaseXmlModel.to_xml() that ensures the return type
    is always bytes for type-checker compatibility.
    """
    result = model.to_xml()
    if isinstance(result, str):
        return result.encode()
    return result


class ReadmeContent(BaseXmlModel, tag="readme_content"):
    """Container for README file content."""

    content: str


class ReadmeSummary(BaseXmlModel, tag="readme_summary"):
    """Container for summarized README content."""

    readme_summary: str


class Instructions(BaseXmlModel, tag="instructions"):
    """Container for analysis instructions."""

    instructions: str


class ResponseFormat(BaseXmlModel, tag="response_format"):
    """Container for expected response format specification."""

    response_format: str


class AnalysisApproach(BaseXmlModel, tag="analysis_approach"):
    """Container for analysis approach guidance."""

    analysis_approach: str


class Guidelines(BaseXmlModel, tag="guidelines"):
    """Container for analysis guidelines."""

    guidelines: str


class FileCode(BaseXmlModel, tag="file_code"):
    """Container for source code being analyzed.

    Attributes:
        file_path: Path to the source file
        file_source: Complete source code content
    """

    file_path: str = element()
    file_source: str = element()


class PreviousAnalysis(BaseXmlModel, tag="previous_analysis"):
    """Container for previous analysis results in iterative analysis."""

    previous_analysis: str


class ExampleBypasses(BaseXmlModel, tag="example_bypasses"):
    """Container for vulnerability-specific bypass examples."""

    example_bypasses: str


class CodeDefinition(BaseXmlModel, tag="code"):
    """Represents a single code context item.

    Used when providing additional context code to the LLM
    during iterative analysis.

    Attributes:
        name: Name of the function/class/symbol
        context_name_requested: Original name requested by LLM
        file_path: Path to the file containing the code
        source: The actual source code
    """

    name: str = element()
    context_name_requested: str = element()
    file_path: str = element()
    source: str = element()


class CodeDefinitions(BaseXmlModel, tag="context_code"):
    """Container for multiple code context items.

    Used to wrap all fetched context code during iterative analysis.
    """

    definitions: list[CodeDefinition] = []

# Vulnhuntr Documentation

This directory contains comprehensive documentation for the Vulnhuntr project, including technical documentation, areas for improvement, and academic project materials.

---

## Documentation Structure

### Main Documentation

#### [openrouter-free-models.md](openrouter-free-models.md)
Guide to using free LLM models via OpenRouter:
- **31 Free Models**: Complete list with specifications
- **Setup Instructions**: API configuration
- **Provider Support**: Claude, GPT, Gemini, Mistral, and more
- **Cost Savings**: Zero-cost testing and development

**Audience**: Users, developers, budget-conscious testers

---

### Project Documentation (Academic Context)

Located in `project/` subdirectory:

#### [project/TECHNICAL_DOCUMENTATION.md](project/TECHNICAL_DOCUMENTATION.md)
Complete technical guide to understanding Vulnhuntr:
- **How It Works**: Architecture and workflow explanation
- **Component Details**: Deep dive into each module
- **Code Analysis**: Step-by-step analysis process
- **Configuration**: Setup and environment variables
- **Usage Examples**: Command-line interface guide
- **Troubleshooting**: Common issues and solutions
- **Performance**: Characteristics and optimization
- **Best Practices**: For users and developers

**Audience**: Developers, security researchers, contributors

---

#### [project/ARCHITECTURE_REFACTOR.md](project/ARCHITECTURE_REFACTOR.md)
Detailed architecture and design documentation:
- **System Architecture**: High-level component overview
- **Data Flow**: Analysis pipeline and iterative context expansion
- **LLM Integration**: Provider-specific implementations
- **Symbol Resolution**: Jedi-based code extraction
- **Process Flow Diagrams**: Visual workflow representations

**Audience**: Developers, contributors, system architects

---

#### [project/AREAS_OF_IMPROVEMENT.md](project/AREAS_OF_IMPROVEMENT.md)
Comprehensive analysis of potential enhancements:
- **15 Major Improvement Areas** covering:
  - Language support
  - Python version compatibility
  - LLM response validation
  - Cost management
  - Vulnerability detection coverage
  - False positive reduction
  - Reporting and integration
  - Performance optimization
  - Local LLM support
  - Context understanding
  - Documentation and usability
  - Testing and QA
  - Security of the tool
  - Extensibility
  - Reproducibility

**Priority Rankings**: High/Medium/Long-term

**Audience**: Contributors, project maintainers, researchers

---

#### [project/MCP_SERVERS.md](project/MCP_SERVERS.md)
Guide to Model Context Protocol server integrations:
- **Available MCP Servers**: Documentation, analysis, Python LSP
- **Integration Strategies**: How to extend Vulnhuntr with MCP
- **Use Cases**: Practical applications for each server

**Audience**: Developers, contributors interested in extensions

---

### Issue Tracking

Located in `issues/` subdirectory:

#### Fixed Issues (`issues/fixed/`)
Resolved bugs and problems with documented solutions:
- Root cause analysis
- Fix implementation details
- Verification steps
- Related PRs and commits

#### Pending Issues (`issues/pending/`)
Active issues under investigation:
- Current symptoms
- Reproduction steps
- Potential solutions
- Priority classification

#### Persistent Issues (`issues/persistent/`)
Known limitations without complete fixes:
- Workarounds and mitigation strategies
- Impact assessment
- Long-term improvement plans

**See**: `issues/README.md` for conventions and templates

---

### Project Documentation (Academic Context)

Located in `project/` subdirectory:

#### [PROJECT_PROPOSAL.md](project/PROJECT_PROPOSAL.md)
Complete academic project proposal for CS5374 (Trustworthy AI):
- **Background**: Tool context and motivation
- **Objectives**: Research questions and goals
- **Methodology**: Experimental design and approach
- **Deliverables**: Expected outputs and artifacts
- **Timeline**: 12-week project schedule
- **Success Criteria**: How to measure project success
- **Ethical Considerations**: Responsible research practices

**Audience**: Course instructors, academic evaluators

---

#### [RESEARCH_METHODOLOGY.md](project/RESEARCH_METHODOLOGY.md)
Detailed research methodology for analyzing Vulnhuntr:
- **Research Questions**: 4 main RQs with sub-questions
- **Experimental Design**: Benchmark creation and testing protocols
- **Variation Experiments**: LLM comparison, prompt engineering, etc.
- **Enhancement Implementation**: Planned improvements
- **Statistical Analysis**: Hypothesis tests and metrics
- **Quality Assurance**: Validation and documentation standards
- **Timeline**: Detailed weekly milestones

**Audience**: Researchers, methodology reviewers

---

#### [LITERATURE_REVIEW.md](project/LITERATURE_REVIEW.md)
Comprehensive review of related research:
- **LLMs for Code**: Foundation models and capabilities
- **Automated Vulnerability Detection**: Traditional and ML approaches
- **LLMs for Security**: Recent research on LLM security analysis
- **Trustworthiness**: Reliability, hallucinations, adversarial robustness
- **Evaluation Methodologies**: Benchmarks and metrics
- **Research Gaps**: Identified opportunities
- **Theoretical Framework**: Conceptual grounding

**Audience**: Academic readers, researchers

---

## Quick Start

### For Users
Start with [TECHNICAL_DOCUMENTATION.md](TECHNICAL_DOCUMENTATION.md):
1. Read "How It Works" section
2. Follow "Configuration" guide
3. Try "Usage Examples"
4. Refer to "Troubleshooting" as needed

### For Contributors
1. Read [TECHNICAL_DOCUMENTATION.md](TECHNICAL_DOCUMENTATION.md) to understand architecture
2. Review [AREAS_OF_IMPROVEMENT.md](AREAS_OF_IMPROVEMENT.md) for contribution ideas
3. Check "Development Setup" in technical docs
4. Follow "Code Style" guidelines

### For Researchers
1. Start with [PROJECT_PROPOSAL.md](project/PROJECT_PROPOSAL.md) for context
2. Review [LITERATURE_REVIEW.md](project/LITERATURE_REVIEW.md) for background
3. Study [RESEARCH_METHODOLOGY.md](project/RESEARCH_METHODOLOGY.md) for approach
4. Use [TECHNICAL_DOCUMENTATION.md](TECHNICAL_DOCUMENTATION.md) for technical details

---

## Key Findings and Fixes

### Completed Improvements

1. **Python 3.13 Compatibility**
   - Upgraded jedi to 0.19.2+
   - Upgraded parso to 0.8.5+
   - Now works with Python 3.12-3.13

2. **LLM Response Validation**
   - Added regex-based JSON extraction
   - Strips markdown code blocks
   - Reduces validation errors significantly

3. **API Key Management**
   - Created `.env` file support
   - Proper environment variable loading
   - Secure credential handling

4. **Model Name Updates**
   - Updated to current Claude model names
   - Fixed 404 errors from deprecated models
   - Documented in `.env.example`

### Known Issues

See [AREAS_OF_IMPROVEMENT.md](AREAS_OF_IMPROVEMENT.md) for comprehensive list.

**High Priority**:
- Cost management needed
- False positive rate high
- No multi-language support
- Limited reporting formats

---

## Project Context

### Course Information
- **Course**: CS5374 - Trustworthy AI
- **Institution**: [Your University]
- **Semester**: Spring 2026
- **Topic**: Analysis of Open Source Tools for Testing/Debugging AI/LLM/RL

### Project Goals
1. Understand an LLM-based security tool
2. Verify claims about effectiveness
3. Identify limitations and failure modes
4. Implement improvements
5. Contribute to trustworthy AI research

### Connection to Trustworthy AI
- **Reliability**: Can we trust LLM security analysis?
- **Validity**: Do findings represent real vulnerabilities?
- **Explainability**: Can we understand the reasoning?
- **Robustness**: Does it work across diverse code?
- **Safety**: What are the risks of the tool itself?

---
### Related Tools
- **Bandit**: https://github.com/PyCQA/bandit
- **Semgrep**: https://semgrep.dev/
- **CodeQL**: https://codeql.github.com/
- **OWASP Benchmark**: https://owasp.org/www-project-benchmark/

### Academic Resources
- **NVD (CVE Database)**: https://nvd.nist.gov/
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **CWE List**: https://cwe.mitre.org/

---
## License

This documentation follows the same license as Vulnhuntr (AGPL-3.0).

See [LICENSE](../LICENSE) in the root directory.


# CS5374 Project Proposal: Analysis and Enhancement of Vulnhuntr

## Project Title
**Vulnhuntr: Verification, Enhancement, and Trustworthiness Analysis of an LLM-Based Vulnerability Detection Tool**

---

## 1. Background and Motivation

### The Tool: Vulnhuntr

Vulnhuntr is an open-source security analysis tool developed by Protect AI that leverages Large Language Models (LLMs) to automatically discover security vulnerabilities in code. Unlike traditional static analysis tools, Vulnhuntr uses AI to understand code semantics, trace data flow across multiple files, and identify complex multi-step vulnerabilities.

### Research Context

The tool is based on the premise that LLMs, trained on vast amounts of code and security literature, can perform semantic code analysis comparable to expert security researchers. This represents a novel application of LLMs in the security domain, going beyond code generation to actual security auditing.

### Why This Tool?

1. **Real-world impact**: Discovered multiple CVEs in popular open-source projects (67k+ stars)
2. **Novel approach**: First tool to autonomously discover 0-day vulnerabilities using LLMs
3. **Open source**: Code and methodology fully accessible
4. **Active development**: Recent project (2024) with ongoing research value
5. **Verifiable claims**: Can test against known vulnerabilities and discovered CVEs

### Connection to Trustworthy AI

- **Model reliability**: Does the LLM consistently detect vulnerabilities?
- **False positive rate**: How trustworthy are the findings?
- **Explainability**: Can we understand the LLM's reasoning process?
- **Robustness**: Does it work across different code styles and patterns?
- **Safety**: Could the tool itself be exploited or produce harmful outputs?

---

## 2. Project Objectives

### Primary Objectives

1. **Verify Claims**: Validate the tool's effectiveness against the published CVEs
2. **Identify Limitations**: Document failure modes and edge cases
3. **Enhance Robustness**: Implement improvements to increase reliability
4. **Measure Trustworthiness**: Develop metrics for confidence in findings

### Specific Research Questions

1. **Effectiveness**:
   - Can we reproduce the discovered CVEs?
   - What is the false positive/negative rate?
   - How does performance vary across vulnerability types?

2. **LLM Behavior**:
   - Is the analysis deterministic or stochastic?
   - How sensitive is it to prompt engineering?
   - Does confidence score correlate with actual exploitability?

3. **Limitations**:
   - What types of vulnerabilities does it miss?
   - What causes false positives?
   - How does code complexity affect accuracy?

4. **Improvements**:
   - Can we reduce false positives without missing true vulnerabilities?
   - Can we extend to other languages or vulnerability types?
   - Can we improve cost efficiency?

---

## 3. Methodology

### Phase 1: Understanding and Verification (Weeks 1-3)

#### Setup and Installation
- Clone repository and set up development environment
- Configure with different LLM providers (Claude, GPT-4)
- Document installation issues and resolutions

#### Code Analysis
- Study the codebase architecture
- Map data flow from input to output
- Identify key components and their interactions
- Document prompt engineering techniques used

#### Verification Testing
- Create test corpus of known vulnerable code
- Test against the CVEs listed in the paper/repository
- Attempt to reproduce findings on the original vulnerable versions
- Compare results with manual security analysis

### Phase 2: Experimental Analysis (Weeks 4-6)

#### Benchmark Creation
- Compile dataset of known Python vulnerabilities:
  - OWASP benchmark cases
  - Real-world CVE code samples
  - Synthetic vulnerable code snippets
  - Benign code with security controls

#### Systematic Testing
- Run Vulnhuntr on benchmark dataset
- Measure:
  - True Positives: Correctly identified vulnerabilities
  - False Positives: Incorrectly flagged safe code
  - False Negatives: Missed vulnerabilities
  - Analysis time and API costs
  - Confidence score distribution

#### Variation Testing
- Test with different LLMs (Claude vs GPT vs Ollama)
- Test with different prompt variations
- Test with different confidence thresholds
- Test with code obfuscation techniques
- Test with different code complexities

### Phase 3: Enhancement Implementation (Weeks 7-10)

Based on findings from Phase 2, implement improvements such as:

#### Improvement 1: False Positive Reduction
- Implement taint analysis validation
- Add automated PoC verification (when safe)
- Create confidence score calibration based on historical data
- Add human feedback loop

#### Improvement 2: Performance Optimization
- Implement caching of symbol definitions
- Add parallel file analysis
- Optimize context retrieval

#### Improvement 3: Explainability Enhancement
- Generate visualization of data flow paths
- Create detailed reasoning traces
- Add interactive review mode
- Implement diff-based re-analysis

### Phase 4: Evaluation and Documentation (Weeks 11-12)

#### Quantitative Evaluation
- Re-run benchmarks with improvements
- Statistical comparison of before/after metrics
- Cost-benefit analysis of changes

#### Qualitative Evaluation
- Case studies of interesting findings
- User study (if time permits)
- Expert review of outputs

#### Documentation
- Comprehensive technical report
- Code documentation and comments
- User guide for improvements
- Research paper draft

---

## 4. Deliverables

### Code Artifacts

1. **Enhanced Vulnhuntr Implementation**
   - Fork of original repository with improvements
   - Well-documented code changes
   - Unit and integration tests
   - Configuration options for new features

2. **Benchmarking Suite**
   - Dataset of test cases
   - Automated testing framework
   - Performance measurement scripts
   - Result visualization tools

3. **Analysis Tools**
   - False positive analysis tool
   - Confidence calibration system
   - Cost tracking and estimation
   - Comparative analysis scripts

### Documentation

1. **Technical Report** (20-30 pages)
   - Introduction and background
   - Tool architecture analysis
   - Experimental design and methodology
   - Results and statistical analysis
   - Discussion of findings
   - Proposed improvements
   - Implementation details
   - Future work

2. **Code Documentation**
   - Architecture documentation (completed in `docs/`)
   - API documentation
   - Improvement rationale
   - Usage examples

3. **Research Artifacts**
   - Benchmark dataset with annotations
   - Experimental data and logs
   - Statistical analysis notebooks
   - Visualization of results

### Presentation

1. **Final Presentation** (15-20 minutes)
   - Project overview
   - Key findings
   - Live demonstration
   - Q&A session

2. **Demonstration Materials**
   - Example vulnerability detection
   - Before/after comparison
   - Performance metrics visualization

---

## 5. Expected Outcomes

### Scientific Understanding

1. **Empirical Analysis**
   - Quantitative assessment of LLM-based vulnerability detection
   - Comparison with traditional static analysis tools
   - Understanding of when and why the approach works

2. **Insights into LLM Behavior**
   - How LLMs reason about security vulnerabilities
   - Limitations of current prompting strategies
   - Factors affecting accuracy and reliability

3. **Best Practices**
   - Recommendations for using LLMs in security analysis
   - Guidelines for prompt engineering in security contexts
   - Strategies for result validation

### Practical Contributions

1. **Improved Tool**
   - More accurate vulnerability detection
   - Reduced false positive rate
   - Better user experience and reporting
   - Cost optimizations

2. **Reusable Components**
   - Benchmark suite for future research
   - Evaluation framework
   - Analysis and visualization tools

3. **Knowledge Transfer**
   - Detailed documentation for community
   - Case studies and examples
   - Contribution back to open-source project

### Academic Output

1. **Technical Report**
   - Publishable analysis of tool effectiveness
   - Novel insights into LLM security analysis
   - Reproducible experimental methodology

2. **Potential Publications**
   - Workshop paper on findings
   - Tool demonstration paper
   - Dataset contribution

---

## 6. Potential Challenges and Mitigation

### Challenge 1: API Costs

**Risk**: LLM API calls can be expensive for extensive testing

**Mitigation**:
- Use API budget limits
- Implement aggressive caching
- Use smaller test sets initially
- Explore Ollama/local LLM options
- Seek academic API credits if available

### Challenge 2: Non-Deterministic Results

**Risk**: LLM outputs may vary between runs

**Mitigation**:
- Multiple runs per test case
- Statistical analysis of variance
- Use temperature=0 for deterministic mode where available
- Document and analyze variance patterns

### Challenge 3: Ground Truth Validation

**Risk**: Difficult to establish definitive "correct" answers

**Mitigation**:
- Focus on known CVEs first
- Manual expert review of findings
- Cross-validation with multiple tools
- Conservative classification of edge cases

### Challenge 4: Code Complexity

**Risk**: Tool may struggle with complex codebases

**Mitigation**:
- Start with simple examples
- Gradually increase complexity
- Document failure patterns
- Focus improvements on common patterns first

### Challenge 5: Time Constraints

**Risk**: 12 weeks is tight for comprehensive analysis

**Mitigation**:
- Clear prioritization of objectives
- Agile approach with regular checkpoints
- Parallel workstreams where possible
- MVP approach for enhancements

---

## 7. Timeline

### Week 1-2: Setup and Understanding
- ✅ Environment setup and configuration
- ✅ Codebase analysis and documentation
- Study of related work
- Initial test runs

### Week 3-4: Verification and Benchmarking
- CVE reproduction attempts
- Benchmark dataset creation
- Initial experimental runs
- Data collection framework

### Week 5-6: Systematic Evaluation
- Comprehensive benchmark testing
- LLM comparison experiments
- Prompt variation testing
- Result analysis

### Week 7-8: Enhancement Design and Implementation
- Identify top improvement opportunities
- Design enhanced architecture
- Implement priority improvements
- Unit testing of changes

### Week 9-10: Integration and Testing
- Integration of improvements
- Re-run benchmarks
- Performance comparison
- Bug fixes and refinement

### Week 11: Documentation and Analysis
- Statistical analysis of results
- Technical report writing
- Code documentation
- User guide creation

### Week 12: Presentation Preparation
- Presentation materials
- Demo preparation
- Final report polish
- Submission

---

## 8. Resources Required

### Computational Resources
- Development machine (personal)
- Cloud LLM API access (Claude/GPT)
- Git/GitHub for version control
- Python 3.12+ environment

### Software/Tools
- Vulnhuntr codebase (open source)
- Static analysis tools for comparison (Bandit, Semgrep)
- Python testing frameworks (pytest)
- Data analysis tools (pandas, matplotlib)
- Jupyter notebooks for analysis

### Data
- Vulnhuntr's discovered CVEs
- OWASP benchmark suite
- NVD CVE database
- Synthetic vulnerable code samples

### Human Resources
- Student (primary investigator)
- Course instructor (advisor)
- Optional: Security expert for validation

---

## 9. Success Criteria

### Minimum Viable Success
1. Reproduce at least 3 of the published CVEs
2. Document 5 specific limitations or failure modes
3. Implement at least 1 measurable improvement
4. Create benchmark suite with 50+ test cases
5. Complete technical report with quantitative analysis

### Target Success
1. Reproduce majority of published CVEs
2. Comprehensive false positive/negative analysis
3. Implement 3-5 significant improvements
4. Benchmark suite with 100+ test cases
5. Demonstrate 20%+ reduction in false positives
6. Publication-ready technical report

### Stretch Goals
1. Extend to support additional programming languages
2. Achieve publishable novel findings
3. Contributions accepted to upstream project
4. Create widely reusable benchmark suite
5. Present at security conference/workshop

---

## 10. Ethical Considerations

### Responsible Disclosure
- Any new vulnerabilities discovered will follow responsible disclosure
- Coordinate with maintainers before public disclosure
- Give adequate time for patching (90 days standard)

### Dual-Use Concerns
- Tool could be used maliciously to find vulnerabilities to exploit
- Improvements should focus on defense, not offense
- Document intended use cases clearly

### Reproducibility
- All code and data will be open source
- Experiments designed to be reproducible
- Clear documentation of methodology

### Academic Integrity
- Proper citation of original work
- Clear attribution of contributions
- Transparent reporting of results, including failures

---

## 11. Related Work

### LLMs for Code Analysis
- GitHub Copilot for code generation
- CodeBERT for code understanding
- AlphaCode for competitive programming
- Recent work on LLMs finding bugs

### Static Vulnerability Detection
- Traditional tools: Bandit, Semgrep, CodeQL
- Taint analysis frameworks
- Symbolic execution tools
- Fuzzing techniques

### AI for Security
- ML for malware detection
- Anomaly detection in logs
- Automated penetration testing
- Vulnerability prioritization

### Prompt Engineering for Technical Tasks
- Chain-of-thought prompting
- Few-shot learning for specialized domains
- Constrained generation for structured outputs

---

## 12. Conclusion

This project offers a unique opportunity to critically examine a cutting-edge application of LLMs to security analysis. By systematically verifying claims, identifying limitations, and implementing improvements, we will gain deep insights into both the tool's effectiveness and broader questions about trusting AI systems for critical security tasks.

The project aligns perfectly with the course's focus on trustworthy AI, combining empirical evaluation, theoretical understanding, and practical engineering. The deliverables will contribute to both the academic understanding of LLM capabilities and the practical goal of building more reliable security tools.

Most importantly, the open-source nature of Vulnhuntr and our planned contributions mean that this work can have real-world impact beyond the classroom, potentially improving the security of numerous software projects.

---

## References

1. Protect AI. "Vulnhuntr: Zero Shot Vulnerability Discovery Using LLMs." GitHub, 2024. https://github.com/protectai/vulnhuntr

2. Protect AI. "Vulnhuntr: The First 0-Day Vulnerabilities Discovered by AI." Blog post, 2024.

3. CVE Details. "CVE-2024-10100, CVE-2024-10101, CVE-2024-10099, CVE-2024-10131, CVE-2024-10044, CVE-2024-9309." https://www.cvedetails.com/

4. Anthropic. "Claude 3.5 Sonnet Model Documentation." 2024.

5. OpenAI. "GPT-4 Technical Report." 2024.

6. OWASP. "OWASP Top 10." 2021. https://owasp.org/www-project-top-ten/

7. Pearce et al. "Can Large Language Models Find And Fix Vulnerable Software?" arXiv:2308.10345, 2023.

8. Fu et al. "Is Stack Overflow Obsolete? An Empirical Study of the Characteristics of ChatGPT Answers to Software Engineering Questions." MSR 2023.

---

## Contact Information

**Student**: [Your Name]  
**Email**: [Your Email]  
**Course**: CS5374 - Trustworthy AI  
**Semester**: Spring 2026  
**Instructor**: [Instructor Name]

**Project Repository**: [To be created]  
**Project Status**: Proposal Stage  
**Estimated Completion**: [End of Semester]

# Research Methodology for Vulnhuntr Analysis

## Overview

This document outlines the detailed research methodology for analyzing and enhancing Vulnhuntr, an LLM-based vulnerability detection tool. Our approach combines empirical software evaluation, security analysis, and AI trustworthiness assessment.

---

## Research Questions

### RQ1: Effectiveness
**Can Vulnhuntr reliably detect known vulnerabilities?**

**Sub-questions**:
- RQ1.1: What is the true positive rate on known CVEs?
- RQ1.2: What is the false positive rate on secure code?
- RQ1.3: What is the false negative rate on vulnerable code?
- RQ1.4: How does performance vary by vulnerability type?

### RQ2: Reliability
**How consistent are Vulnhuntr's results?**

**Sub-questions**:
- RQ2.1: Does analysis vary between runs (stochastic behavior)?
- RQ2.2: How does LLM choice (Claude vs GPT) affect results?
- RQ2.3: Does confidence score correlate with actual exploitability?
- RQ2.4: Are results reproducible across different environments?

### RQ3: Limitations
**What are Vulnhuntr's failure modes?**

**Sub-questions**:
- RQ3.1: What vulnerability patterns does it miss?
- RQ3.2: What causes false positives?
- RQ3.3: How does code complexity affect accuracy?
- RQ3.4: What are the computational and cost constraints?

### RQ4: Improvements
**Can we enhance Vulnhuntr's trustworthiness?**

**Sub-questions**:
- RQ4.1: Can we reduce false positives without increasing false negatives?
- RQ4.2: Can prompt engineering improve accuracy?
- RQ4.3: Can we add verification layers to increase confidence?
- RQ4.4: Can we optimize cost while maintaining accuracy?

---

## Experimental Design

### 1. Benchmark Dataset Creation

#### 1.1 Known Vulnerable Code (Positive Cases)

**Source 1: Vulnhuntr's Discovered CVEs**
- Collect code from projects where Vulnhuntr found vulnerabilities
- Use versions before patches were applied
- Expected vulnerabilities are known (ground truth)

**Source 2: Public CVE Databases**
- NVD (National Vulnerability Database)
- GitHub Security Advisories
- Filter for Python projects with public code
- Manually verify exploitability

**Source 3: OWASP Benchmark**
- OWASP's test suite for security tools
- Known vulnerable patterns
- https://github.com/OWASP/Benchmark

**Source 4: Synthetic Vulnerable Code**
- Create minimalist examples of each vulnerability type
- Gradually increase complexity
- Ensure exploitability is clear

**Target Distribution**:
```
RCE:   20 examples
LFI:   20 examples
XSS:   20 examples
SQLI:  20 examples
SSRF:  20 examples
AFO:   10 examples
IDOR:  10 examples
Total: 100 vulnerable code samples
```

#### 1.2 Secure Code (Negative Cases)

**Source 1: Popular Python Projects**
- Well-maintained projects with security reviews
- Flask, Django, FastAPI core code
- Known to have security controls

**Source 2: Patched Versions**
- Same code as vulnerable set, but after security fixes
- Direct comparison opportunity

**Source 3: Synthetic Secure Code**
- Secure implementations of common patterns
- Proper input validation examples
- Security best practices

**Target**: 100 secure code samples

#### 1.3 Ambiguous Cases

**Purpose**: Test edge cases and near-misses
- Code with partial vulnerabilities
- Defense-in-depth scenarios
- Context-dependent issues

**Target**: 25 ambiguous samples with expert annotations

---

### 2. Baseline Measurement Protocol

#### 2.1 Configuration
```bash
# Standard configuration
LLM: Claude Sonnet 4.5
Temperature: 0 (deterministic mode if possible)
Max iterations: 7 (default)
Verbosity: -vv (maximum detail)
```

#### 2.2 Execution
For each file in benchmark:
1. Record start time
2. Run Vulnhuntr analysis
3. Capture all output (console + logs)
4. Record end time
5. Save API token usage
6. Calculate cost

#### 2.3 Result Recording
Create structured record for each analysis:
```json
{
  "file_id": "CVE-2024-10100",
  "file_path": "/path/to/vulnerable.py",
  "expected_vuln": ["LFI"],
  "detected_vuln": ["LFI", "XSS"],
  "confidence_scores": {"LFI": 9, "XSS": 6},
  "analysis_time_seconds": 45.2,
  "api_calls": 5,
  "total_tokens": 15234,
  "cost_usd": 0.45,
  "llm_reasoning": "...",
  "poc": "...",
  "true_positive": true,
  "false_positive": ["XSS"],
  "false_negative": [],
  "notes": "Correctly identified LFI, incorrectly flagged XSS"
}
```

#### 2.4 Metrics Calculation

**Accuracy Metrics**:
```
Precision = TP / (TP + FP)
Recall = TP / (TP + FN)
F1 Score = 2 × (Precision × Recall) / (Precision + Recall)

Per-vulnerability-type metrics
Overall aggregate metrics
```

**Confidence Calibration**:
```
For each confidence score bucket [0-2, 3-4, 5-6, 7-8, 9-10]:
  Calculate actual accuracy in that bucket
  Compare with expected accuracy
```

**Cost Analysis**:
```
Average cost per file
Cost per true positive
Cost per false positive
Total cost for repository scan
```

---

### 3. Variation Experiments

#### Experiment 1: LLM Comparison

**Hypothesis**: Different LLMs have different accuracy profiles

**Method**:
- Run same benchmark with:
  - Claude Sonnet 4.5
  - GPT-4o
  - Ollama Llama 3.2 (if functional)
- Compare accuracy, cost, time

**Metrics**: Precision, Recall, F1, Cost, Time

#### Experiment 2: Prompt Engineering

**Hypothesis**: Modified prompts can improve accuracy

**Method**:
- Create variations:
  1. Baseline (current prompts)
  2. More explicit bypass instructions
  3. Few-shot examples added
  4. Chain-of-thought emphasis
  5. Conservative bias (reduce FP)
- Test subset of benchmark (25 files)

**Metrics**: Change in TP, FP, FN rates

#### Experiment 3: Confidence Threshold

**Hypothesis**: Filtering by confidence score can optimize precision/recall tradeoff

**Method**:
- Analyze results with different confidence cutoffs:
  - ≥4, ≥5, ≥6, ≥7, ≥8, ≥9
- Plot precision-recall curve

**Metrics**: Precision, Recall at each threshold

#### Experiment 4: Code Complexity

**Hypothesis**: More complex code leads to worse performance

**Method**:
- Measure code complexity:
  - Lines of code
  - Cyclomatic complexity
  - Function call depth
  - Number of files involved
- Correlate with accuracy

**Metrics**: Correlation coefficients, scatter plots

#### Experiment 5: Reproducibility

**Hypothesis**: Results are reproducible despite LLM non-determinism

**Method**:
- Run same 20 files 10 times each
- Measure variance in:
  - Detected vulnerabilities
  - Confidence scores
  - Analysis reasoning

**Metrics**: Standard deviation, coefficient of variation

---

### 4. Enhancement Implementation

Based on findings, implement improvements. Planned enhancements:

#### Enhancement 1: Taint Analysis Validator

**Goal**: Verify LLM findings with traditional taint analysis

**Method**:
- Implement lightweight taint tracker
- Trace user input to dangerous sinks
- Confirm or reject LLM findings
- Use as confidence booster/reducer

**Evaluation**: Measure change in FP rate

#### Enhancement 2: Confidence Calibration

**Goal**: Make confidence scores more accurate

**Method**:
- Train calibration model on benchmark results
- Map LLM confidence + code features → actual probability
- Use logistic regression or similar

**Evaluation**: Calibration curve before/after

#### Enhancement 3: Iterative Refinement

**Goal**: Reduce FP through clarifying questions

**Method**:
- When confidence is medium (5-7), ask LLM to verify
- Provide additional context or constraints
- Re-analyze with refined prompt

**Evaluation**: FP reduction, cost increase

#### Enhancement 4: Caching Layer

**Goal**: Reduce cost without affecting accuracy

**Method**:
- Cache symbol definitions
- Cache LLM responses for identical inputs
- Implement smart context reuse

**Evaluation**: Cost reduction, time savings

---

### 5. Comparative Analysis

#### Comparison with Traditional Tools

Run same benchmark with:
- **Bandit**: Python security linter
- **Semgrep**: Pattern-based static analysis
- **CodeQL**: Semantic code analysis

**Metrics to Compare**:
- True/False Positives/Negatives
- Vulnerability types detected
- Time to analyze
- Ease of use

**Analysis**:
- Venn diagrams of detected vulnerabilities
- Unique findings per tool
- Complementary strengths/weaknesses

---

### 6. Case Studies

Select 5-10 interesting cases for deep analysis:

1. **Success Story**: Complex multi-step vulnerability correctly identified
2. **False Positive**: Why was secure code flagged?
3. **False Negative**: Why was vulnerability missed?
4. **Borderline Case**: Disagreement between experts
5. **Novel Finding**: Previously unknown vulnerability

For each case study:
- Detailed code walkthrough
- LLM's reasoning analysis
- Expert security assessment
- Lessons learned

---

## Data Collection and Management

### Data Organization

```
vulnhuntr-research/
├── benchmark/
│   ├── vulnerable/
│   │   ├── rce/
│   │   ├── lfi/
│   │   └── ...
│   ├── secure/
│   └── ambiguous/
├── results/
│   ├── baseline/
│   │   ├── raw_output/
│   │   ├── structured_results.json
│   │   └── analysis.ipynb
│   ├── experiment_1_llm_comparison/
│   ├── experiment_2_prompts/
│   └── ...
├── enhancements/
│   ├── taint_analysis/
│   ├── calibration/
│   └── ...
└── analysis/
    ├── statistical_analysis.ipynb
    ├── visualizations/
    └── report_figures/
```

### Data Tracking

Use SQLite database to track all experiments:

```sql
CREATE TABLE experiments (
    id INTEGER PRIMARY KEY,
    name TEXT,
    description TEXT,
    date TIMESTAMP,
    configuration JSON
);

CREATE TABLE results (
    id INTEGER PRIMARY KEY,
    experiment_id INTEGER,
    file_id TEXT,
    detected_vulns JSON,
    confidence_scores JSON,
    metrics JSON,
    cost REAL,
    time REAL,
    FOREIGN KEY (experiment_id) REFERENCES experiments(id)
);
```

---

## Statistical Analysis Plan

### Descriptive Statistics

For each experiment:
- Mean, median, standard deviation of metrics
- Distribution plots (histograms, box plots)
- Summary tables

### Inferential Statistics

**Hypothesis Tests**:

1. **LLM Comparison** (Experiment 1)
   - H₀: No significant difference in F1 scores
   - Test: Paired t-test or Wilcoxon signed-rank
   - α = 0.05

2. **Prompt Engineering** (Experiment 2)
   - H₀: Prompt modifications don't improve accuracy
   - Test: ANOVA with post-hoc tests
   - α = 0.05

3. **Code Complexity** (Experiment 4)
   - H₀: No correlation between complexity and accuracy
   - Test: Pearson or Spearman correlation
   - α = 0.05

**Effect Sizes**:
- Cohen's d for mean differences
- R² for correlations
- Report confidence intervals

### Reproducibility

All analysis in Jupyter notebooks with:
- Clear documentation
- Reproducible random seeds
- Versioned dependencies
- Automated from raw data

---

## Quality Assurance

### Validation Procedures

1. **Benchmark Validation**
   - Two independent reviewers for each case
   - Consensus required, third reviewer for conflicts
   - Document reasoning for each classification

2. **Result Validation**
   - Spot-check 20% of automated classifications
   - Manual review of all novel findings
   - Expert validation of case studies

3. **Code Quality**
   - Unit tests for enhancements
   - Code review before integration
   - Continuous integration checks

### Documentation Standards

- README for each experiment
- Code comments for non-obvious logic
- Jupyter notebooks with markdown explanations
- Version control for all code and data

---

## Ethical Review

### Privacy Considerations

- Only use publicly available code
- Anonymize any sensitive findings
- No unauthorized testing on live systems

### Responsible Disclosure

- Coordinate with maintainers for new findings
- 90-day disclosure window
- Document disclosure process

### Bias Awareness

- Acknowledge LLM training biases
- Consider demographic impacts
- Diverse benchmark creation

---

## Risk Mitigation

### Risk 1: Benchmark Creation Difficulty

**Mitigation**: Start with existing CVEs, expand gradually

### Risk 2: API Cost Overruns

**Mitigation**: Budget tracking, caching, smaller initial experiments

### Risk 3: Non-Reproducibility

**Mitigation**: Version control, detailed logging, environment specification

### Risk 4: Time Constraints

**Mitigation**: Prioritized objectives, MVP approach, parallel work where possible

---

## Conclusion

This methodology provides a rigorous, reproducible approach to evaluating and enhancing Vulnhuntr. By combining quantitative experiments with qualitative case studies, we'll gain comprehensive understanding of the tool's trustworthiness and contribute practical improvements to the security analysis community.

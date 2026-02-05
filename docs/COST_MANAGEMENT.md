# Cost Management in Vulnhuntr

Vulnhuntr uses LLM APIs (Claude, ChatGPT, or Ollama) to analyze code for vulnerabilities. API costs can accumulate quickly on large repositories. This document explains how to manage and control analysis costs.

---

## Overview

**Why Cost Management Matters:**
- Large repositories can cost $50-$500+ to analyze completely
- Iterative analysis (up to 7 iterations per vulnerability type) multiplies token usage
- Claude and GPT-4 charge per 1,000 tokens for both input and output
- No built-in limits means accidental runaway costs

**Vulnhuntr's Cost Management Features:**
1. **Token Usage Tracking** - Real-time cost calculation and reporting
2. **Dry-Run Mode** - Estimate costs before running analysis
3. **Budget Limits** - Hard caps on spending with warnings
4. **Checkpointing** - Save progress to avoid re-running expensive analysis
5. **Cost-Aware Iteration Limiting** - Stop expensive iteration loops
6. **Configuration** - Set defaults in `.vulnhuntr.yaml`

---

## Quick Start

### 1. Estimate Costs Before Running (Dry-Run)

```bash
vulnhuntr -r /path/to/repo --dry-run
```

**Output:**
```
DRY RUN - COST ESTIMATE
============================================================

Model: claude-3-5-sonnet-20241022
Files to analyze: 42

Estimated Tokens:
  Input:  1,245,000
  Output: 425,000
  Total:  1,670,000

Estimated Cost: $5.12 USD
  Range: $2.56 - $7.68

Top 10 Most Expensive Files:
┏━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ File                     ┃    Tokens ┃ Est. Cost ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━┩
│ api/routes.py            │   45,231  │ $0.52     │
│ models/user.py           │   32,100  │ $0.37     │
│ ...                      │   ...     │ ...       │
└──────────────────────────┴───────────┴───────────┘

Actual costs might be different based on complexity.
Use --budget to set a spending limit.
```

### 2. Set a Budget Limit

```bash
vulnhuntr -r /path/to/repo --budget 10.00
```

- Analysis stops when budget is exceeded
- 80% budget warning by default
- Progress saved to checkpoint for resuming with higher budget

### 3. Resume After Budget Exceeded

```bash
vulnhuntr -r /path/to/repo --budget 20.00 --resume
```

- Continues from where previous analysis stopped
- New budget applies to remaining files
- Previous costs tracked separately

---

## Cost Tracking

### Real-Time Tracking

Vulnhuntr tracks costs for every LLM API call:

```python
# Tracked automatically
- Input tokens (prompt + context)
- Output tokens (LLM response)
- Model used
- Cost per call
- Cost per file
- Cost per model
```

### Cost Summary Report

At the end of analysis, you'll see a detailed cost report:

```
============================================================
COST SUMMARY
============================================================
Total Cost: $4.23 USD
Total Tokens: 1,234,567 (987,654 in / 246,913 out)
API Calls: 127
Elapsed Time: 342.5 seconds

Costs by Model:
  claude-3-5-sonnet-20241022: $4.23

Top 10 Files by Cost:
  $0.52 - api/routes.py
  $0.37 - models/user.py
  $0.31 - services/auth.py
  ...

============================================================
```

---

## Budget Enforcement

### Setting Budgets

**Via CLI:**
```bash
vulnhuntr -r /path/to/repo --budget 50.00
```

**Via Configuration:**
```yaml
# .vulnhuntr.yaml
cost:
  max_budget_usd: 50.0
  warning_threshold: 0.8  # Warn at 80%
  max_cost_per_file: 2.0  # Skip files over $2
  max_cost_per_iteration: 0.50  # Limit iteration costs
```

### How Budget Enforcement Works

1. **Warning Threshold (default 80%)**
   - Logs warning when 80% of budget is used
   - Continues analysis

2. **Hard Limit (100%)**
   - Stops analysis immediately
   - Saves checkpoint
   - Prints summary

3. **Per-File Limit**
   - Skips files that would exceed per-file budget
   - Useful for skipping very large files

4. **Per-Iteration Limit**
   - Stops iteration loops that become too expensive
   - Prevents runaway context accumulation

---

## Cost-Aware Context Limiting

Vulnhuntr can analyze vulnerabilities through multiple iterations (up to 7), fetching additional context functions each time. This can accumulate significant costs.

**Cost-Aware Limiting prevents this by:**

1. **Tracking iteration costs** - Each iteration's cost is calculated
2. **Detecting cost escalation** - If costs increase significantly each iteration, stop
3. **Per-iteration limits** - Hard cap on single iteration cost
4. **Preventing diminishing returns** - Stop when iterations aren't improving analysis

**Example:**
```
Iteration 1: $0.10  ✓
Iteration 2: $0.15  ✓
Iteration 3: $0.25  ✓
Iteration 4: $0.45  ✗ STOP - costs escalating
```

**Configure:**
```yaml
# .vulnhuntr.yaml
cost:
  max_cost_per_iteration: 0.50  # Stop iterations over $0.50
```

---

## Checkpointing

Checkpoints save analysis progress to avoid re-running expensive API calls.

### Automatic Checkpointing

**Enabled by default** - creates `.vulnhuntr_checkpoint` in scan directory.

**Saves:**
- Files completed
- Files in progress
- Cost tracking data
- Analysis results
- Timestamp

### Resume from Checkpoint

```bash
# Default checkpoint location
vulnhuntr -r /path/to/repo --resume

# Custom checkpoint file
vulnhuntr -r /path/to/repo --resume /path/to/checkpoint.json
```

### Disable Checkpointing

```bash
vulnhuntr -r /path/to/repo --no-checkpoint
```

**When to disable:**
- One-time scans
- CI/CD pipelines (ephemeral environments)
- Testing different configurations

---

## Configuration File

Create `.vulnhuntr.yaml` in project root or home directory:

```yaml
# Cost Management Configuration
cost:
  # Maximum total budget (USD)
  max_budget_usd: 50.0
  
  # Warn when this percentage of budget is used (0.0-1.0)
  warning_threshold: 0.8
  
  # Maximum cost per file (USD) - skip files over this
  max_cost_per_file: 2.0
  
  # Maximum cost per iteration (USD) - stop iterations over this
  max_cost_per_iteration: 0.50

# Checkpoint Configuration
checkpoint:
  # Enable automatic checkpointing
  enabled: true
  
  # Checkpoint file location (relative to scan directory)
  path: ".vulnhuntr_checkpoint"
  
  # Auto-save interval (files)
  interval: 1
```

---

## Pricing Information

### Current Pricing (as of 2024-12)

**Claude (Anthropic):**
- `claude-3-5-sonnet-20241022`: $0.003/1K input, $0.015/1K output
- `claude-3-opus-20240229`: $0.015/1K input, $0.075/1K output
- `claude-3-haiku-20240307`: $0.00025/1K input, $0.00125/1K output

**ChatGPT (OpenAI):**
- `gpt-4o`: $0.005/1K input, $0.015/1K output
- `gpt-4-turbo`: $0.01/1K input, $0.03/1K output
- `gpt-3.5-turbo`: $0.0005/1K input, $0.0015/1K output

**Ollama (Local):**
- All models: $0.00 (runs locally)

**Note:** Pricing changes frequently. Check provider websites for current rates.

### Cost Estimation Accuracy

Dry-run estimates are **conservative approximations**:
- ✅ **Overestimate** file token counts by ~20%
- ✅ **Assume average case** for iterations (5 of 7)
- ✅ **Include overhead** for prompts, examples, XML wrappers
- ❌ **Cannot predict** actual vulnerability complexity
- ❌ **Cannot predict** actual context code size

**Expect actual costs to be:**
- **50-150% of estimate** for typical repositories
- **Higher if:** Many complex vulnerabilities found
- **Lower if:** Few vulnerabilities, simple code

---

## Cost Optimization Tips

### 1. Use Dry-Run First
```bash
vulnhuntr -r /path/to/repo --dry-run
```
- See which files are most expensive
- Decide if full scan is worth it

### 2. Target Specific Files
```bash
vulnhuntr -r /path/to/repo -a src/api/routes.py
```
- Analyze only high-risk files
- Much cheaper than full repo scan

### 3. Set Conservative Budget
```bash
vulnhuntr -r /path/to/repo --budget 10.00
```
- Start low, increase if needed
- Resume with higher budget later

### 4. Use Cheaper Models for Initial Scans
```bash
vulnhuntr -r /path/to/repo -l gpt --budget 5.00
# Then use Claude for detailed analysis of findings
```

### 5. Configure Per-File/Iteration Limits
```yaml
cost:
  max_cost_per_file: 1.0
  max_cost_per_iteration: 0.30
```
- Prevents runaway costs on complex files
- Still analyzes most files normally

### 6. Use Local Models (Ollama) for Testing
```bash
vulnhuntr -r /path/to/repo -l ollama
```
- No API costs
- Good for testing configurations
- Lower accuracy than Claude/GPT-4

---

## Troubleshooting

### "Budget limit reached" - What happened?
- Your `--budget` limit was hit
- Analysis stopped to prevent overspending
- **Solution:** Resume with higher budget: `--resume --budget 20.00`

### Costs higher than dry-run estimate
- Dry-run is a conservative estimate, not exact
- Complex vulnerabilities require more iterations
- Fetched context code larger than estimated
- **Solution:** Normal variation (50-150% of estimate)

### How to reduce costs on large repository?
1. Use `--dry-run` to identify expensive files
2. Use `-a` flag to target specific files first
3. Set `max_cost_per_file` limit
4. Consider using GPT-3.5-turbo for initial screening

### Checkpoint not resuming correctly
- Ensure checkpoint file exists: `ls -la .vulnhuntr_checkpoint`
- Check checkpoint is from same repository
- Verify file paths haven't changed
- **Solution:** Delete checkpoint to restart: `rm .vulnhuntr_checkpoint`

---

## API Reference

### CostTracker

```python
from vulnhuntr.cost_tracker import CostTracker

tracker = CostTracker()

# Track a call
cost = tracker.track_call(
    input_tokens=1000,
    output_tokens=500,
    model="claude-3-5-sonnet-20241022",
    file_path="api/routes.py",
)

# Get summary
summary = tracker.get_summary()
print(f"Total cost: ${summary['total_cost_usd']:.2f}")
```

### BudgetEnforcer

```python
from vulnhuntr.cost_tracker import BudgetEnforcer

enforcer = BudgetEnforcer(
    max_budget_usd=50.0,
    warning_threshold=0.8,
    max_cost_per_file=2.0,
    max_cost_per_iteration=0.50,
)

# Check if can continue
if not enforcer.check(current_cost):
    print("Budget exceeded!")
```

### Dry-Run Estimation

```python
from vulnhuntr.cost_tracker import estimate_analysis_cost
from pathlib import Path

files = [Path("api/routes.py"), Path("models/user.py")]
estimate = estimate_analysis_cost(files, model="claude-3-5-sonnet-20241022")

print(f"Estimated cost: ${estimate['estimated_cost_usd']:.2f}")
print(f"Range: ${estimate['estimated_cost_range']['low']:.2f} - "
      f"${estimate['estimated_cost_range']['high']:.2f}")
```

---

## Best Practices

1. ✅ **Always run dry-run first** on new repositories
2. ✅ **Set a budget** to prevent overspending
3. ✅ **Use checkpoints** to avoid re-running expensive analyses
4. ✅ **Configure per-file limits** for large repos
5. ✅ **Review cost summary** to optimize future scans
6. ✅ **Start with specific files** before full repo scan
7. ✅ **Use cheaper models** for initial screening
8. ❌ **Don't run without budget** on untrusted/large repos
9. ❌ **Don't disable checkpointing** for expensive scans
10. ❌ **Don't ignore dry-run estimates** - they're conservative but useful

---

## See Also

- [QUICKSTART.md](../QUICKSTART.md) - Getting started guide
- [REPORTING.md](REPORTING.md) - Report generation and export
- [INTEGRATIONS.md](INTEGRATIONS.md) - CI/CD and tool integrations
- [Development Path: Cost Management](development_path/01_cost_management.md) - Implementation details

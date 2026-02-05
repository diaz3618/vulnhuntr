# Development Path: Cost Management

**Priority**: HIGH - Immediate Impact  
**Complexity**: Medium  
**Estimated Effort**: 2-3 weeks  
**Dependencies**: None

---

## Current State Analysis

### Existing Implementation
- **Location**: `vulnhuntr/__main__.py`, `vulnhuntr/LLMs.py`
- **Token Configuration**: Fixed `max_tokens=8192` (lines 395, 464 in __main__.py)
- **LLM Clients**: Claude, ChatGPT, Ollama implementations with basic error handling
- **Logging**: structlog with JSON output to `vulnhuntr.log`
- **No Cost Tracking**: Currently no mechanism to track API costs, token usage, or provide cost estimates

### Problem Statement
From README and user feedback:
- Can rack up "hefty bills" on large repositories
- No way to estimate costs before running analysis
- No checkpointing - interrupted analyses must restart from scratch
- No budget limits or alerts
- Users have no visibility into token consumption

---

## Technical Architecture

### 1. Token Usage Tracking

**Implementation Location**: New file `vulnhuntr/cost_tracker.py`

```python
from dataclasses import dataclass
from typing import Dict, List
import json
from pathlib import Path

@dataclass
class TokenUsage:
    """Track token usage for a single LLM call"""
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    model: str
    timestamp: str
    file_analyzed: str
    cost_usd: float

class CostTracker:
    """Tracks and reports LLM API costs"""
    
    # Pricing per 1K tokens (update regularly)
    PRICING = {
        "claude-3-5-sonnet-20241022": {"input": 0.003, "output": 0.015},
        "claude-sonnet-4-5": {"input": 0.003, "output": 0.015},
        "gpt-4-turbo-preview": {"input": 0.01, "output": 0.03},
        "chatgpt-4o-latest": {"input": 0.005, "output": 0.015},
        "ollama": {"input": 0.0, "output": 0.0}  # Local
    }
    
    def __init__(self, checkpoint_file: Path = None):
        self.usage_history: List[TokenUsage] = []
        self.checkpoint_file = checkpoint_file
        self.total_cost = 0.0
        
    def track_call(self, prompt_tokens: int, completion_tokens: int, 
                   model: str, file: str) -> float:
        """Track a single LLM call and return its cost"""
        # Calculate cost
        pricing = self._get_pricing(model)
        cost = (prompt_tokens / 1000 * pricing["input"] + 
                completion_tokens / 1000 * pricing["output"])
        
        # Record usage
        usage = TokenUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
            model=model,
            timestamp=datetime.now().isoformat(),
            file_analyzed=file,
            cost_usd=cost
        )
        
        self.usage_history.append(usage)
        self.total_cost += cost
        
        # Save checkpoint
        if self.checkpoint_file:
            self._save_checkpoint()
        
        return cost
    
    def get_summary(self) -> Dict:
        """Get cost summary statistics"""
        return {
            "total_calls": len(self.usage_history),
            "total_tokens": sum(u.total_tokens for u in self.usage_history),
            "total_cost_usd": round(self.total_cost, 4),
            "files_analyzed": len(set(u.file_analyzed for u in self.usage_history)),
            "by_model": self._breakdown_by_model()
        }
```

**Integration Points**:
- Modify `LLM.chat()` method to extract token counts from responses
- Claude: `response.usage.input_tokens`, `response.usage.output_tokens`
- ChatGPT: `response.usage.prompt_tokens`, `response.usage.completion_tokens`
- Pass to `CostTracker.track_call()` after each LLM interaction

### 2. Dry-Run Mode

**Implementation Location**: `vulnhuntr/__main__.py`

Add new CLI argument:
```python
parser.add_argument('--dry-run', action='store_true',
                   help='Estimate costs without running actual analysis')
parser.add_argument('--budget', type=float, default=None,
                   help='Maximum budget in USD (analysis stops if exceeded)')
```

**Dry-Run Logic**:
```python
def estimate_cost(repo_path: Path, llm_model: str) -> Dict:
    """Estimate analysis cost without running LLM calls"""
    
    # 1. Discover files (same as actual run)
    repo = RepoOps(repo_path)
    files = list(repo.scan_repo())
    
    # 2. Estimate tokens per file
    estimated_tokens = []
    for file in files:
        content = file.read_text()
        
        # Rough token estimate: ~4 chars per token
        file_tokens = len(content) / 4
        
        # Initial analysis: file + system prompt (~1K) + response (~2K)
        initial_est = file_tokens + 1000 + 2000
        
        # Secondary analysis: 7 iterations * (file + context) * vuln types
        # Assume avg 3 vuln types, avg 5 iterations, avg 5K context per iteration
        secondary_est = 3 * 5 * (file_tokens + 5000 + 2000)
        
        total_est = initial_est + secondary_est
        estimated_tokens.append(total_est)
    
    # 3. Calculate cost
    total_tokens = sum(estimated_tokens)
    pricing = CostTracker.PRICING.get(llm_model, {"input": 0.01, "output": 0.03})
    
    # Assume 60% input, 40% output (based on observed ratios)
    input_tokens = total_tokens * 0.6
    output_tokens = total_tokens * 0.4
    
    estimated_cost = (input_tokens / 1000 * pricing["input"] + 
                     output_tokens / 1000 * pricing["output"])
    
    return {
        "files": len(files),
        "estimated_total_tokens": int(total_tokens),
        "estimated_cost_usd": round(estimated_cost, 2),
        "per_file_average_usd": round(estimated_cost / len(files), 4),
        "pricing_model": llm_model
    }
```

### 3. Checkpointing System

**Implementation Location**: New file `vulnhuntr/checkpoint.py`

```python
class AnalysisCheckpoint:
    """Save and resume analysis progress"""
    
    def __init__(self, checkpoint_dir: Path):
        self.checkpoint_dir = checkpoint_dir
        self.checkpoint_file = checkpoint_dir / "checkpoint.json"
        self.results_file = checkpoint_dir / "results.json"
        
    def save(self, completed_files: List[str], results: List[Dict], 
             cost_tracker: CostTracker):
        """Save current progress"""
        checkpoint_data = {
            "timestamp": datetime.now().isoformat(),
            "completed_files": completed_files,
            "results": [r.model_dump() for r in results],
            "cost_summary": cost_tracker.get_summary()
        }
        
        self.checkpoint_file.write_text(json.dumps(checkpoint_data, indent=2))
        log.info("Checkpoint saved", files_completed=len(completed_files))
    
    def load(self) -> Dict:
        """Load previous checkpoint if exists"""
        if not self.checkpoint_file.exists():
            return None
        
        data = json.loads(self.checkpoint_file.read_text())
        log.info("Checkpoint loaded", files_completed=len(data["completed_files"]))
        return data
    
    def resume(self, all_files: List[Path]) -> List[Path]:
        """Get list of remaining files to analyze"""
        checkpoint = self.load()
        if not checkpoint:
            return all_files
        
        completed = set(checkpoint["completed_files"])
        remaining = [f for f in all_files if str(f) not in completed]
        
        print(f"[*] Resuming from checkpoint: {len(completed)} files completed, "
              f"{len(remaining)} remaining")
        
        return remaining
```

**Integration in __main__.py**:
```python
# Initialize checkpoint
checkpoint_dir = Path(".vulnhuntr_checkpoint")
checkpoint_dir.mkdir(exist_ok=True)
checkpoint = AnalysisCheckpoint(checkpoint_dir)

# Load previous progress
remaining_files = checkpoint.resume(all_files)

# Analyze with periodic checkpointing
for i, file in enumerate(remaining_files):
    try:
        result = analyze_file(file, llm, ...)
        results.append(result)
        
        # Save checkpoint every 5 files
        if i % 5 == 0:
            checkpoint.save(
                completed_files=[str(f) for f in all_files if f not in remaining_files[i:]],
                results=results,
                cost_tracker=cost_tracker
            )
    except Exception as e:
        log.error("Analysis failed", file=file, error=str(e))
        # Save checkpoint on failure
        checkpoint.save(...)
        raise
```

### 4. Budget Alerts and Hard Limits

**Implementation Location**: `vulnhuntr/cost_tracker.py`

```python
class BudgetEnforcer:
    """Enforce budget limits during analysis"""
    
    def __init__(self, max_budget_usd: float, warning_threshold: float = 0.8):
        self.max_budget = max_budget_usd
        self.warning_threshold = warning_threshold
        self.warned = False
        
    def check(self, current_cost: float) -> bool:
        """Check if budget exceeded. Returns True to continue, False to stop."""
        
        # Warning at 80% of budget
        if not self.warned and current_cost >= self.max_budget * self.warning_threshold:
            print(f"\n[!] WARNING: {current_cost:.2f} USD spent "
                  f"({current_cost/self.max_budget*100:.0f}% of ${self.max_budget:.2f} budget)")
            self.warned = True
        
        # Hard stop at budget limit
        if current_cost >= self.max_budget:
            print(f"\n[!] BUDGET EXCEEDED: {current_cost:.2f} USD spent "
                  f"(limit: ${self.max_budget:.2f})")
            print("[!] Analysis stopped to prevent further costs")
            return False
        
        return True
```

**Integration**:
```python
# In __main__.py
if args.budget:
    budget_enforcer = BudgetEnforcer(args.budget)

for file in files:
    # ... analyze file ...
    
    # Check budget after each file
    if args.budget and not budget_enforcer.check(cost_tracker.total_cost):
        log.warning("Budget exceeded, stopping analysis")
        break
```

### 5. Cost-Aware Context Limiting

**Implementation Location**: `vulnhuntr/__main__.py` (modify iteration loop)

```python
def should_continue_iteration(iteration: int, context_size: int, 
                             file_size: int, budget_remaining: float) -> bool:
    """Decide whether to continue iterating based on cost concerns"""
    
    # Estimate cost of next iteration
    # Context size in chars / 4 = approx tokens
    estimated_tokens = (file_size + context_size) / 4
    estimated_cost = estimated_tokens / 1000 * 0.018  # Avg price
    
    # Stop if next iteration would exceed remaining budget
    if budget_remaining and estimated_cost > budget_remaining:
        log.info("Stopping iteration due to budget constraints",
                iteration=iteration,
                estimated_cost=estimated_cost,
                budget_remaining=budget_remaining)
        return False
    
    # Stop if context is getting too large (diminishing returns)
    if context_size > 100000:  # ~25K tokens
        log.info("Stopping iteration due to large context",
                iteration=iteration,
                context_size=context_size)
        return False
    
    return iteration < 7  # Max 7 iterations
```

---

## Implementation Plan

### Phase 1: Token Tracking (Week 1)
1. Create `cost_tracker.py` with `CostTracker` class
2. Update pricing table with current API rates
3. Modify `LLM.chat()` methods to extract token counts:
   - Claude: Extract from `response.usage`
   - ChatGPT: Extract from `response.usage`
   - Ollama: Return 0 (local, no cost)
4. Integrate `CostTracker` into main analysis loop
5. Add cost summary to final output
6. **Testing**: Run on small repo, verify token counts match API dashboard

### Phase 2: Dry-Run Mode (Week 1-2)
1. Implement `estimate_cost()` function
2. Add `--dry-run` CLI flag
3. Display cost estimate with breakdown:
   - Files to analyze
   - Estimated tokens
   - Estimated cost range (min/max scenarios)
   - Per-file average
4. **Testing**: Compare dry-run estimates with actual costs on known repos

### Phase 3: Checkpointing (Week 2)
1. Create `checkpoint.py` with `AnalysisCheckpoint` class
2. Implement save/load/resume logic
3. Integrate into main analysis loop:
   - Save every N files
   - Save on error
   - Save on keyboard interrupt (Ctrl+C)
4. Add `--resume` flag to continue from checkpoint
5. **Testing**: Interrupt analysis mid-run, verify resume works correctly

### Phase 4: Budget Management (Week 2-3)
1. Implement `BudgetEnforcer` class
2. Add `--budget` CLI flag
3. Add warning at 80% threshold
4. Add hard stop at 100%
5. Integrate with checkpoint (save before stopping)
6. **Testing**: Set low budget, verify stops correctly

### Phase 5: Cost-Aware Limiting (Week 3)
1. Implement `should_continue_iteration()` function
2. Add context size tracking in iteration loop
3. Add budget-aware iteration limits
4. Add configurable max context size
5. **Testing**: Compare results with/without limiting, verify quality maintained

### Phase 6: Reporting & Monitoring (Week 3)
1. Create cost report generation:
   - Total cost breakdown
   - Per-file costs
   - Time-series cost tracking
   - Model comparison
2. Add real-time cost display during analysis (progress bar with cost)
3. Export cost data to CSV/JSON for analysis
4. **Testing**: Run multiple analyses, verify reports are accurate

---

## Configuration File Support

**New file**: `.vulnhuntr.yaml` (optional, defaults if not present)

```yaml
# Cost Management Configuration
cost:
  # Maximum budget in USD (null = no limit)
  max_budget: 50.0
  
  # Warn when this percentage of budget is used
  warning_threshold: 0.8
  
  # Stop analysis if single file exceeds this cost
  max_cost_per_file: 5.0
  
  # Maximum context size in characters (prevents runaway token usage)
  max_context_size: 100000
  
  # Maximum iterations for secondary analysis (default 7)
  max_iterations: 7

# Checkpoint Configuration  
checkpoint:
  # Enable automatic checkpointing
  enabled: true
  
  # Save checkpoint every N files
  save_frequency: 5
  
  # Directory for checkpoint files
  directory: .vulnhuntr_checkpoint
```

**Loading Configuration**:
```python
import yaml

def load_config() -> Dict:
    """Load configuration from .vulnhuntr.yaml if exists"""
    config_file = Path.cwd() / ".vulnhuntr.yaml"
    
    if config_file.exists():
        with open(config_file) as f:
            return yaml.safe_load(f)
    
    # Default config
    return {
        "cost": {
            "max_budget": None,
            "warning_threshold": 0.8,
            "max_cost_per_file": None,
            "max_context_size": 100000,
            "max_iterations": 7
        },
        "checkpoint": {
            "enabled": True,
            "save_frequency": 5,
            "directory": ".vulnhuntr_checkpoint"
        }
    }
```

---

## Testing Strategy

### Unit Tests
```python
# tests/test_cost_tracker.py
def test_token_tracking():
    tracker = CostTracker()
    cost = tracker.track_call(1000, 500, "claude-3-5-sonnet-20241022", "test.py")
    assert cost == (1000/1000 * 0.003) + (500/1000 * 0.015)
    assert tracker.total_cost == cost

def test_budget_enforcement():
    enforcer = BudgetEnforcer(max_budget_usd=10.0)
    assert enforcer.check(5.0) == True  # Continue
    assert enforcer.check(10.5) == False  # Stop

# tests/test_checkpoint.py
def test_checkpoint_save_load(tmp_path):
    checkpoint = AnalysisCheckpoint(tmp_path)
    checkpoint.save(["file1.py", "file2.py"], [], CostTracker())
    
    loaded = checkpoint.load()
    assert len(loaded["completed_files"]) == 2
```

### Integration Tests
- Run full analysis with checkpointing enabled
- Interrupt mid-analysis, verify resume works
- Set budget limit, verify stops correctly
- Compare dry-run estimates with actual costs

### Manual Testing Checklist
- [ ] Dry-run shows reasonable cost estimates
- [ ] Budget warning appears at 80%
- [ ] Analysis stops at 100% budget
- [ ] Checkpoint saves and resumes correctly
- [ ] Cost reports are accurate (compare with API dashboard)
- [ ] Performance impact is minimal (<5% overhead)

---

## Success Metrics

1. **Cost Visibility**: Users can estimate costs before running analysis
2. **Budget Control**: Analysis stops before exceeding budget
3. **Resumability**: Interrupted analyses can resume from checkpoint
4. **Cost Reporting**: Clear breakdown of costs per file, model, and time
5. **Performance**: Token tracking adds <5% overhead

---

## Documentation Updates

### README.md
- Add cost management section
- Explain `--dry-run`, `--budget`, `--resume` flags
- Provide cost estimation guidelines
- Link to pricing documentation

### QUICKSTART.md
- Add cost estimation step before first run
- Recommend starting with `--dry-run`
- Explain checkpoint system

### New: COST_MANAGEMENT.md
- Detailed guide on cost optimization
- Best practices for large repositories
- Pricing comparison between providers
- Tips for reducing token usage

---

## Future Enhancements

1. **Token Optimization**: Implement intelligent context pruning to reduce token usage
2. **Cost Prediction ML**: Use historical data to predict costs more accurately
3. **Parallel Analysis with Budget**: Distribute budget across parallel workers
4. **Cloud Cost Integration**: Integrate with cloud billing APIs for real-time cost tracking
5. **Cost-Quality Tradeoffs**: Options to reduce analysis depth for lower costs

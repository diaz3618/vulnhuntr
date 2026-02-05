# Development Path: Performance Optimization

**Priority**: MEDIUM - Important but not urgent  
**Complexity**: Medium  
**Estimated Effort**: 3-4 weeks  
**Dependencies**: None (but synergizes with Cost Management)

---

## Current State Analysis

### Performance Bottlenecks

**From codebase analysis**:

1. **Sequential File Processing** (`__main__.py` lines 300-490):
   - Files analyzed one at a time
   - No parallelization
   - Large repos take hours

2. **No Caching** (entire codebase):
   - Symbol definitions fetched repeatedly
   - Same functions analyzed multiple times
   - LLM responses never cached

3. **Full File Content to LLM** (`__main__.py` lines 395, 464):
   - Sends entire file even if only analyzing small section
   - No intelligent context pruning
   - Max 8192 tokens per call (can hit limit)

4. **Repeated Symbol Resolution** (`symbol_finder.py`):
   - Three-tier search performed every time
   - Jedi parsing overhead
   - No memoization

### Benchmarks (Estimated on 100-file Python repo)

| Metric | Current | Target (After Optimization) |
|--------|---------|----------------------------|
| Analysis Time | 2-3 hours | 20-30 minutes |
| API Calls | ~500-700 | ~200-300 (via caching) |
| API Cost | $50-$100 | $20-$40 |
| Memory Usage | 200-500MB | 200-500MB (same) |
| CPU Usage | 5-10% (single-core) | 60-80% (multi-core) |

---

## Technical Architecture

### 1. Parallel File Analysis

**Implementation**: `vulnhuntr/parallel.py`

```python
from multiprocessing import Pool, Manager, cpu_count
from typing import List, Dict
import structlog

log = structlog.get_logger()

class ParallelAnalyzer:
    """Parallel file analysis with shared caching"""
    
    def __init__(self, num_workers: int = None):
        # Use CPU count - 1 (leave one core for system)
        self.num_workers = num_workers or max(1, cpu_count() - 1)
        self.manager = Manager()
        self.cache = self.manager.dict()  # Shared cache across workers
        
    def analyze_files(self, files: List[Path], llm_config: Dict, 
                     repo_path: Path) -> List[Dict]:
        """Analyze files in parallel"""
        
        print(f"[*] Using {self.num_workers} parallel workers")
        
        # Create worker pool
        with Pool(processes=self.num_workers) as pool:
            # Prepare work items
            work_items = [
                (file, llm_config, repo_path, self.cache)
                for file in files
            ]
            
            # Map work to pool (with progress tracking)
            results = []
            for result in pool.imap_unordered(analyze_file_worker, work_items):
                results.append(result)
                print(f"[*] Completed {len(results)}/{len(files)} files")
        
        return results

def analyze_file_worker(args):
    """Worker function for parallel analysis"""
    file, llm_config, repo_path, shared_cache = args
    
    try:
        # Initialize LLM (each worker gets own instance)
        llm = initialize_llm(llm_config)
        
        # Initialize language support
        lang_support = registry.get_support('python', repo_path)
        
        # Analyze file (with access to shared cache)
        result = analyze_file_with_cache(file, llm, lang_support, shared_cache)
        
        return result
        
    except Exception as e:
        log.error("Worker failed", file=str(file), error=str(e))
        return {
            'file': str(file),
            'error': str(e),
            'vulnerability_found': False
        }
```

**Integration**:
```python
# In __main__.py
if args.parallel:
    analyzer = ParallelAnalyzer(num_workers=args.workers)
    results = analyzer.analyze_files(entry_point_files, llm_config, repo_path)
else:
    # Sequential (current implementation)
    results = [analyze_file(f, llm, lang_support) for f in entry_point_files]
```

**CLI Arguments**:
```python
parser.add_argument('--parallel', action='store_true',
                   help='Enable parallel file analysis')
parser.add_argument('--workers', type=int, default=None,
                   help='Number of parallel workers (default: CPU count - 1)')
```

### 2. Multi-Level Caching System

**Implementation**: `vulnhuntr/cache.py`

```python
from typing import Dict, Optional, Any
from pathlib import Path
import json
import hashlib
from datetime import datetime, timedelta

class AnalysisCache:
    """Multi-level caching for symbols, LLM responses, and analyses"""
    
    def __init__(self, cache_dir: Path = None):
        self.cache_dir = cache_dir or Path(".vulnhuntr_cache")
        self.cache_dir.mkdir(exist_ok=True)
        
        # In-memory caches
        self.symbol_cache: Dict[str, Dict] = {}
        self.llm_cache: Dict[str, str] = {}
        
        # Persistent cache files
        self.symbol_cache_file = self.cache_dir / "symbols.json"
        self.llm_cache_file = self.cache_dir / "llm_responses.json"
        
        self._load_caches()
    
    def _load_caches(self):
        """Load caches from disk"""
        if self.symbol_cache_file.exists():
            self.symbol_cache = json.loads(self.symbol_cache_file.read_text())
        
        if self.llm_cache_file.exists():
            self.llm_cache = json.loads(self.llm_cache_file.read_text())
    
    def _save_caches(self):
        """Save caches to disk"""
        self.symbol_cache_file.write_text(json.dumps(self.symbol_cache, indent=2))
        self.llm_cache_file.write_text(json.dumps(self.llm_cache, indent=2))
    
    def get_symbol(self, symbol_name: str, code_line: str, 
                   file_hash: str) -> Optional[Dict]:
        """Get cached symbol definition"""
        cache_key = f"{file_hash}:{symbol_name}:{code_line}"
        return self.symbol_cache.get(cache_key)
    
    def cache_symbol(self, symbol_name: str, code_line: str, 
                    file_hash: str, definition: Dict):
        """Cache symbol definition"""
        cache_key = f"{file_hash}:{symbol_name}:{code_line}"
        self.symbol_cache[cache_key] = definition
        self._save_caches()
    
    def get_llm_response(self, prompt: str, model: str) -> Optional[str]:
        """Get cached LLM response"""
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()
        cache_key = f"{model}:{prompt_hash}"
        
        cached = self.llm_cache.get(cache_key)
        if cached:
            # Check if cache is expired (7 days)
            if datetime.now() - datetime.fromisoformat(cached['timestamp']) < timedelta(days=7):
                return cached['response']
        
        return None
    
    def cache_llm_response(self, prompt: str, model: str, response: str):
        """Cache LLM response"""
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()
        cache_key = f"{model}:{prompt_hash}"
        
        self.llm_cache[cache_key] = {
            'response': response,
            'timestamp': datetime.now().isoformat()
        }
        self._save_caches()
    
    def clear(self):
        """Clear all caches"""
        self.symbol_cache = {}
        self.llm_cache = {}
        self._save_caches()
```

**Integration in Symbol Extraction**:
```python
# In symbol_finder.py
class SymbolExtractor:
    def __init__(self, repo_path: Path, cache: AnalysisCache = None):
        self.repo_path = repo_path
        self.cache = cache or AnalysisCache()
        # ... existing init ...
    
    def extract(self, symbol_name: str, code_line: str, files: List) -> Dict:
        # Check cache first
        file_hash = self._compute_files_hash(files)
        cached = self.cache.get_symbol(symbol_name, code_line, file_hash)
        if cached:
            log.debug("Symbol cache hit", symbol=symbol_name)
            return cached
        
        # Not cached, perform extraction
        result = self._extract_symbol(symbol_name, code_line, files)
        
        # Cache result
        if result:
            self.cache.cache_symbol(symbol_name, code_line, file_hash, result)
        
        return result
```

**Integration in LLM Calls**:
```python
# In LLMs.py
class LLM:
    def __init__(self, system_prompt: str = "", cache: AnalysisCache = None):
        self.cache = cache or AnalysisCache()
        # ... existing init ...
    
    def chat(self, user_prompt: str, response_model: BaseModel = None, 
            max_tokens: int = 8192, use_cache: bool = True) -> Union[BaseModel, str]:
        
        # Check cache (only if use_cache=True)
        if use_cache:
            cached_response = self.cache.get_llm_response(user_prompt, self.model)
            if cached_response:
                log.info("LLM cache hit", model=self.model)
                if response_model:
                    return self._validate_response(cached_response, response_model)
                return cached_response
        
        # Not cached, make actual API call
        # ... existing chat implementation ...
        
        # Cache response before returning
        if use_cache:
            self.cache.cache_llm_response(user_prompt, self.model, response_text)
        
        return response_text
```

### 3. Intelligent Context Pruning

**Implementation**: `vulnhuntr/context_pruner.py`

```python
class ContextPruner:
    """Intelligently reduce context size while preserving relevant code"""
    
    def prune_file_content(self, file_content: str, 
                          entry_point_lines: List[int]) -> str:
        """Keep only relevant sections of file"""
        
        lines = file_content.split('\n')
        relevant_lines = set()
        
        # Include entry point functions with N lines context
        for entry_line in entry_point_lines:
            start = max(0, entry_line - 10)
            end = min(len(lines), entry_line + 50)
            relevant_lines.update(range(start, end))
        
        # Include all imports (needed for context)
        for i, line in enumerate(lines):
            if line.strip().startswith(('import ', 'from ')):
                relevant_lines.add(i)
        
        # Build pruned content
        pruned_lines = []
        in_relevant_section = False
        
        for i, line in enumerate(lines):
            if i in relevant_lines:
                if not in_relevant_section:
                    pruned_lines.append(f"# ... [lines {i-10}-{i} omitted] ...")
                pruned_lines.append(line)
                in_relevant_section = True
            else:
                in_relevant_section = False
        
        return '\n'.join(pruned_lines)
    
    def prune_context_definitions(self, definitions: List[Dict], 
                                  max_size: int = 20000) -> List[Dict]:
        """Keep only most relevant context definitions"""
        
        # Sort by relevance (heuristic: shorter = more focused)
        definitions.sort(key=lambda d: len(d['source']))
        
        # Add definitions until size limit
        pruned = []
        total_size = 0
        
        for definition in definitions:
            size = len(definition['source'])
            if total_size + size > max_size:
                break
            pruned.append(definition)
            total_size += size
        
        return pruned
```

### 4. Incremental Analysis

**Implementation**: `vulnhuntr/incremental.py`

```python
import git

class IncrementalAnalyzer:
    """Analyze only changed files since last run"""
    
    def __init__(self, repo_path: Path):
        self.repo_path = repo_path
        self.git_repo = git.Repo(repo_path)
        self.state_file = repo_path / ".vulnhuntr_state.json"
    
    def get_changed_files(self, since_commit: str = None) -> List[Path]:
        """Get files changed since last analysis"""
        
        # Load last analyzed commit
        if self.state_file.exists():
            state = json.loads(self.state_file.read_text())
            since_commit = since_commit or state.get('last_commit')
        
        if not since_commit:
            # First run, analyze all files
            return list(self.repo_path.rglob("*.py"))
        
        # Get changed files since commit
        diff = self.git_repo.commit(since_commit).diff(None)
        
        changed_files = []
        for item in diff:
            file_path = self.repo_path / item.a_path
            if file_path.exists() and file_path.suffix == '.py':
                changed_files.append(file_path)
        
        print(f"[*] Incremental analysis: {len(changed_files)} files changed")
        
        return changed_files
    
    def save_state(self):
        """Save current commit as last analyzed"""
        state = {
            'last_commit': self.git_repo.head.commit.hexsha,
            'timestamp': datetime.now().isoformat()
        }
        self.state_file.write_text(json.dumps(state, indent=2))
```

---

## Implementation Plan

### Phase 1: Caching (Week 1-2)
1. Implement `AnalysisCache` class
2. Integrate with `SymbolExtractor`
3. Integrate with `LLM` classes
4. Add cache management CLI commands
5. **Testing**: Verify cache hit rates, measure speedup

### Phase 2: Parallel Processing (Week 2-3)
1. Implement `ParallelAnalyzer` class
2. Add `--parallel` and `--workers` flags
3. Test with shared cache
4. Handle worker failures gracefully
5. **Testing**: Compare sequential vs parallel times

### Phase 3: Context Pruning (Week 3)
1. Implement `ContextPruner` class
2. Integrate into prompt building
3. Test accuracy impact
4. Tune pruning parameters
5. **Testing**: Verify no accuracy degradation

### Phase 4: Incremental Analysis (Week 4)
1. Implement `IncrementalAnalyzer` class
2. Add `--incremental` flag
3. Integrate with git
4. Test on repos with history
5. **Testing**: Verify only changed files analyzed

---

## CLI Interface

```bash
# Enable parallel analysis
vulnhuntr -r /repo --parallel --workers 4

# Use caching
vulnhuntr -r /repo --cache

# Clear cache
vulnhuntr --clear-cache

# Incremental analysis (only changed files)
vulnhuntr -r /repo --incremental

# All optimizations combined
vulnhuntr -r /repo --parallel --workers 8 --cache --incremental
```

---

## Configuration (.vulnhuntr.yaml)

```yaml
performance:
  # Parallel processing
  parallel:
    enabled: false
    workers: null  # null = auto (CPU count - 1)
  
  # Caching
  cache:
    enabled: true
    directory: .vulnhuntr_cache
    ttl_days: 7  # Cache expiration
  
  # Context pruning
  pruning:
    enabled: true
    max_context_size: 20000  # characters
    entry_point_context_lines: 50
  
  # Incremental analysis
  incremental:
    enabled: false
    state_file: .vulnhuntr_state.json
```

---

## Success Metrics

1. **Speed**: 4-6x faster with parallel + caching
2. **Cost**: 40-60% reduction via caching
3. **Accuracy**: <5% degradation with pruning
4. **Scalability**: Handle 1000+ file repos efficiently

---

## Documentation Updates

- README.md: Performance optimization section
- New: PERFORMANCE.md: Detailed optimization guide
- QUICKSTART.md: Recommend --parallel for large repos

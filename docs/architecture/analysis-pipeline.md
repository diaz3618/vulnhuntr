# Analysis Pipeline

## Data Flow

### Complete Analysis Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. INITIALIZATION                                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  CLI Args ──> Parse Arguments ──> Initialize RepoOps            │
│                                                                 │
│  Discover Files ──> Filter by Type ──> Create File List         │
│                    (network/user)                               │
│                                                                 │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             v
┌─────────────────────────────────────────────────────────────────┐
│ 2. README SUMMARIZATION (Optional)                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  README.md ──> LLM Summary ──> Add to System Prompt             │
│                                                                 │
│  <readme_content>...</readme_content> ──>                       │
│  <readme_summary>...</readme_summary>                           │
│                                                                 │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             v
┌─────────────────────────────────────────────────────────────────┐
│ 3. INITIAL ANALYSIS (Per File)                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Prompt Structure:                                        │   │
│  │   <file_code>                                            │   │
│  │     file_path: target.py                                 │   │
│  │     file_source: [entire file content]                   │   │
│  │   </file_code>                                           │   │
│  │   <instructions>INITIAL_ANALYSIS_PROMPT</instructions>   │   │
│  │   <analysis_approach>...</analysis_approach>             │   │
│  │   <previous_analysis></previous_analysis>                │   │
│  │   <guidelines>...</guidelines>                           │   │
│  │   <response_format>Response.json_schema</response_format>│   │
│  └──────────────────────────────────────────────────────────┘   │
│                            │                                    │
│                            v                                    │
│                     LLM.chat()                                  │
│                     max_tokens=8192                             │
│                            │                                    │
│                            v                                    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ Response (JSON):                                        │    │
│  │   scratchpad: "step-by-step analysis"                   │    │
│  │   analysis: "final analysis"                            │    │
│  │   poc: "exploit code"                                   │    │
│  │   confidence_score: 0-10                                │    │
│  │   vulnerability_types: [SQLI, XSS, ...]                 │    │
│  │   context_code: [                                       │    │
│  │     {name: "func1", reason: "...", code_line: "..."},   │    │
│  │     {name: "Class2", reason: "...", code_line: "..."}   │    │
│  │   ]                                                     │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                 │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             v
┌─────────────────────────────────────────────────────────────────┐
│ 4. SECONDARY ANALYSIS (Per Vulnerability Type)                  │
│    Iterative Context Expansion (Up to 7 iterations)             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  IF confidence_score > 0 AND vulnerability_types exist:         │
│                                                                 │
│  FOR EACH vulnerability_type IN vulnerability_types:            │
│    ┌──────────────────────────────────────────────────┐         │
│    │ Iteration Loop (i = 0 to 6):                     │         │
│    │                                                  │         │
│    │ ┌─────────────────────────────────────────────┐  │         │
│    │ │ IF i > 0:                                   │  │         │
│    │ │   FOR EACH requested context_code:          │  │         │
│    │ │     SymbolExtractor.extract() ──>           │  │         │
│    │ │       Jedi search ──> Code definition       │  │         │
│    │ │                                             │  │         │
│    │ │   Build CodeDefinitions XML                 │  │         │
│    │ └─────────────────────────────────────────────┘  │         │
│    │                  │                               │         │
│    │                  v                               │         │
│    │ ┌─────────────────────────────────────────────┐  │         │
│    │ │ Prompt Structure:                           │  │         │
│    │ │   <file_code>original file</file_code>      │  │         │
│    │ │   <context_code>                            │  │         │
│    │ │     <code name="..." source="..."/>         │  │         │
│    │ │     <code name="..." source="..."/>         │  │         │
│    │ │   </context_code>                           │  │         │
│    │ │   <example_bypasses>vuln-specific</...>     │  │         │
│    │ │   <instructions>VULN_SPECIFIC_PROMPT</...>  │  │         │
│    │ │   <analysis_approach>...</...>              │  │         │
│    │ │   <previous_analysis>prev iteration</...>   │  │         │
│    │ │   <guidelines>...</guidelines>              │  │         │
│    │ │   <response_format>...</response_format>    │  │         │
│    │ └─────────────────────────────────────────────┘  │         │
│    │                  │                               │         │
│    │                  v                               │         │
│    │            LLM.chat()                            │         │
│    │            max_tokens=8192                       │         │
│    │                  │                               │         │
│    │                  v                               │         │
│    │ ┌─────────────────────────────────────────────┐  │         │
│    │ │ Response with new context_code requests     │  │         │
│    │ └─────────────────────────────────────────────┘  │         │
│    │                  │                               │         │
│    │ ┌────────────────┴────────────────────────────┐  │         │
│    │ │ Termination Conditions:                     │  │         │
│    │ │  - No context_code requested? ──> BREAK     │  │         │
│    │ │  - No new context added? ──> BREAK (once)   │  │         │
│    │ │  - Same context 2x? ──> BREAK               │  │         │
│    │ └─────────────────────────────────────────────┘  │         │
│    │                  │                               │         │
│    │                  v                               │         │
│    │         Next iteration or exit                   │         │
│    └──────────────────────────────────────────────────┘         │
│                                                                 │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             v
┌─────────────────────────────────────────────────────────────────┐
│ 5. OUTPUT                                                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Final Response ──> print_readable() ──> Console Output         │
│                                                                 │
│  All Analysis ──> structlog ──> vulnhuntr.log                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Iterative Context Expansion Algorithm

```python
for vuln_type in initial_analysis.vulnerability_types:
    stored_code_definitions = {}
    same_context = False
    previous_analysis = ''
    previous_context_amount = 0
    
    for iteration in range(7):  # Max 7 iterations
        
        # Iteration 0: No context, just file and vuln-specific prompt
        # Iteration 1+: Fetch requested context from previous iteration
        
        if iteration > 0:
            previous_context_amount = len(stored_code_definitions)
            previous_analysis = secondary_analysis_report.analysis
            
            # Fetch requested context code
            for context_item in secondary_analysis_report.context_code:
                if context_item.name not in stored_code_definitions:
                    match = symbol_extractor.extract(
                        name=context_item.name,
                        code_line=context_item.code_line,
                        files=filtered_files
                    )
                    if match:
                        stored_code_definitions[context_item.name] = match
        
        # Build prompt with all gathered context
        prompt = build_secondary_prompt(
            file_code=original_file,
            context_definitions=stored_code_definitions.values(),
            vuln_type=vuln_type,
            previous_analysis=previous_analysis
        )
        
        # Analyze with LLM
        secondary_analysis_report = llm.chat(prompt, max_tokens=8192)
        
        # Termination conditions
        if not secondary_analysis_report.context_code:
            break  # No more context requested
        
        if previous_context_amount >= len(stored_code_definitions) and iteration > 0:
            if same_context:
                break  # Requested same context twice
            same_context = True
```

**Termination Conditions**:

1. LLM returns empty `context_code` list
2. No new context symbols found (allowed once, breaks on second occurrence)
3. Maximum 7 iterations reached

The 7-iteration limit balances analysis thoroughness with API cost. Most vulnerabilities resolve within 3–5 iterations.

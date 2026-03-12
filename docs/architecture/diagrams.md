# Process Flow Diagrams

Flowcharts for the major subsystems.

---

## Diagram 1: Overall System Flow

```mermaid
flowchart TD
    START([START]) --> PARSE[Parse CLI Arguments]
    PARSE --> INIT[Initialize RepoOps]
    INIT --> DISC{"--analyze flag?"}
    DISC -->|yes| ANA[get_files_to_analyze]
    DISC -->|no| SCAN["get_relevant_py_files\nget_network_related_files"]
    ANA --> RDME{README exists?}
    SCAN --> RDME
    RDME -->|yes| RSUM["LLM.chat README_SUMMARY_PROMPT\nExtract summary tag, add to system_prompt"]
    RDME -->|no| LLMI
    RSUM --> LLMI[Initialize LLM with system_prompt]
    LLMI --> FLOOP([for each file])
    FLOOP --> READ["Read file\nBuild prompt: file_code + instructions + response_format"]
    READ --> LLM1[llm.chat max_tokens=8192]
    LLM1 --> RPT1[print_readable initial_report]
    RPT1 --> CONF{"confidence_score > 0\nAND vuln_types?"}
    CONF -->|yes| VLOOP([for each vuln_type])
    VLOOP --> SEC["Secondary Analysis Loop (Diagram 2)"]
    SEC --> MVULN{more vuln_types?}
    MVULN -->|yes| VLOOP
    MVULN -->|no| MFILE{more files?}
    CONF -->|no| MFILE
    MFILE -->|yes| FLOOP
    MFILE -->|no| END([END])
```

---

## Diagram 2: Secondary Analysis Loop

```mermaid
flowchart TD
    ENTER(["Secondary Analysis\nfor vuln_type"]) --> INIT["Initialize:\nstored_code_definitions = {}\nsame_context = False\niteration = 0"]
    INIT --> MAXCHK{iteration >= 7?}
    MAXCHK -->|yes| BRKMAX([EXIT: max iterations])
    MAXCHK -->|no| ITCHK{iteration > 0?}
    ITCHK -->|yes| EXPAND["For each new context_item:\nSymbolExtractor.extract\nStore if match found"]
    ITCHK -->|no| BUILD
    EXPAND --> BUILD["Build secondary prompt:\nfile_code + context_code + example_bypasses\n+ instructions + previous_analysis + response_format"]
    BUILD --> LLM2[llm.chat max_tokens=8192]
    LLM2 --> VERB{verbosity > 0?}
    VERB -->|yes| PRNT[print_readable report]
    VERB -->|no| C1
    PRNT --> C1{context_code empty?}
    C1 -->|yes| P1[print_readable if verbosity==0]
    P1 --> EXIT1([BREAK: no new context])
    C1 -->|no| C2{"no new definitions\nadded this iteration?"}
    C2 -->|yes| SAMECHK{"same_context\nalready True?"}
    SAMECHK -->|yes| P2[print_readable if verbosity==0]
    P2 --> EXIT2([BREAK: same context twice])
    SAMECHK -->|no| SETSC[same_context = True]
    SETSC --> INC[iteration += 1]
    C2 -->|no| RESETSC[same_context = False]
    RESETSC --> INC
    INC --> MAXCHK
```

---

## Diagram 3: Symbol Resolution Flow

```mermaid
flowchart TD
    ENTER(["extract(symbol_name, code_line, filtered_files)"]) --> PARSE["Parse symbol_name.split('.')\ne.g. AuthHandler.validate -> [AuthHandler, validate]"]
    PARSE --> FILES["Find files where code_line appears\nCreate jedi.Script for each"]
    FILES --> S1[STRATEGY 1: file_search]
    S1 --> S1L["For each script:\nscript.search(symbol_name)\nMatch by name.type"]
    S1L --> S1F{match?}
    S1F -->|yes| CMO
    S1F -->|no| S2[STRATEGY 2: project_search]
    S2 --> S2L["project.search(symbol_name)\nMatch by name.type"]
    S2L --> S2F{match?}
    S2F -->|yes| CMO
    S2F -->|no| S3[STRATEGY 3: all_names_search]
    S3 --> S3L["get_names(all_scopes=True)\nMatch by full_name or name parts"]
    S3L --> S3F{match?}
    S3F -->|no| FBACK["FALLBACK:\nMatch code_line against name descriptions"]
    FBACK --> FBF{match?}
    FBF -->|no| NONE([return None])
    FBF -->|yes| CMO
    S3F -->|yes| CMO[_create_match_obj]
    CMO --> THRD{third-party module?}
    THRD -->|yes| TPSTR["source = 'Third party library...'"]
    THRD -->|no| DEFSRC["source = _get_definition_source\nstart/end positions from jedi"]
    TPSTR --> RET(["Return name, file_path, source"])
    DEFSRC --> RET
```

---

## Diagram 4: LLM Response Processing

```mermaid
flowchart TD
    RAW([Raw API Response]) --> PROV{provider?}
    PROV -->|Claude| CLAUD["response.content[0].text\nstrip newlines"]
    PROV -->|ChatGPT| CGPT["response.choices[0].message.content"]
    PROV -->|Ollama| OLMA["response.json()['response']"]
    CLAUD --> RTEXT[response_text]
    CGPT --> RTEXT
    OLMA --> RTEXT
    RTEXT --> PF{prefill exists?}
    PF -->|yes| PREP[prepend prefill to response_text]
    PF -->|no| RSTRIP
    PREP --> RSTRIP["Regex extract outermost JSON object\nre.DOTALL"]
    RSTRIP --> RMATCH{match found?}
    RMATCH -->|yes| USEM["response_text = match.group(0)"]
    RMATCH -->|no| PYDVAL
    USEM --> PYDVAL["response_model.model_validate_json(response_text)"]
    PYDVAL --> VALID{valid?}
    VALID -->|yes| OK([Return Response object])
    VALID -->|no| LOGW[log.warning: validation failed]
    LOGW --> ERR([raise LLMError])
```

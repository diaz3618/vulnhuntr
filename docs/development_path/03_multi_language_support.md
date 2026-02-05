# Development Path: Multi-Language Support

**Priority**: LONG-TERM - Strategic  
**Complexity**: HIGH  
**Estimated Effort**: 8-12 weeks  
**Dependencies**: Tree-sitter MCP Server integration recommended

---

## Current State Analysis

### Existing Implementation
- **Python-only**: Uses Jedi (0.19.2+) and Parso (0.8.5+) for Python AST parsing
- **Symbol Resolution**: `vulnhuntr/symbol_finder.py` - Python-specific three-tier search
- **Network Patterns**: `vulnhuntr/__main__.py` lines 105-210 - Python web frameworks only
- **Language Constraints**: Hard-coded Python 3.10-3.13 compatibility

### Target Languages (Priority Order)
1. **JavaScript/TypeScript** (Immediate value - high web app coverage)
2. **Go** (Popular for microservices, cloud-native apps)
3. **Java** (Enterprise applications)
4. **Ruby** (Rails apps)
5. **PHP** (Legacy web apps)

---

## Technical Architecture

### 1. Abstraction Layer

**New Base Classes**: `vulnhuntr/language_support/base.py`

```python
from abc import ABC, abstractmethod
from typing import List, Dict, Optional
from pathlib import Path

class LanguageSupport(ABC):
    """Abstract base class for language-specific analysis"""
    
    @property
    @abstractmethod
    def language_name(self) -> str:
        """Language identifier (e.g., 'python', 'javascript')"""
        pass
    
    @property
    @abstractmethod
    def file_extensions(self) -> List[str]:
        """Supported file extensions (e.g., ['.py', '.pyi'])"""
        pass
    
    @abstractmethod
    def detect_network_entry_points(self, file_path: Path) -> bool:
        """Return True if file contains network entry points"""
        pass
    
    @abstractmethod
    def extract_symbol(self, symbol_name: str, code_line: str, 
                      files: List[Path]) -> Optional[Dict]:
        """Extract symbol definition from codebase"""
        pass
    
    @abstractmethod
    def parse_imports(self, file_path: Path) -> List[str]:
        """Extract imported modules/packages"""
        pass
    
    @abstractmethod
    def get_function_at_line(self, file_path: Path, line: int) -> Optional[Dict]:
        """Get function/method definition at specific line"""
        pass

class PythonSupport(LanguageSupport):
    """Python language support (refactored from existing code)"""
    
    def __init__(self, repo_path: Path):
        self.repo_path = repo_path
        self.symbol_extractor = SymbolExtractor(repo_path)
    
    @property
    def language_name(self) -> str:
        return "python"
    
    @property
    def file_extensions(self) -> List[str]:
        return ['.py', '.pyi']
    
    def detect_network_entry_points(self, file_path: Path) -> bool:
        """Check for Flask, FastAPI, Django, etc. patterns"""
        # Move existing regex patterns from __main__.py here
        patterns = [
            r'@app\.route\(.*?\)',
            r'@app\.(?:get|post|put|delete)',
            # ... all 210+ patterns
        ]
        
        content = file_path.read_text()
        return any(re.search(p, content) for p in patterns)
    
    def extract_symbol(self, symbol_name: str, code_line: str, 
                      files: List[Path]) -> Optional[Dict]:
        """Delegate to existing SymbolExtractor"""
        return self.symbol_extractor.extract(symbol_name, code_line, files)
```

### 2. JavaScript/TypeScript Support

**Implementation**: `vulnhuntr/language_support/javascript.py`

**Key Differences from Python**:
- No standard library AST parser in Python
- Must use Tree-sitter or external tool
- Different web frameworks (Express, Fastify, Next.js, etc.)
- Module systems (CommonJS, ESM)

```python
import tree_sitter
from tree_sitter_languages import get_language, get_parser

class JavaScriptSupport(LanguageSupport):
    """JavaScript/TypeScript language support via Tree-sitter"""
    
    def __init__(self, repo_path: Path):
        self.repo_path = repo_path
        self.parser = get_parser('javascript')
        self.language = get_language('javascript')
    
    @property
    def language_name(self) -> str:
        return "javascript"
    
    @property
    def file_extensions(self) -> List[str]:
        return ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']
    
    def detect_network_entry_points(self, file_path: Path) -> bool:
        """Detect Express, Fastify, Next.js routes, etc."""
        patterns = [
            # Express.js
            r'app\.(get|post|put|delete|patch)\(',
            r'router\.(get|post|put|delete|patch)\(',
            
            # Fastify
            r'fastify\.(get|post|put|delete|patch)\(',
            
            # Next.js API routes
            r'export\s+default\s+async\s+function\s+handler',
            r'export\s+async\s+function\s+(GET|POST|PUT|DELETE)',
            
            # Koa
            r'router\.(get|post|put|delete|patch)\(',
            
            # NestJS
            r'@(Get|Post|Put|Delete|Patch)\(',
            r'@Controller\(',
            
            # tRPC
            r'\.query\(|\.mutation\(',
        ]
        
        content = file_path.read_text()
        return any(re.search(p, content) for p in patterns)
    
    def extract_symbol(self, symbol_name: str, code_line: str, 
                      files: List[Path]) -> Optional[Dict]:
        """Extract function/class definition using Tree-sitter"""
        
        # Find files containing the code_line
        matching_files = [f for f in files 
                         if self._search_in_file(f, code_line)]
        
        for file in matching_files:
            tree = self._parse_file(file)
            
            # Query for function declarations
            query = self.language.query("""
                (function_declaration name: (identifier) @func.name)
                (variable_declarator 
                    name: (identifier) @func.name
                    value: (arrow_function))
                (method_definition name: (property_identifier) @method.name)
            """)
            
            captures = query.captures(tree.root_node)
            
            for node, capture_name in captures:
                if node.text.decode('utf8') == symbol_name:
                    # Found it! Extract full function
                    parent = self._find_function_node(node)
                    if parent:
                        return {
                            'name': symbol_name,
                            'source': parent.text.decode('utf8'),
                            'file': str(file),
                            'line': parent.start_point[0] + 1
                        }
        
        return None
    
    def _parse_file(self, file_path: Path):
        """Parse file with Tree-sitter"""
        code = file_path.read_bytes()
        return self.parser.parse(code)
    
    def _find_function_node(self, identifier_node):
        """Walk up AST to find containing function"""
        current = identifier_node
        while current:
            if current.type in ['function_declaration', 'arrow_function', 
                               'method_definition', 'class_declaration']:
                return current
            current = current.parent
        return None
```

**Dependencies**:
```bash
pip install tree-sitter tree-sitter-languages
```

### 3. Go Support

**Implementation**: `vulnhuntr/language_support/go.py`

**Key Challenges**:
- Different package system (modules)
- Different web frameworks (Gin, Echo, Chi, etc.)
- Strong typing (helpful for analysis)

```python
class GoSupport(LanguageSupport):
    """Go language support"""
    
    def __init__(self, repo_path: Path):
        self.repo_path = repo_path
        self.parser = get_parser('go')
        self.language = get_language('go')
    
    @property
    def language_name(self) -> str:
        return "go"
    
    @property
    def file_extensions(self) -> List[str]:
        return ['.go']
    
    def detect_network_entry_points(self, file_path: Path) -> bool:
        """Detect Gin, Echo, Chi, net/http handlers"""
        patterns = [
            # net/http
            r'http\.HandleFunc\(',
            r'http\.Handle\(',
            r'mux\.HandleFunc\(',
            
            # Gin
            r'\.GET\(|\.POST\(|\.PUT\(|\.DELETE\(',
            r'router\.Group\(',
            
            # Echo
            r'e\.GET\(|e\.POST\(|e\.PUT\(|e\.DELETE\(',
            
            # Chi
            r'r\.Get\(|r\.Post\(|r\.Put\(|r\.Delete\(',
            
            # Fiber
            r'app\.Get\(|app\.Post\(|app\.Put\(|app\.Delete\(',
        ]
        
        content = file_path.read_text()
        return any(re.search(p, content) for p in patterns)
```

### 4. Language Detection & Registry

**Implementation**: `vulnhuntr/language_support/registry.py`

```python
class LanguageRegistry:
    """Manages available language supports"""
    
    def __init__(self):
        self.supports: Dict[str, Type[LanguageSupport]] = {}
        self._register_defaults()
    
    def _register_defaults(self):
        """Register built-in language supports"""
        from .python import PythonSupport
        from .javascript import JavaScriptSupport
        from .go import GoSupport
        
        self.register('python', PythonSupport)
        self.register('javascript', JavaScriptSupport)
        self.register('go', GoSupport)
    
    def register(self, name: str, support_class: Type[LanguageSupport]):
        """Register a language support"""
        self.supports[name] = support_class
    
    def detect_language(self, file_path: Path) -> Optional[str]:
        """Auto-detect language from file extension"""
        ext = file_path.suffix.lower()
        
        for name, support_class in self.supports.items():
            # Create temporary instance to check extensions
            if ext in support_class(Path('.')).file_extensions:
                return name
        
        return None
    
    def get_support(self, language: str, repo_path: Path) -> LanguageSupport:
        """Get language support instance"""
        if language not in self.supports:
            raise ValueError(f"Unsupported language: {language}")
        
        return self.supports[language](repo_path)

# Global registry
registry = LanguageRegistry()
```

### 5. Modified Main Analysis Loop

**Changes to `vulnhuntr/__main__.py`**:

```python
from vulnhuntr.language_support import registry

def run():
    # ... argument parsing ...
    
    # Auto-detect languages in repository
    languages_found = set()
    language_files = {}  # language -> list of files
    
    for file in all_files:
        lang = registry.detect_language(file)
        if lang:
            languages_found.add(lang)
            language_files.setdefault(lang, []).append(file)
    
    print(f"[*] Detected languages: {', '.join(languages_found)}")
    
    # Analyze each language separately
    all_results = []
    
    for language in languages_found:
        print(f"\n[*] Analyzing {language} files...")
        
        # Get language-specific support
        lang_support = registry.get_support(language, repo_path)
        
        # Filter to network entry points
        entry_point_files = [
            f for f in language_files[language]
            if lang_support.detect_network_entry_points(f)
        ]
        
        print(f"[*] Found {len(entry_point_files)} {language} entry point files")
        
        # Analyze each file (same flow, language-agnostic)
        for file in entry_point_files:
            result = analyze_file(file, llm, lang_support)
            all_results.append(result)
    
    # ... rest of analysis ...

def analyze_file(file: Path, llm: LLM, lang_support: LanguageSupport):
    """Language-agnostic file analysis"""
    
    # Read file
    content = file.read_text()
    
    # Initial analysis (same prompts, language-agnostic)
    initial_analysis = llm.chat(
        build_initial_prompt(content, lang_support.language_name),
        response_model=Response
    )
    
    # Secondary analysis with symbol resolution
    for vuln_type in initial_analysis.vulnerability_types:
        for i in range(7):
            # ... iteration logic ...
            
            # Fetch context using language-specific symbol resolver
            for context_item in analysis.context_code:
                symbol = lang_support.extract_symbol(
                    context_item.name,
                    context_item.code_line,
                    language_files[lang_support.language_name]
                )
                if symbol:
                    context_definitions.append(symbol)
            
            # ... continue analysis ...
```

---

## Prompt Modifications

**Language-Aware Prompts**:

```python
# vulnhuntr/prompts.py

def build_initial_prompt(code: str, language: str) -> str:
    """Build language-specific initial analysis prompt"""
    
    language_specifics = {
        'python': {
            'common_vulns': 'os.system(), eval(), pickle, SQL string formatting',
            'frameworks': 'Flask, FastAPI, Django',
            'patterns': 'f-strings, % formatting, .format()'
        },
        'javascript': {
            'common_vulns': 'eval(), child_process.exec(), SQL template strings',
            'frameworks': 'Express, Fastify, Next.js',
            'patterns': 'template literals, string concatenation'
        },
        'go': {
            'common_vulns': 'os.Command(), database/sql query building',
            'frameworks': 'Gin, Echo, Chi, net/http',
            'patterns': 'string concatenation, fmt.Sprintf'
        }
    }
    
    specifics = language_specifics.get(language, {})
    
    return f"""
<file_code language="{language}">
{code}
</file_code>

<instructions>
Analyze this {language.upper()} code for security vulnerabilities.

Common {language} vulnerability patterns to check:
- {specifics.get('common_vulns', 'injection vulnerabilities')}

Frameworks to recognize:
- {specifics.get('frameworks', 'common web frameworks')}

Dangerous patterns:
- {specifics.get('patterns', 'unsafe string operations')}

... (rest of prompt)
</instructions>
"""
```

---

## MCP Server Integration

**Tree-sitter MCP Server** provides universal parsing:

```python
from mcp import MCPClient

class TreeSitterMCPSymbolExtractor:
    """Use Tree-sitter MCP server for symbol extraction"""
    
    def __init__(self, mcp_server_url: str):
        self.client = MCPClient(mcp_server_url)
    
    def extract_symbol(self, file_path: Path, symbol_name: str) -> Optional[Dict]:
        """Extract symbol via MCP server"""
        
        response = self.client.call_tool(
            "tree-sitter-query",
            {
                "file": str(file_path),
                "query": f"(function_declaration name: (identifier) @name (#eq? @name \"{symbol_name}\"))"
            }
        )
        
        # Parse MCP response
        if response.get('matches'):
            match = response['matches'][0]
            return {
                'name': symbol_name,
                'source': match['text'],
                'file': str(file_path),
                'line': match['start_line']
            }
        
        return None
```

---

## Implementation Plan

### Phase 1: Abstraction (Week 1-2)
1. Create `language_support/` package
2. Define `LanguageSupport` abstract base class
3. Refactor Python support into `PythonSupport` class
4. Update main loop to use language abstraction
5. **Testing**: Verify Python analysis still works

### Phase 2: JavaScript/TypeScript (Week 3-6)
1. Install Tree-sitter dependencies
2. Implement `JavaScriptSupport` class
3. Add JavaScript framework detection patterns
4. Test on JavaScript projects (Express, Next.js)
5. **Testing**: Analyze vulnerable JS repos, verify accuracy

### Phase 3: Go Support (Week 7-9)
1. Implement `GoSupport` class
2. Add Go framework detection patterns
3. Test on Go projects (Gin, Echo)
4. **Testing**: Analyze vulnerable Go repos

### Phase 4: Language Registry (Week 9-10)
1. Implement `LanguageRegistry` class
2. Add auto-detection logic
3. Support multiple languages in single repo
4. **Testing**: Analyze polyglot repositories

### Phase 5: Prompt Optimization (Week 10-11)
1. Create language-specific prompt variations
2. Test effectiveness across languages
3. Refine based on false positive/negative rates
4. **Testing**: Benchmark accuracy per language

### Phase 6: Documentation (Week 11-12)
1. Document language support architecture
2. Create guide for adding new languages
3. Update README with supported languages
4. **Testing**: Community feedback

---

## Testing Strategy

### Unit Tests
```python
# tests/language_support/test_registry.py
def test_language_detection():
    registry = LanguageRegistry()
    assert registry.detect_language(Path("test.py")) == "python"
    assert registry.detect_language(Path("test.js")) == "javascript"
    assert registry.detect_language(Path("test.go")) == "go"

# tests/language_support/test_javascript.py
def test_javascript_symbol_extraction():
    support = JavaScriptSupport(Path("test_repo"))
    symbol = support.extract_symbol("getUserById", "getUserById(req.params.id)", [Path("api.js")])
    assert symbol is not None
    assert "function getUserById" in symbol['source']
```

### Integration Tests
- Analyze vulnerable JavaScript project (e.g., DVWA-js)
- Analyze vulnerable Go project
- Analyze polyglot project (Python + JavaScript)

---

## Success Metrics

1. **Python Compatibility**: No regressions after refactoring
2. **JavaScript Accuracy**: >70% true positive rate on test corpus
3. **Go Accuracy**: >70% true positive rate on test corpus
4. **Polyglot Support**: Successfully analyze repos with multiple languages

---

## Documentation Updates

### README.md
- List supported languages
- Language-specific examples
- Framework coverage per language

### New: LANGUAGE_SUPPORT.md
- Architecture overview
- Adding new language guide
- Framework detection patterns
- Symbol extraction guide

---

## Future Enhancements

1. **Java Support**: Spring Boot, JSF, Servlets
2. **Ruby Support**: Rails, Sinatra
3. **PHP Support**: Laravel, Symfony
4. **C# Support**: ASP.NET Core
5. **Rust Support**: Actix, Rocket
6. **Framework Plugins**: Extensible framework detection

# Development Path: MCP Server Integration

**Priority**: MEDIUM - Enhances Capabilities  
**Complexity**: High  
**Estimated Effort**: 6-8 weeks  
**Dependencies**: None (can be implemented independently)

---

## Implementation Status

| Phase | Feature | Status | Notes |
|-------|---------|--------|-------|
| 1 | MCP Client Infrastructure | ❌ NOT STARTED | Base client, connection management |
| 2 | Integrated Servers (Filesystem) | ❌ NOT STARTED | Replace direct file access with MCP |
| 3 | Integrated Servers (Ripgrep) | ❌ NOT STARTED | Fast search across codebase |
| 4 | Integrated Servers (Tree-sitter) | ❌ NOT STARTED | Multi-language AST parsing |
| 5 | External Servers (Process) | ❌ NOT STARTED | Config-based, PoC execution |
| 6 | External Servers (CodeQL) | ❌ NOT STARTED | Config-based, CVE validation |
| - | Configuration System | ❌ NOT STARTED | `.vulnhuntr.yaml` MCP section |
| - | Fallback Mechanisms | ❌ NOT STARTED | Graceful degradation to current methods |
| - | Unit Tests | ❌ NOT STARTED | Mock MCP servers, connection tests |
| - | Documentation | ❌ NOT STARTED | MCP setup guide, server configuration |

---

## Overview

**MCP (Model Context Protocol)** enables LLMs to interact with external tools and data sources through a standardized interface. For Vulnhuntr, MCP servers can:
- **Enhance code navigation** (Tree-sitter for multi-language AST parsing)
- **Improve search capabilities** (Ripgrep for fast code search)
- **Validate findings** (CodeQL for CVE cross-reference)
- **Execute PoCs safely** (Process server for sandboxed execution)
- **Provide safe file access** (Filesystem server with permissions)

### Integration Strategy

**Two-tier approach**:
1. **Integrated Servers**: Built-in, enabled by default, with fallback to current methods
   - Filesystem MCP Server → Replaces direct Path operations (optional)
   - Ripgrep MCP Server → Fast search (falls back to glob)
   - Tree-sitter MCP Server → Multi-language parsing (falls back to Jedi for Python)

2. **External Servers**: Config-based, optional, for advanced features
   - Process MCP Server → Safe PoC execution (disabled by default)
   - CodeQL MCP Server → CVE validation (disabled by default)

---

## Current State Analysis

### Existing Implementation

**File Operations** (`vulnhuntr/symbol_finder.py`, `vulnhuntr/__main__.py`):
```python
# Direct file access
repo_path = Path(args.root)
files = repo_path.rglob("*.py")
with file.open() as f:
    content = f.read()
```

**Code Search** (`vulnhuntr/__main__.py`, `symbol_finder.py`):
```python
# Regex-based pattern matching
for f in files:
    with f.open() as file:
        if pattern in file.read():
            matches.append(f)
```

**Python Parsing** (`vulnhuntr/symbol_finder.py`):
```python
# Jedi for Python symbol resolution
import jedi
project = jedi.Project(path=repo_path)
script = jedi.Script(path=file, project=project)
symbols = script.search(name)
```

**Limitations**:
- Python-only (Jedi constraint)
- Slow search on large repos (no indexing)
- No sandboxed PoC execution
- No CVE database integration
- Direct file access (security concern for untrusted repos)

---

## Technical Architecture

### 1. MCP Client Infrastructure

**Implementation Location**: New file `vulnhuntr/mcp_client.py`

```python
from typing import Dict, Any, Optional, List
from pathlib import Path
import json
import subprocess
import logging
from dataclasses import dataclass
from enum import Enum

log = logging.getLogger(__name__)

class MCPServerType(Enum):
    """Types of MCP servers"""
    INTEGRATED = "integrated"  # Built-in, enabled by default
    EXTERNAL = "external"      # Config-based, optional

@dataclass
class MCPServerConfig:
    """Configuration for a single MCP server"""
    name: str
    type: MCPServerType
    command: List[str]
    enabled: bool = True
    fallback_enabled: bool = True
    args: Dict[str, Any] = None

class MCPClient:
    """Client for interacting with MCP servers"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.servers: Dict[str, subprocess.Popen] = {}
        self.connections: Dict[str, Any] = {}
        
    def start_server(self, server_config: MCPServerConfig) -> bool:
        """Start an MCP server process"""
        try:
            cmd = server_config.command.copy()
            if server_config.args:
                cmd.extend(self._format_args(server_config.args))
            
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            self.servers[server_config.name] = process
            log.info(f"Started MCP server: {server_config.name}", pid=process.pid)
            return True
            
        except Exception as e:
            log.error(f"Failed to start MCP server {server_config.name}: {e}")
            return False
    
    def call_tool(self, server_name: str, tool_name: str, 
                  arguments: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Call a tool on an MCP server"""
        if server_name not in self.servers:
            log.warning(f"Server {server_name} not started")
            return None
        
        try:
            request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": arguments
                }
            }
            
            # Send request
            process = self.servers[server_name]
            process.stdin.write(json.dumps(request) + "\n")
            process.stdin.flush()
            
            # Read response
            response_line = process.stdout.readline()
            response = json.loads(response_line)
            
            if "error" in response:
                log.error(f"MCP tool error: {response['error']}")
                return None
            
            return response.get("result")
            
        except Exception as e:
            log.error(f"MCP tool call failed: {e}")
            return None
    
    def stop_all(self):
        """Stop all MCP server processes"""
        for name, process in self.servers.items():
            try:
                process.terminate()
                process.wait(timeout=5)
                log.info(f"Stopped MCP server: {name}")
            except Exception as e:
                log.error(f"Error stopping server {name}: {e}")
                process.kill()
    
    def _format_args(self, args: Dict[str, Any]) -> List[str]:
        """Convert args dict to command line arguments"""
        formatted = []
        for key, value in args.items():
            formatted.append(f"--{key}")
            if value is not True:
                formatted.append(str(value))
        return formatted
```

### 2. Integrated Server: Filesystem MCP

**Purpose**: Safe file operations with permission controls (optional replacement for direct Path access)

**Configuration**:
```yaml
# .vulnhuntr.yaml
mcp:
  integrated:
    filesystem:
      enabled: false  # Disabled by default (use current Path methods)
      fallback: true  # Use Path if MCP fails
      allowed_roots:
        - /workspace
        - /tmp/analysis
```

**Implementation**:
```python
class FilesystemMCP:
    """Wrapper for Filesystem MCP Server"""
    
    def __init__(self, client: MCPClient, allowed_roots: List[Path]):
        self.client = client
        self.allowed_roots = [Path(r) for r in allowed_roots]
        self.fallback_enabled = True
    
    def read_file(self, path: Path) -> Optional[str]:
        """Read file via MCP or fallback to direct access"""
        # Validate path
        if not self._is_allowed(path):
            log.warning(f"Path not in allowed roots: {path}")
            return None
        
        # Try MCP first
        result = self.client.call_tool(
            "filesystem",
            "read_file",
            {"path": str(path)}
        )
        
        if result and "content" in result:
            return result["content"]
        
        # Fallback to direct access
        if self.fallback_enabled:
            log.debug(f"MCP failed, using direct file access for {path}")
            try:
                return path.read_text()
            except Exception as e:
                log.error(f"Direct file access failed: {e}")
                return None
        
        return None
    
    def _is_allowed(self, path: Path) -> bool:
        """Check if path is under allowed roots"""
        try:
            path_resolved = path.resolve()
            return any(path_resolved.is_relative_to(root) for root in self.allowed_roots)
        except Exception:
            return False
```

### 3. Integrated Server: Ripgrep MCP

**Purpose**: Fast code search across large repositories

**Configuration**:
```yaml
mcp:
  integrated:
    ripgrep:
      enabled: true  # Enabled by default for performance
      fallback: true  # Use glob if ripgrep unavailable
      max_filesize: 1048576  # 1MB limit
```

**Implementation**:
```python
class RipgrepMCP:
    """Fast code search using Ripgrep MCP Server"""
    
    def __init__(self, client: MCPClient):
        self.client = client
        self.fallback_enabled = True
    
    def search_pattern(self, repo_path: Path, pattern: str, 
                      file_types: List[str] = None) -> List[Path]:
        """Search for pattern in repository"""
        
        # Try ripgrep via MCP
        result = self.client.call_tool(
            "ripgrep",
            "search",
            {
                "path": str(repo_path),
                "pattern": pattern,
                "file_types": file_types or ["py"],
                "case_sensitive": False
            }
        )
        
        if result and "matches" in result:
            return [Path(m["path"]) for m in result["matches"]]
        
        # Fallback to current glob + regex method
        if self.fallback_enabled:
            log.debug("Ripgrep unavailable, using glob search")
            return self._fallback_search(repo_path, pattern, file_types)
        
        return []
    
    def _fallback_search(self, repo_path: Path, pattern: str, 
                        file_types: List[str]) -> List[Path]:
        """Fallback to current implementation"""
        import re
        matches = []
        
        for ext in file_types:
            for file in repo_path.rglob(f"*.{ext}"):
                try:
                    if re.search(pattern, file.read_text(), re.IGNORECASE):
                        matches.append(file)
                except Exception:
                    continue
        
        return matches
```

### 4. Integrated Server: Tree-sitter MCP

**Purpose**: Multi-language AST parsing (extends beyond Python)

**Configuration**:
```yaml
mcp:
  integrated:
    tree_sitter:
      enabled: true  # Enable for future multi-language support
      fallback: true  # Use Jedi for Python
      languages:
        - python
        - javascript
        - typescript
        - go
```

**Implementation**:
```python
class TreeSitterMCP:
    """Multi-language AST parsing via Tree-sitter"""
    
    def __init__(self, client: MCPClient):
        self.client = client
        self.fallback_to_jedi = True
    
    def parse_file(self, file_path: Path, language: str) -> Optional[Dict[str, Any]]:
        """Parse file and return AST"""
        
        result = self.client.call_tool(
            "tree_sitter",
            "parse",
            {
                "path": str(file_path),
                "language": language
            }
        )
        
        if result and "ast" in result:
            return result["ast"]
        
        # Fallback to Jedi for Python
        if self.fallback_to_jedi and language == "python":
            log.debug("Tree-sitter unavailable, using Jedi for Python")
            return self._parse_with_jedi(file_path)
        
        return None
    
    def find_symbols(self, file_path: Path, symbol_name: str, 
                     language: str) -> List[Dict[str, Any]]:
        """Find symbol definitions in file"""
        
        result = self.client.call_tool(
            "tree_sitter",
            "query",
            {
                "path": str(file_path),
                "language": language,
                "query": f"(identifier) @name (#eq? @name \"{symbol_name}\")"
            }
        )
        
        if result and "matches" in result:
            return result["matches"]
        
        # Fallback to Jedi for Python
        if self.fallback_to_jedi and language == "python":
            return self._find_symbols_jedi(file_path, symbol_name)
        
        return []
    
    def _parse_with_jedi(self, file_path: Path) -> Dict[str, Any]:
        """Fallback to Jedi for Python parsing"""
        import jedi
        
        try:
            script = jedi.Script(path=file_path)
            return {
                "type": "jedi_fallback",
                "names": [n.name for n in script.get_names()]
            }
        except Exception as e:
            log.error(f"Jedi parsing failed: {e}")
            return {}
    
    def _find_symbols_jedi(self, file_path: Path, symbol_name: str) -> List[Dict]:
        """Fallback to Jedi for symbol search"""
        from vulnhuntr.symbol_finder import SymbolExtractor
        
        try:
            extractor = SymbolExtractor(file_path.parent)
            result = extractor.extract(symbol_name, "", [file_path])
            return [result] if result else []
        except Exception as e:
            log.error(f"Jedi symbol search failed: {e}")
            return []
```

### 5. External Server: Process MCP

**Purpose**: Safe PoC execution in sandboxed environment

**Configuration**:
```yaml
mcp:
  external:
    process:
      enabled: false  # Disabled by default (security concern)
      config_file: ~/.config/mcp/process-server.json
      allow_poc_execution: false
      timeout: 30
      sandbox: true
```

**External Config** (`~/.config/mcp/process-server.json`):
```json
{
  "mcpServers": {
    "process": {
      "command": "npx",
      "args": ["-y", "@anonx3247/process-mcp"],
      "env": {
        "SANDBOX_MODE": "true",
        "MAX_RUNTIME": "30"
      }
    }
  }
}
```

**Implementation**:
```python
class ProcessMCP:
    """Safe PoC execution via Process MCP Server"""
    
    def __init__(self, client: MCPClient, config: Dict[str, Any]):
        self.client = client
        self.enabled = config.get("enabled", False)
        self.allow_poc = config.get("allow_poc_execution", False)
        self.timeout = config.get("timeout", 30)
    
    def execute_poc(self, poc_code: str, language: str = "python") -> Optional[Dict[str, Any]]:
        """Execute PoC in sandboxed environment"""
        
        if not self.enabled or not self.allow_poc:
            log.warning("PoC execution disabled in config")
            return None
        
        result = self.client.call_tool(
            "process",
            "execute",
            {
                "code": poc_code,
                "language": language,
                "timeout": self.timeout,
                "sandbox": True
            }
        )
        
        if result:
            return {
                "stdout": result.get("stdout"),
                "stderr": result.get("stderr"),
                "exit_code": result.get("exit_code"),
                "execution_time": result.get("execution_time")
            }
        
        return None
    
    def validate_vulnerability(self, vuln_analysis: Dict[str, Any]) -> bool:
        """Attempt to validate vulnerability by executing PoC"""
        
        if not self.allow_poc:
            return False
        
        poc = vuln_analysis.get("poc", "")
        if not poc:
            return False
        
        result = self.execute_poc(poc)
        
        if result and result["exit_code"] == 0:
            log.info("PoC executed successfully - vulnerability likely valid")
            return True
        
        return False
```

### 6. External Server: CodeQL MCP

**Purpose**: Cross-reference findings with CVE database

**Configuration**:
```yaml
mcp:
  external:
    codeql:
      enabled: false  # Disabled by default (requires CodeQL setup)
      config_file: ~/.config/mcp/codeql-server.json
      database_path: ~/.codeql/databases
```

**External Config** (`~/.config/mcp/codeql-server.json`):
```json
{
  "mcpServers": {
    "codeql": {
      "command": "node",
      "args": ["/path/to/codeql-mcp/dist/index.js"],
      "env": {
        "CODEQL_HOME": "/usr/local/codeql"
      }
    }
  }
}
```

**Implementation**:
```python
class CodeQLMCP:
    """CVE validation via CodeQL MCP Server"""
    
    def __init__(self, client: MCPClient, config: Dict[str, Any]):
        self.client = client
        self.enabled = config.get("enabled", False)
        self.db_path = Path(config.get("database_path", "~/.codeql/databases")).expanduser()
    
    def query_vulnerabilities(self, repo_path: Path, 
                            vuln_type: str) -> List[Dict[str, Any]]:
        """Query CodeQL database for known vulnerabilities"""
        
        if not self.enabled:
            return []
        
        # Map Vulnhuntr vuln types to CodeQL query suites
        query_map = {
            "SQLI": "Security/CWE-089",
            "XSS": "Security/CWE-079",
            "RCE": "Security/CWE-078",
            "SSRF": "Security/CWE-918",
            "LFI": "Security/CWE-022"
        }
        
        query = query_map.get(vuln_type)
        if not query:
            return []
        
        result = self.client.call_tool(
            "codeql",
            "query",
            {
                "database": str(self.db_path / repo_path.name),
                "query": query
            }
        )
        
        if result and "results" in result:
            return result["results"]
        
        return []
    
    def cross_reference_finding(self, vuln_analysis: Dict[str, Any], 
                              repo_path: Path) -> Dict[str, Any]:
        """Cross-reference Vulnhuntr finding with CodeQL results"""
        
        vuln_types = vuln_analysis.get("vulnerability_types", [])
        
        codeql_results = []
        for vuln_type in vuln_types:
            results = self.query_vulnerabilities(repo_path, vuln_type)
            codeql_results.extend(results)
        
        # Check if Vulnhuntr finding overlaps with CodeQL results
        file_path = vuln_analysis.get("file")
        matches = [r for r in codeql_results if file_path in r.get("location", "")]
        
        return {
            "codeql_confirmed": len(matches) > 0,
            "matching_cves": [m.get("cve") for m in matches if "cve" in m],
            "confidence_boost": 2 if matches else 0  # Increase confidence if CodeQL agrees
        }
```

---

## Configuration File Integration

**Extend** `.vulnhuntr.yaml`:

```yaml
# MCP Server Configuration
mcp:
  # Integrated servers (built-in, with fallback)
  integrated:
    filesystem:
      enabled: false  # Use direct Path access by default
      fallback: true
      allowed_roots:
        - ${REPO_PATH}  # Dynamic, set at runtime
    
    ripgrep:
      enabled: true  # Enable for performance
      fallback: true  # Fallback to glob
      max_filesize: 1048576
    
    tree_sitter:
      enabled: true  # Enable for future multi-language
      fallback: true  # Fallback to Jedi for Python
      languages:
        - python
        - javascript
        - typescript
        - go
  
  # External servers (config-based, optional)
  external:
    process:
      enabled: false
      config_file: ~/.config/mcp/process-server.json
      allow_poc_execution: false
      timeout: 30
    
    codeql:
      enabled: false
      config_file: ~/.config/mcp/codeql-server.json
      database_path: ~/.codeql/databases
```

**Loading Configuration** (extend `vulnhuntr/config.py`):

```python
from dataclasses import dataclass, field
from typing import Dict, Any, List
from pathlib import Path
import yaml

@dataclass
class MCPIntegratedServerConfig:
    """Config for integrated MCP servers"""
    enabled: bool = False
    fallback: bool = True
    args: Dict[str, Any] = field(default_factory=dict)

@dataclass
class MCPExternalServerConfig:
    """Config for external MCP servers"""
    enabled: bool = False
    config_file: str = ""
    args: Dict[str, Any] = field(default_factory=dict)

@dataclass
class MCPConfig:
    """MCP server configuration"""
    integrated: Dict[str, MCPIntegratedServerConfig] = field(default_factory=dict)
    external: Dict[str, MCPExternalServerConfig] = field(default_factory=dict)

@dataclass
class VulnhuntrConfig:
    """Existing config + MCP section"""
    cost: Dict[str, Any] = field(default_factory=dict)
    checkpoint: Dict[str, Any] = field(default_factory=dict)
    mcp: MCPConfig = field(default_factory=MCPConfig)
    # ... existing fields

def load_config(config_file: Path = None) -> VulnhuntrConfig:
    """Load configuration with MCP support"""
    if config_file is None:
        config_file = find_config_file()
    
    if config_file and config_file.exists():
        with open(config_file) as f:
            data = yaml.safe_load(f) or {}
        
        # Parse MCP config
        mcp_data = data.get("mcp", {})
        mcp_config = MCPConfig(
            integrated={
                name: MCPIntegratedServerConfig(**cfg)
                for name, cfg in mcp_data.get("integrated", {}).items()
            },
            external={
                name: MCPExternalServerConfig(**cfg)
                for name, cfg in mcp_data.get("external", {}).items()
            }
        )
        
        return VulnhuntrConfig(
            cost=data.get("cost", {}),
            checkpoint=data.get("checkpoint", {}),
            mcp=mcp_config
        )
    
    # Default config with MCP disabled
    return VulnhuntrConfig(
        mcp=MCPConfig(
            integrated={
                "filesystem": MCPIntegratedServerConfig(enabled=False, fallback=True),
                "ripgrep": MCPIntegratedServerConfig(enabled=True, fallback=True),
                "tree_sitter": MCPIntegratedServerConfig(enabled=True, fallback=True),
            },
            external={
                "process": MCPExternalServerConfig(enabled=False),
                "codeql": MCPExternalServerConfig(enabled=False),
            }
        )
    )
```

---

## Implementation Plan

### Phase 1: MCP Client Infrastructure (Week 1-2)

1. **Create `mcp_client.py`**:
   - `MCPClient` class with JSON-RPC communication
   - Server lifecycle management (start/stop/restart)
   - Error handling and logging
   - Connection pooling

2. **Extend `config.py`**:
   - Add `MCPConfig` dataclass
   - Parse MCP section from `.vulnhuntr.yaml`
   - Validate server configurations

3. **Add CLI flags**:
   - `--mcp-disable-all`: Disable all MCP servers (use fallbacks)
   - `--mcp-enable <server>`: Enable specific server
   - `--mcp-config <file>`: Specify config file

4. **Testing**:
   - Mock MCP server for testing
   - Connection lifecycle tests
   - Configuration parsing tests

### Phase 2: Integrated Servers - Filesystem (Week 2-3)

1. **Implement `FilesystemMCP` wrapper**
2. **Update file operations** in `symbol_finder.py` and `__main__.py`:
   - Check if MCP enabled
   - Use MCP or fallback to Path
3. **Add permission validation**
4. **Testing**:
   - Compare MCP vs direct access
   - Test fallback on MCP failure

### Phase 3: Integrated Servers - Ripgrep (Week 3-4)

1. **Implement `RipgrepMCP` wrapper**
2. **Update search operations** in `__main__.py`:
   - Replace regex file searches with ripgrep calls
   - Fallback to current glob method
3. **Benchmark performance** (should be 5-10x faster)
4. **Testing**:
   - Compare search results (MCP vs glob)
   - Performance benchmarks

### Phase 4: Integrated Servers - Tree-sitter (Week 4-5)

1. **Implement `TreeSitterMCP` wrapper**
2. **Create abstraction layer** in `symbol_finder.py`:
   - `LanguageParser` interface
   - Tree-sitter implementation
   - Jedi fallback for Python
3. **Add language detection** (Python, JS, TS, Go)
4. **Testing**:
   - Parse Python files (compare with Jedi)
   - Parse JavaScript files (new capability)

### Phase 5: External Servers - Process (Week 5-6)

1. **Implement `ProcessMCP` wrapper**
2. **Add PoC execution option**:
   - New CLI flag: `--execute-poc`
   - Security warning
   - Sandbox verification
3. **Integrate with analysis flow**:
   - After LLM generates PoC
   - Optional automated validation
4. **Testing**:
   - Safe PoC execution
   - Timeout handling
   - Sandbox escape prevention

### Phase 6: External Servers - CodeQL (Week 6-7)

1. **Implement `CodeQLMCP` wrapper**
2. **Add CVE cross-reference**:
   - Query CodeQL after analysis
   - Boost confidence if match found
3. **Generate comparison report**:
   - Vulnhuntr findings
   - CodeQL findings
   - Overlap analysis
4. **Testing**:
   - CVE database queries
   - Cross-reference accuracy

### Phase 7: Integration & Polish (Week 7-8)

1. **CLI improvements**:
   - MCP status display
   - Server health checks
   - Fallback notifications
2. **Performance optimization**:
   - Connection pooling
   - Request batching
3. **Documentation**:
   - MCP setup guide
   - Server configuration examples
   - Troubleshooting guide
4. **Testing**:
   - End-to-end integration tests
   - Multiple server combinations
   - Failure scenarios

---

## CLI Interface

```bash
# Disable all MCP servers (use fallbacks only)
vulnhuntr -r /repo --mcp-disable-all

# Enable specific server
vulnhuntr -r /repo --mcp-enable ripgrep

# Use custom config
vulnhuntr -r /repo --mcp-config custom-mcp.yaml

# Enable PoC execution (Process MCP)
vulnhuntr -r /repo --execute-poc

# Enable CVE cross-reference (CodeQL MCP)
vulnhuntr -r /repo --mcp-enable codeql

# Check MCP server status
vulnhuntr --mcp-status
```

**Output Example**:
```
[*] MCP Server Status:
    ✓ Filesystem: Disabled (using direct Path access)
    ✓ Ripgrep: Enabled (fallback: glob)
    ✓ Tree-sitter: Enabled (fallback: Jedi)
    ✗ Process: Not configured
    ✗ CodeQL: Not configured
```

---

## Testing Strategy

### Unit Tests

```python
# tests/test_mcp_client.py
def test_mcp_client_initialization():
    config = {"integrated": {"ripgrep": {"enabled": True}}}
    client = MCPClient(config)
    assert client is not None

def test_server_lifecycle():
    client = MCPClient({})
    config = MCPServerConfig(
        name="test",
        type=MCPServerType.INTEGRATED,
        command=["echo", "test"]
    )
    assert client.start_server(config) is True
    client.stop_all()

# tests/test_ripgrep_mcp.py
def test_ripgrep_search(tmp_path):
    # Create test files
    (tmp_path / "test.py").write_text("def vulnerable(): pass")
    
    client = MCPClient({})
    ripgrep = RipgrepMCP(client)
    
    results = ripgrep.search_pattern(tmp_path, "vulnerable")
    assert len(results) > 0

# tests/test_fallback.py
def test_fallback_on_mcp_failure():
    """Test that fallback works when MCP unavailable"""
    client = MCPClient({})
    ripgrep = RipgrepMCP(client)
    ripgrep.fallback_enabled = True
    
    # MCP not started, should use fallback
    results = ripgrep.search_pattern(Path("."), "import")
    assert results is not None
```

### Integration Tests

```python
def test_full_analysis_with_mcp():
    """Test complete analysis using MCP servers"""
    config = load_config()
    config.mcp.integrated["ripgrep"].enabled = True
    
    # Run analysis
    results = run_analysis(test_repo, config)
    
    # Verify MCP was used
    assert "ripgrep" in results["mcp_servers_used"]

def test_cross_reference_with_codeql():
    """Test CVE cross-reference"""
    config = load_config()
    config.mcp.external["codeql"].enabled = True
    
    results = run_analysis(test_repo, config)
    
    # Check if findings were cross-referenced
    for finding in results["vulnerabilities"]:
        assert "codeql_confirmed" in finding
```

---

## Success Metrics

1. **Performance**: Ripgrep integration provides 5-10x faster search on large repos
2. **Multi-language**: Tree-sitter enables JS/TS analysis (new capability)
3. **Validation**: Process MCP reduces false positives by 20-30% through PoC execution
4. **CVE Matching**: CodeQL integration boosts confidence on known vulnerability patterns
5. **Fallback Reliability**: 100% fallback success rate when MCP unavailable

---

## Documentation Updates

### New: MCP_SETUP.md

```markdown
# MCP Server Setup for Vulnhuntr

## Quick Start

Vulnhuntr works out-of-the-box with integrated MCP servers (Filesystem, Ripgrep, Tree-sitter). External servers (Process, CodeQL) require additional setup.

## Integrated Servers

### Ripgrep MCP (Recommended)

**Enabled by default** for faster code search.

No setup required - Vulnhuntr will attempt to use ripgrep if available, fallback to glob if not.

To disable:
```yaml
# .vulnhuntr.yaml
mcp:
  integrated:
    ripgrep:
      enabled: false
```

### Tree-sitter MCP

**Enabled by default** for future multi-language support.

Currently uses Jedi for Python, will support JS/TS/Go in future versions.

...
```

### README.md Updates

Add MCP section:
```markdown
## MCP Server Integration

Vulnhuntr supports Model Context Protocol servers for enhanced capabilities:

- **Ripgrep**: Faster code search (enabled by default)
- **Tree-sitter**: Multi-language AST parsing (Python fallback to Jedi)
- **Process**: Safe PoC execution (optional, requires config)
- **CodeQL**: CVE cross-reference (optional, requires config)

See [MCP_SETUP.md](docs/MCP_SETUP.md) for configuration.
```

---

## Future Enhancements

1. **Custom MCP Servers**: Plugin system for user-defined servers
2. **Server Marketplace**: Repository of community MCP servers
3. **Distributed Analysis**: MCP servers on remote machines for parallel processing
4. **LLM-Direct MCP**: Let LLM call MCP tools directly (autonomous mode)
5. **Caching MCP Results**: Cache symbol lookups and search results for performance

---

## Security Considerations

### Process MCP Server

**CRITICAL**: Only enable with trusted code!

- Always run in sandbox mode
- Set strict timeouts (default 30s)
- Review PoC before execution
- Disable by default in config

### CodeQL MCP Server

- Requires CodeQL CLI installation
- Database creation can be slow (one-time per repo)
- Ensure database is up-to-date before analysis

### Filesystem MCP Server

- Validate allowed_roots strictly
- Never allow access outside repo directory
- Log all file access attempts

---

## Troubleshooting

### MCP Server Won't Start

Check:
1. Server executable in PATH
2. Node.js installed (for npm-based servers)
3. Config file syntax correct
4. Permissions on config directory

### Fallback Always Used

Check:
1. Server enabled in config
2. Server process running (check logs)
3. No firewall blocking JSON-RPC communication

### Process MCP Timeout

Increase timeout in config:
```yaml
mcp:
  external:
    process:
      timeout: 60  # Increase from 30s
```

---

## Dependencies

**New Python packages**:
```toml
# pyproject.toml
[tool.poetry.dependencies]
# No new Python dependencies - MCP servers are external processes
```

**External tools** (optional):
- ripgrep: `brew install ripgrep` or `apt install ripgrep`
- CodeQL CLI: Download from GitHub
- Node.js: For npm-based MCP servers

---

## Implementation Status Tracking

- [ ] Phase 1: MCP Client Infrastructure
- [ ] Phase 2: Filesystem MCP Integration
- [ ] Phase 3: Ripgrep MCP Integration
- [ ] Phase 4: Tree-sitter MCP Integration
- [ ] Phase 5: Process MCP Integration
- [ ] Phase 6: CodeQL MCP Integration
- [ ] Phase 7: Integration & Polish
- [ ] Documentation Complete
- [ ] Tests Passing
- [ ] Benchmarks Verified

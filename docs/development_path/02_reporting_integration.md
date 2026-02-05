# Development Path: Reporting and Integration

**Priority**: HIGH - Immediate Impact  
**Complexity**: Medium-High  
**Estimated Effort**: 3-4 weeks  
**Dependencies**: None (standalone improvements)

---

## Implementation Status

| Phase | Feature | Status | Notes |
|-------|---------|--------|-------|
| 1 | SARIF Support | ✅ COMPLETE | `reporters/sarif.py`, `--sarif` flag |
| 2 | HTML Reports | ✅ COMPLETE | `reporters/html.py` with Jinja2, `--html` flag |
| 3 | GitHub Issues | ✅ COMPLETE | `integrations/github_issues.py`, `--create-issues` flag |
| 4 | ---VS Code Extension | ❌ NOT IMPLEMENTED | Out of scope, requires separate project--- **IGNORE THIS FOR NOW** |
| 5 | Webhook Integration | ✅ COMPLETE | `integrations/webhook.py`, `--webhook` flag |
| 6 | Export Formats | ✅ COMPLETE | JSON, CSV, Markdown reporters |
| - | `--export-all` flag | ✅ COMPLETE | CLI convenience flag added |
| - | Unit Tests | ❌ NOT IMPLEMENTED | No test files exist |
| - | Documentation | ✅ COMPLETE | REPORTING.md and INTEGRATIONS.md created |
| - | REPORTING.md | ✅ COMPLETE | Documentation file created |
| - | INTEGRATIONS.md | ✅ COMPLETE | Documentation file created |

---

## Current State Analysis

### Existing Implementation
- **Location**: `vulnhuntr/__main__.py` - lines 480-490
- **Output Format**: Terminal output via `rich.print()` + JSON logging to `vulnhuntr.log`
- **Current Output**:
  - Pretty-printed results using Rich library
  - Structured JSON logs with `structlog`
  - No persistent report files
  - No integration with external tools

### Problem Statement
- Output only to console - ephemeral, not shareable
- No structured report format for CI/CD integration
- Can't import findings into issue trackers (JIRA, GitHub Issues)
- No IDE integration (developers can't see warnings inline)
- No export to security platforms (Snyk, SonarQube)
- Results lost when terminal closes

---

## Technical Architecture

### 1. SARIF Format Support

**SARIF** (Static Analysis Results Interchange Format) is the industry standard for static analysis tool output.

**Implementation Location**: New file `vulnhuntr/reporters/sarif.py`

```python
from typing import List, Dict
import json
from pathlib import Path
from datetime import datetime

class SARIFReporter:
    """Generate SARIF 2.1.0 compliant reports"""
    
    SARIF_VERSION = "2.1.0"
    SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    
    def __init__(self, tool_name: str = "vulnhuntr", tool_version: str = "0.1.0"):
        self.tool_name = tool_name
        self.tool_version = tool_version
        self.runs = []
        
    def create_report(self, results: List[Dict], repo_path: Path) -> Dict:
        """Convert vulnhuntr results to SARIF format"""
        
        # Map vulnhuntr vulnerability types to SARIF
        vuln_to_cwe = {
            "LFI": "CWE-22",     # Path Traversal
            "RCE": "CWE-78",     # OS Command Injection
            "SQLI": "CWE-89",    # SQL Injection
            "XSS": "CWE-79",     # Cross-site Scripting
            "SSRF": "CWE-918",   # Server-Side Request Forgery
            "IDOR": "CWE-639",   # Authorization Bypass
            "AFO": "CWE-73"      # External Control of File Name or Path
        }
        
        sarif_results = []
        
        for result in results:
            if not result.get('vulnerability_found'):
                continue
            
            for vuln_type in result.get('vulnerability_types', []):
                sarif_result = {
                    "ruleId": vuln_type,
                    "level": self._get_severity_level(result['confidence_score']),
                    "message": {
                        "text": result['analysis'],
                        "markdown": f"## {vuln_type} Vulnerability\\n\\n{result['analysis']}\\n\\n### Proof of Concept\\n```\\n{result['poc']}\\n```"
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": str(Path(result['file']).relative_to(repo_path)),
                                "uriBaseId": "%SRCROOT%"
                            },
                            "region": {
                                "startLine": self._extract_line_number(result.get('source', ''))
                            }
                        }
                    }],
                    "properties": {
                        "confidence": result['confidence_score'],
                        "scratchpad": result.get('scratchpad', ''),
                        "cwe": vuln_to_cwe.get(vuln_type, "CWE-0")
                    }
                }
                
                sarif_results.append(sarif_result)
        
        # Build SARIF document
        sarif_doc = {
            "version": self.SARIF_VERSION,
            "$schema": self.SCHEMA_URI,
            "runs": [{
                "tool": {
                    "driver": {
                        "name": self.tool_name,
                        "version": self.tool_version,
                        "informationUri": "https://github.com/protectai/vulnhuntr",
                        "rules": self._generate_rules()
                    }
                },
                "results": sarif_results,
                "invocations": [{
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.utcnow().isoformat() + "Z"
                }]
            }]
        }
        
        return sarif_doc
    
    def _get_severity_level(self, confidence: int) -> str:
        """Map confidence score to SARIF severity level"""
        if confidence >= 8:
            return "error"      # High confidence
        elif confidence >= 5:
            return "warning"    # Medium confidence
        else:
            return "note"       # Low confidence
    
    def _generate_rules(self) -> List[Dict]:
        """Generate SARIF rules for all vulnerability types"""
        rules = [
            {
                "id": "LFI",
                "shortDescription": {"text": "Local File Inclusion"},
                "fullDescription": {"text": "Path traversal allowing access to arbitrary files"},
                "helpUri": "https://owasp.org/www-community/attacks/Path_Traversal",
                "properties": {"tags": ["security", "external/cwe/cwe-22"]}
            },
            {
                "id": "RCE",
                "shortDescription": {"text": "Remote Code Execution"},
                "fullDescription": {"text": "Arbitrary code execution on the server"},
                "helpUri": "https://owasp.org/www-community/attacks/Code_Injection",
                "properties": {"tags": ["security", "external/cwe/cwe-78"]}
            },
            {
                "id": "SQLI",
                "shortDescription": {"text": "SQL Injection"},
                "fullDescription": {"text": "SQL query manipulation via user input"},
                "helpUri": "https://owasp.org/www-community/attacks/SQL_Injection",
                "properties": {"tags": ["security", "external/cwe/cwe-89"]}
            },
            {
                "id": "XSS",
                "shortDescription": {"text": "Cross-Site Scripting"},
                "fullDescription": {"text": "Injection of malicious scripts in web pages"},
                "helpUri": "https://owasp.org/www-community/attacks/xss/",
                "properties": {"tags": ["security", "external/cwe/cwe-79"]}
            },
            {
                "id": "SSRF",
                "shortDescription": {"text": "Server-Side Request Forgery"},
                "fullDescription": {"text": "Unauthorized requests from the server"},
                "helpUri": "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "properties": {"tags": ["security", "external/cwe/cwe-918"]}
            },
            {
                "id": "IDOR",
                "shortDescription": {"text": "Insecure Direct Object Reference"},
                "fullDescription": {"text": "Unauthorized access to resources"},
                "helpUri": "https://owasp.org/www-community/IDOR",
                "properties": {"tags": ["security", "external/cwe/cwe-639"]}
            },
            {
                "id": "AFO",
                "shortDescription": {"text": "Arbitrary File Overwrite"},
                "fullDescription": {"text": "Uncontrolled file write operations"},
                "helpUri": "https://cwe.mitre.org/data/definitions/73.html",
                "properties": {"tags": ["security", "external/cwe/cwe-73"]}
            }
        ]
        
        return rules
    
    def save(self, sarif_doc: Dict, output_path: Path):
        """Save SARIF report to file"""
        output_path.write_text(json.dumps(sarif_doc, indent=2))
        print(f"[*] SARIF report saved to: {output_path}")
```

**Integration**:
```python
# In __main__.py
parser.add_argument('--sarif', type=str, metavar='PATH',
                   help='Generate SARIF report at specified path')

if args.sarif:
    reporter = SARIFReporter()
    sarif_doc = reporter.create_report(results, args.root)
    reporter.save(sarif_doc, Path(args.sarif))
```

### 2. HTML Report Generation

**Implementation Location**: New file `vulnhuntr/reporters/html.py`

```python
from jinja2 import Template
from pathlib import Path

class HTMLReporter:
    """Generate interactive HTML reports"""
    
    TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Vulnhuntr Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { background: white; padding: 20px; margin: 20px 0; border-radius: 5px; }
        .vulnerability { background: white; padding: 20px; margin: 20px 0; border-radius: 5px; border-left: 5px solid #e74c3c; }
        .high { border-left-color: #e74c3c; }
        .medium { border-left-color: #f39c12; }
        .low { border-left-color: #3498db; }
        .code { background: #ecf0f1; padding: 10px; border-radius: 3px; font-family: monospace; overflow-x: auto; }
        .badge { display: inline-block; padding: 5px 10px; border-radius: 3px; color: white; font-size: 12px; }
        .badge-critical { background: #e74c3c; }
        .badge-high { background: #f39c12; }
        .badge-medium { background: #3498db; }
        .badge-low { background: #95a5a6; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Vulnhuntr Security Report</h1>
        <p>Repository: {{ repo_path }}</p>
        <p>Generated: {{ timestamp }}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Files Analyzed:</strong> {{ files_analyzed }}</p>
        <p><strong>Vulnerabilities Found:</strong> {{ total_vulns }}</p>
        <p><strong>High Confidence (8-10):</strong> {{ high_confidence }}</p>
        <p><strong>Medium Confidence (5-7):</strong> {{ medium_confidence }}</p>
        <p><strong>Low Confidence (0-4):</strong> {{ low_confidence }}</p>
    </div>
    
    {% for vuln in vulnerabilities %}
    <div class="vulnerability {{ 'high' if vuln.confidence >= 8 else 'medium' if vuln.confidence >= 5 else 'low' }}">
        <h3>{{ vuln.type }} in {{ vuln.file }}</h3>
        <span class="badge {{ 'badge-critical' if vuln.confidence >= 9 else 'badge-high' if vuln.confidence >= 7 else 'badge-medium' if vuln.confidence >= 5 else 'badge-low' }}">
            Confidence: {{ vuln.confidence }}/10
        </span>
        
        <h4>Analysis</h4>
        <p>{{ vuln.analysis }}</p>
        
        <h4>Proof of Concept</h4>
        <div class="code">{{ vuln.poc }}</div>
        
        {% if vuln.scratchpad %}
        <details>
            <summary>Analysis Details (Scratchpad)</summary>
            <div class="code">{{ vuln.scratchpad }}</div>
        </details>
        {% endif %}
    </div>
    {% endfor %}
</body>
</html>
    """
    
    def generate(self, results: List[Dict], repo_path: Path, output_path: Path):
        """Generate HTML report"""
        # Prepare data
        vulnerabilities = []
        for result in results:
            if result.get('vulnerability_found'):
                for vuln_type in result.get('vulnerability_types', []):
                    vulnerabilities.append({
                        'type': vuln_type,
                        'file': result['file'],
                        'confidence': result['confidence_score'],
                        'analysis': result['analysis'],
                        'poc': result['poc'],
                        'scratchpad': result.get('scratchpad', '')
                    })
        
        # Sort by confidence (highest first)
        vulnerabilities.sort(key=lambda v: v['confidence'], reverse=True)
        
        # Render template
        template = Template(self.TEMPLATE)
        html = template.render(
            repo_path=str(repo_path),
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            files_analyzed=len(results),
            total_vulns=len(vulnerabilities),
            high_confidence=len([v for v in vulnerabilities if v['confidence'] >= 8]),
            medium_confidence=len([v for v in vulnerabilities if 5 <= v['confidence'] < 8]),
            low_confidence=len([v for v in vulnerabilities if v['confidence'] < 5]),
            vulnerabilities=vulnerabilities
        )
        
        output_path.write_text(html)
        print(f"[*] HTML report saved to: {output_path}")
```

### 3. GitHub Issues Integration

**Implementation Location**: New file `vulnhuntr/integrations/github_issues.py`

```python
import requests
from typing import List, Dict
import os

class GitHubIssuesIntegration:
    """Create GitHub issues for vulnerabilities"""
    
    def __init__(self, repo_owner: str, repo_name: str, token: str = None):
        self.repo_owner = repo_owner
        self.repo_name = repo_name
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.api_base = "https://api.github.com"
        
    def create_issues(self, vulnerabilities: List[Dict], 
                     dry_run: bool = False) -> List[str]:
        """Create GitHub issues for each vulnerability"""
        
        if not self.token:
            raise ValueError("GitHub token required (set GITHUB_TOKEN env var)")
        
        issue_urls = []
        
        for vuln in vulnerabilities:
            # Skip low-confidence findings
            if vuln['confidence_score'] < 5:
                continue
            
            # Create issue title
            title = f"[Security] {vuln['vulnerability_type']} in {Path(vuln['file']).name}"
            
            # Create issue body
            body = f"""## Vulnerability Report

**Type**: {vuln['vulnerability_type']}  
**File**: `{vuln['file']}`  
**Confidence**: {vuln['confidence_score']}/10  
**Detected by**: Vulnhuntr

### Analysis
{vuln['analysis']}

### Proof of Concept
```python
{vuln['poc']}
```

### Remediation
Please review and fix this security vulnerability. Consider:
- Input validation and sanitization
- Principle of least privilege
- Security controls appropriate for the vulnerability type

---
*This issue was automatically created by Vulnhuntr security scanner.*
"""
            
            if dry_run:
                print(f"[Dry Run] Would create issue: {title}")
                issue_urls.append(f"https://github.com/{self.repo_owner}/{self.repo_name}/issues/NEW")
                continue
            
            # Create issue via GitHub API
            url = f"{self.api_base}/repos/{self.repo_owner}/{self.repo_name}/issues"
            headers = {
                "Authorization": f"token {self.token}",
                "Accept": "application/vnd.github.v3+json"
            }
            data = {
                "title": title,
                "body": body,
                "labels": ["security", "vulnerability", vuln['vulnerability_type'].lower()]
            }
            
            response = requests.post(url, headers=headers, json=data)
            
            if response.status_code == 201:
                issue_url = response.json()['html_url']
                issue_urls.append(issue_url)
                print(f"[*] Created issue: {issue_url}")
            else:
                print(f"[!] Failed to create issue: {response.status_code}")
                print(response.json())
        
        return issue_urls
```

### 4. VS Code Extension Integration

**Conceptual Design** (separate project, but plan for it)

**Extension Features**:
1. **Inline Warnings**: Show squiggly lines under vulnerable code
2. **Hover Information**: Display analysis and PoC on hover
3. **Quick Fixes**: Suggest remediations
4. **Background Analysis**: Run on file save
5. **Results Panel**: View all findings

**Data Exchange Format**:
```python
# vulnhuntr outputs to .vulnhuntr/vscode-findings.json
{
    "version": "1.0",
    "findings": [
        {
            "file": "api/user.py",
            "line": 42,
            "column": 10,
            "severity": "error",
            "type": "SQLI",
            "message": "SQL injection via user_id parameter",
            "analysis": "...",
            "poc": "..."
        }
    ]
}
```

**VS Code Extension** (TypeScript):
```typescript
// Watch for findings file changes
const watcher = vscode.workspace.createFileSystemWatcher('**/.vulnhuntr/vscode-findings.json');
watcher.onDidChange(() => {
    const findings = loadFindings();
    updateDiagnostics(findings);
});
```

### 5. Webhook Integration

**Implementation Location**: New file `vulnhuntr/integrations/webhook.py`

```python
import requests
import json

class WebhookIntegration:
    """Send findings to custom webhooks"""
    
    def __init__(self, webhook_url: str, webhook_secret: str = None):
        self.webhook_url = webhook_url
        self.webhook_secret = webhook_secret
        
    def send(self, results: List[Dict], repo_path: Path):
        """Send results to webhook"""
        
        payload = {
            "tool": "vulnhuntr",
            "version": "0.1.0",
            "repository": str(repo_path),
            "timestamp": datetime.utcnow().isoformat(),
            "summary": {
                "files_analyzed": len(results),
                "vulnerabilities_found": sum(1 for r in results if r.get('vulnerability_found')),
                "high_confidence": sum(1 for r in results if r.get('confidence_score', 0) >= 8)
            },
            "findings": [
                {
                    "file": r['file'],
                    "type": r['vulnerability_types'][0] if r.get('vulnerability_types') else None,
                    "confidence": r['confidence_score'],
                    "analysis": r['analysis']
                }
                for r in results if r.get('vulnerability_found')
            ]
        }
        
        headers = {"Content-Type": "application/json"}
        
        if self.webhook_secret:
            import hmac
            import hashlib
            signature = hmac.new(
                self.webhook_secret.encode(),
                json.dumps(payload).encode(),
                hashlib.sha256
            ).hexdigest()
            headers["X-Vulnhuntr-Signature"] = f"sha256={signature}"
        
        response = requests.post(self.webhook_url, json=payload, headers=headers)
        
        if response.status_code == 200:
            print(f"[*] Webhook notification sent successfully")
        else:
            print(f"[!] Webhook failed: {response.status_code}")
```

---

## Implementation Plan

### Phase 1: SARIF Support (Week 1)
1. Create `vulnhuntr/reporters/` directory
2. Implement `SARIFReporter` class
3. Add vulnerability to CWE mapping
4. Add `--sarif` CLI flag
5. Test with GitHub Code Scanning upload
6. **Testing**: Upload SARIF to GitHub, verify findings appear

### Phase 2: HTML Reports (Week 1-2)
1. Install jinja2 dependency (`pip install jinja2`)
2. Implement `HTMLReporter` class
3. Design responsive HTML template
4. Add `--html` CLI flag
5. Test on various repositories
6. **Testing**: Generate reports, verify formatting on desktop/mobile

### Phase 3: GitHub Issues (Week 2)
1. Implement `GitHubIssuesIntegration` class
2. Add `--create-issues` flag with `--github-repo` parameter
3. Implement dry-run mode
4. Add issue deduplication (don't create duplicates)
5. **Testing**: Create issues in test repo, verify content and labels

### Phase 4: VS Code Extension Foundation (Week 3)
1. Define findings JSON schema
2. Add `.vulnhuntr/vscode-findings.json` output
3. Document extension integration protocol
4. Create VS Code extension scaffold (separate project)
5. **Testing**: Manual validation of findings file format

### Phase 5: Webhook Integration (Week 3-4)
1. Implement `WebhookIntegration` class
2. Add webhook signature support (HMAC-SHA256)
3. Add `--webhook` CLI flag
4. Add retry logic for failed webhooks
5. **Testing**: Test with webhook.site, verify payloads

### Phase 6: Export Formats (Week 4)
1. Add JSON export (`--json` flag) - structured, machine-readable
2. Add CSV export (`--csv` flag) - for Excel/spreadsheet analysis
3. Add Markdown export (`--markdown` flag) - for documentation
4. Test all formats
5. **Testing**: Verify all export formats parse correctly

---

## CLI Interface

```bash
# Generate SARIF report
vulnhuntr -r /repo --sarif report.sarif

# Generate HTML report
vulnhuntr -r /repo --html report.html

# Create GitHub issues
vulnhuntr -r /repo --create-issues --github-repo owner/repo

# Send to webhook
vulnhuntr -r /repo --webhook https://api.example.com/vulnhuntr

# Multiple outputs
vulnhuntr -r /repo --sarif report.sarif --html report.html --json findings.json

# VS Code integration (automatic)
vulnhuntr -r /repo --vscode

# Export all formats
vulnhuntr -r /repo --export-all output_dir/
```

---

## Configuration File Support

**Add to `.vulnhuntr.yaml`**:

```yaml
# Reporting Configuration
reporting:
  # Default output formats (if no flags specified)
  default_formats:
    - console  # Always show in terminal
    - json     # Always save JSON
  
  # SARIF configuration
  sarif:
    enabled: false
    output_path: vulnhuntr-report.sarif
  
  # HTML configuration
  html:
    enabled: false
    output_path: vulnhuntr-report.html
    theme: default  # Future: support themes
  
  # GitHub Issues integration
  github_issues:
    enabled: false
    repository: owner/repo
    min_confidence: 7  # Only create issues for high-confidence findings
    labels:
      - security
      - vulnerability
  
  # Webhook integration
  webhook:
    enabled: false
    url: https://api.example.com/vulnhuntr
    secret_env_var: WEBHOOK_SECRET
    retry_attempts: 3
```

---

## Testing Strategy

### Unit Tests
```python
# tests/reporters/test_sarif.py
def test_sarif_generation():
    reporter = SARIFReporter()
    results = [{"vulnerability_found": True, "vulnerability_types": ["SQLI"], ...}]
    sarif = reporter.create_report(results, Path("/repo"))
    
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1
    assert sarif["runs"][0]["results"][0]["ruleId"] == "SQLI"

# tests/reporters/test_html.py
def test_html_generation(tmp_path):
    reporter = HTMLReporter()
    output = tmp_path / "report.html"
    reporter.generate([], Path("/repo"), output)
    
    assert output.exists()
    assert "Vulnhuntr Security Report" in output.read_text()
```

### Integration Tests
- Generate SARIF, validate with schema validator
- Upload SARIF to GitHub, verify findings appear
- Generate HTML, check all vulnerabilities present
- Create GitHub issues (in test repo), verify content

---

## Success Metrics

1. **SARIF Integration**: Reports upload to GitHub Code Scanning successfully
2. **HTML Reports**: Professional, shareable reports generated
3. **GitHub Issues**: Findings automatically tracked in issue tracker
4. **VS Code Extension**: Inline warnings display correctly
5. **Multiple Formats**: All export formats work correctly

---

## Documentation Updates

### README.md
- Add reporting section
- Document all output formats
- Explain integration options

### New: REPORTING.md
- Comprehensive reporting guide
- Format specifications
- Integration tutorials
- CI/CD examples

### New: INTEGRATIONS.md
- GitHub Issues setup
- VS Code extension installation
- Webhook configuration
- SARIF upload guide

---

## Future Enhancements

1. **PDF Reports**: Executive-friendly PDF generation
2. **JIRA Integration**: Direct ticket creation
3. **Slack/Teams Notifications**: Real-time alerts
4. **SonarQube Plugin**: Import findings
5. **Defect Dojo Integration**: Vulnerability management
6. **Custom Report Templates**: User-defined HTML templates

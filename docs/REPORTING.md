# Reporting and Export in Vulnhuntr

Vulnhuntr supports multiple report formats and integrations to fit into your security workflow. This document explains all available reporting options.

---

## Supported Report Formats

| Format | Standard | IDE Support | CI/CD | Best For |
|--------|----------|-------------|-------|----------|
| **SARIF** | ✅ Industry | ✅ VS Code, IntelliJ | ✅ GitHub Actions | CI/CD pipelines, automated workflows |
| **HTML** | ❌ Custom | ❌ External viewer | ⚠️ Artifact only | Management reporting, audit documentation |
| **JSON** | ✅ Standard | ⚠️ Limited | ✅ All systems | Custom tooling, data processing |
| **CSV** | ✅ Universal | ❌ External | ⚠️ Limited | Spreadsheet analysis, metrics tracking |
| **Markdown** | ✅ Standard | ✅ All editors | ✅ GitHub, GitLab | Documentation, PR descriptions |

---

## Quick Start

### Generate Single Report

```bash
# SARIF format (recommended for CI/CD)
vulnhuntr -r /path/to/repo --sarif report.sarif

# HTML report with styling
vulnhuntr -r /path/to/repo --html report.html

# JSON for custom processing
vulnhuntr -r /path/to/repo --json report.json

# CSV for spreadsheets
vulnhuntr -r /path/to/repo --csv report.csv

# Markdown for documentation
vulnhuntr -r /path/to/repo --markdown report.md
```

### Generate All Formats at Once

```bash
# Export all formats to a directory
vulnhuntr -r /path/to/repo --export-all ./reports

# Creates:
# - vulnhuntr_repo_20240205_143022.sarif
# - vulnhuntr_repo_20240205_143022.html
# - vulnhuntr_repo_20240205_143022.json
# - vulnhuntr_repo_20240205_143022.csv
# - vulnhuntr_repo_20240205_143022.md
```

### Multiple Specific Formats

```bash
vulnhuntr -r /path/to/repo \
  --sarif report.sarif \
  --html report.html \
  --json report.json
```

---

## SARIF Format

**SARIF** (Static Analysis Results Interchange Format) is the industry standard for static analysis tools.

### What is SARIF?

- JSON-based format for static analysis results
- OASIS standard (SARIF 2.1.0)
- Supported by GitHub, Azure DevOps, VS Code, IntelliJ
- Includes vulnerability metadata, locations, severity, CWE mappings

### Example SARIF Output

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Vulnhuntr",
        "version": "1.0.0",
        "informationUri": "https://github.com/protectai/vulnhuntr"
      }
    },
    "results": [{
      "ruleId": "SQLI",
      "level": "error",
      "message": {
        "text": "SQL Injection vulnerability detected..."
      },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {
            "uri": "api/routes.py"
          },
          "region": {
            "startLine": 45
          }
        }
      }],
      "properties": {
        "cwe": "CWE-89",
        "confidence": 8,
        "poc": "..."
      }
    }]
  }]
}
```

### Using SARIF

**VS Code:**
```bash
# Install SARIF Viewer extension
code --install-extension ms-sarif.sarif-viewer

# Open SARIF file in VS Code
code report.sarif
```

**GitHub Actions:**
```yaml
- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: report.sarif
```

---

## HTML Reports

Interactive, styled HTML reports with vulnerability details, code snippets, and navigation.

### Features

- **Responsive design** - Works on desktop and mobile
- **Syntax highlighting** - Code snippets with highlighting
- **Filtering** - By severity, vulnerability type
- **Sortable tables** - Click column headers
- **Expandable details** - Show/hide code context

### Example

```bash
vulnhuntr -r /path/to/repo --html security_report.html

# Open in browser
open security_report.html  # macOS
xdg-open security_report.html  # Linux
start security_report.html  # Windows
```

### Customization

HTML reports use Jinja2 templates. To customize:

1. Copy template from `vulnhuntr/reporters/templates/html_report.j2`
2. Modify styling, layout, content
3. Set template path in config:

```yaml
# .vulnhuntr.yaml
reporting:
  html:
    template: /path/to/custom_template.j2
    title: "Custom Security Report"
```

---

## JSON Reports

Structured JSON for custom processing and integration.

### Structure

```json
{
  "metadata": {
    "tool": "Vulnhuntr",
    "version": "1.0.0",
    "scan_timestamp": "2024-02-05T14:30:22",
    "repository": "/path/to/repo",
    "files_analyzed": 42,
    "total_cost_usd": 4.23
  },
  "findings": [
    {
      "id": "sqli-routes-45",
      "vulnerability_type": "SQLI",
      "severity": "high",
      "confidence": 8,
      "file_path": "api/routes.py",
      "line_number": 45,
      "function_name": "get_user",
      "description": "SQL Injection vulnerability...",
      "poc": "curl http://localhost/api/user?id=1' OR '1'='1",
      "cwe": "CWE-89",
      "context_code": {
        "get_db_connection": "def get_db_connection()...",
        "execute_query": "def execute_query(sql)..."
      }
    }
  ]
}
```

### Processing JSON

**Python:**
```python
import json

with open('report.json') as f:
    report = json.load(f)

high_severity = [f for f in report['findings'] 
                 if f['severity'] == 'high']
print(f"High severity findings: {len(high_severity)}")
```

**jq (command-line JSON processor):**
```bash
# Count findings by type
cat report.json | jq '.findings | group_by(.vulnerability_type) | map({type: .[0].vulnerability_type, count: length})'

# Extract high confidence findings
cat report.json | jq '.findings[] | select(.confidence >= 8)'
```

---

## CSV Reports

Tabular format for spreadsheet analysis and metrics tracking.

### Columns

| Column | Description |
|--------|-------------|
| `ID` | Unique finding identifier |
| `Vulnerability Type` | SQLI, XSS, RCE, etc. |
| `Severity` | critical, high, medium, low |
| `Confidence` | 0-10 score |
| `File Path` | Relative path to vulnerable file |
| `Line Number` | Line where vulnerability exists |
| `Function` | Function or method name |
| `CWE` | Common Weakness Enumeration ID |
| `Description` | Brief vulnerability description |
| `POC` | Proof-of-concept exploit |

### Example

```csv
ID,Vulnerability Type,Severity,Confidence,File Path,Line Number,Function,CWE,Description,POC
sqli-routes-45,SQLI,high,8,api/routes.py,45,get_user,CWE-89,SQL Injection via user_id parameter,"curl http://localhost/api/user?id=1' OR '1'='1"
xss-views-78,XSS,medium,7,web/views.py,78,render_comment,CWE-79,Reflected XSS in comment rendering,<script>alert(1)</script>
```

### Using CSV

**Excel/Google Sheets:**
- Open CSV directly
- Use Data → Filter to sort/filter
- Create pivot tables for metrics

**Command-line (csvkit):**
```bash
# Install csvkit
pip install csvkit

# Summary statistics
csvstat report.csv

# Filter high severity
csvgrep -c Severity -m "high" report.csv

# Convert to JSON
csvjson report.csv > report.json
```

---

## Markdown Reports

Human-readable reports suitable for documentation and PR descriptions.

### Features

- **GitHub Flavored Markdown** - Renders perfectly on GitHub/GitLab
- **Code blocks with syntax highlighting**
- **Collapsible sections** - `<details>` tags for context code
- **Tables** - Summary and findings tables
- **Links** - Jump to file locations

### Example Output

```markdown
# Vulnhuntr Security Report

**Repository:** my-app  
**Scan Date:** 2024-02-05 14:30:22  
**Files Analyzed:** 42  
**Total Cost:** $4.23 USD  

## Summary

| Vulnerability Type | Count | Highest Confidence |
|--------------------|-------|--------------------|
| SQL Injection      | 3     | 8                  |
| XSS                | 2     | 7                  |
| SSRF               | 1     | 6                  |

## Findings

### 1. SQL Injection in `api/routes.py:45`

**Severity:** High  
**Confidence:** 8/10  
**CWE:** CWE-89  

**Description:**
SQL Injection vulnerability detected in `get_user` function...

**Proof-of-Concept:**
```bash
curl http://localhost/api/user?id=1' OR '1'='1
```

<details>
<summary>Context Code</summary>

```python
def get_user(user_id):
    conn = get_db_connection()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return conn.execute(query)
```
</details>
```

### Using Markdown Reports

**As PR Description:**
```bash
vulnhuntr -r /path/to/repo --markdown findings.md

# Copy content to PR description
cat findings.md | pbcopy  # macOS
cat findings.md | xclip -selection clipboard  # Linux
```

**In Documentation:**
```bash
# Add to docs folder
vulnhuntr -r /path/to/repo --markdown docs/security_audit.md

# Commit to repo
git add docs/security_audit.md
git commit -m "docs: add security audit report"
```

---

## Export All Formats

The `--export-all` flag is a convenience feature to generate all report formats at once.

### Usage

```bash
vulnhuntr -r /path/to/repo --export-all ./reports
```

### File Naming

All files use the pattern: `vulnhuntr_{repo_name}_{timestamp}.{ext}`

Example:
```
reports/
  vulnhuntr_my-app_20240205_143022.sarif
  vulnhuntr_my-app_20240205_143022.html
  vulnhuntr_my-app_20240205_143022.json
  vulnhuntr_my-app_20240205_143022.csv
  vulnhuntr_my-app_20240205_143022.md
```

### Configuration

```yaml
# .vulnhuntr.yaml
reporting:
  export_all:
    directory: "./security-reports"
    include_timestamp: true
    formats: ["sarif", "html", "json", "csv", "markdown"]
```

---

## Configuration

### Global Report Settings

```yaml
# .vulnhuntr.yaml
reporting:
  # Minimum confidence to include in reports (0-10)
  min_confidence: 5
  
  # Include context code in reports
  include_context: true
  
  # Include proof-of-concept exploits
  include_poc: true
  
  # SARIF specific settings
  sarif:
    version: "2.1.0"
    include_snippets: true
    
  # HTML specific settings
  html:
    template: null  # Path to custom template
    title: "Vulnhuntr Security Report"
    theme: "default"  # or "dark"
    
  # JSON specific settings
  json:
    pretty_print: true
    indent: 2
```

---

## Best Practices

### 1. Use SARIF for CI/CD

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  vulnhuntr:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Run Vulnhuntr
        run: |
          vulnhuntr -r . \
            --sarif vulnhuntr.sarif \
            --budget 10.00
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: vulnhuntr.sarif
```

### 2. Generate HTML for Stakeholders

```bash
# Include in reports for management/auditors
vulnhuntr -r /path/to/repo \
  --html reports/security_audit_$(date +%Y%m%d).html
```

### 3. Use JSON for Metrics Tracking

```bash
# Store JSON reports over time
vulnhuntr -r /path/to/repo --json reports/$(git rev-parse HEAD).json

# Track vulnerability trends
python scripts/analyze_trends.py reports/*.json
```

### 4. Export All for Comprehensive Audit

```bash
# Generate all formats for compliance/audit
vulnhuntr -r /path/to/repo --export-all audit_reports/
```

---

## Troubleshooting

### "Failed to write report" Error

**Cause:** Directory doesn't exist or permission denied

**Solution:**
```bash
# Create directory first
mkdir -p reports/

# Check permissions
ls -ld reports/
```

### SARIF Not Rendering in VS Code

**Cause:** SARIF Viewer extension not installed

**Solution:**
```bash
code --install-extension ms-sarif.sarif-viewer
```

### HTML Report Missing Styling

**Cause:** Template not found or CSS file missing

**Solution:**
- Ensure `vulnhuntr/reporters/templates/html_report.j2` exists
- Check that Jinja2 is installed: `pip install jinja2`

### CSV Opens with Wrong Encoding

**Cause:** Excel expects UTF-8 BOM for UTF-8 files

**Solution:**
```bash
# Add BOM to CSV
printf '\xEF\xBB\xBF' | cat - report.csv > report_excel.csv
```

---

## API Reference

### SARIFReporter

```python
from vulnhuntr.reporters import SARIFReporter
from pathlib import Path

reporter = SARIFReporter(
    tool_name="Vulnhuntr",
    tool_version="1.0.0",
    repo_root=Path("/path/to/repo"),
)

reporter.add_findings(findings)
reporter.write(Path("report.sarif"))
```

### HTMLReporter

```python
from vulnhuntr.reporters import HTMLReporter

reporter = HTMLReporter(
    title="Security Audit Report",
    repo_root=Path("/path/to/repo"),
)

reporter.add_findings(findings)
reporter.write(Path("report.html"))
```

### JSONReporter

```python
from vulnhuntr.reporters import JSONReporter

reporter = JSONReporter(repo_root=Path("/path/to/repo"))
reporter.add_findings(findings)
reporter.write(Path("report.json"))
```

---

## See Also

- [INTEGRATIONS.md](INTEGRATIONS.md) - GitHub Issues, webhooks, and CI/CD
- [COST_MANAGEMENT.md](COST_MANAGEMENT.md) - Managing analysis costs
- [QUICKSTART.md](../QUICKSTART.md) - Getting started guide
- [Development Path: Reporting](development_path/02_reporting_integration.md) - Implementation details

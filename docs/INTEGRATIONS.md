# Integrations in Vulnhuntr

Vulnhuntr integrates with popular platforms and workflows to streamline vulnerability management. This document explains how to set up and use all available integrations.

---

## Supported Integrations

| Integration | Purpose | Setup Difficulty | Best For |
|-------------|---------|------------------|----------|
| **GitHub Issues** | Automated issue creation | Easy | GitHub-hosted projects |
| **Webhooks** | Real-time notifications | Medium | Custom workflows, Slack, Discord |
| **CI/CD Pipelines** | Automated scans | Medium | All CI/CD platforms |
| **SARIF Upload** | GitHub Security tab | Easy | GitHub Actions workflows |

---

## GitHub Issues Integration

Automatically create GitHub Issues for each finding with proper labels, assignees, and templates.

### Quick Start

```bash
# Set environment variables
export GITHUB_TOKEN="ghp_your_token_here"
export GITHUB_OWNER="your-username"
export GITHUB_REPO="your-repo"

# Run scan with issue creation
vulnhuntr -r /path/to/repo --create-issues
```

### Configuration

**Via Environment Variables:**
```bash
export GITHUB_TOKEN="ghp_..."          # GitHub Personal Access Token
export GITHUB_OWNER="protectai"        # Repository owner
export GITHUB_REPO="vulnhuntr"         # Repository name
export GITHUB_LABELS="security,high-priority"  # Optional: comma-separated labels
export GITHUB_ASSIGNEES="username1,username2"  # Optional: comma-separated usernames
```

**Via Configuration File:**
```yaml
# .vulnhuntr.yaml
integrations:
  github:
    enabled: true
    token: ${GITHUB_TOKEN}  # Use env var
    owner: "protectai"
    repo: "vulnhuntr"
    labels:
      - "security"
      - "vulnhuntr"
      - "high-priority"
    assignees:
      - "security-team"
    # Prevent duplicate issues
    check_duplicates: true
    # Issue template path (optional)
    template_path: ".github/ISSUE_TEMPLATE/security.md"
```

### Creating GitHub Token

1. Go to GitHub Settings → Developer settings → Personal access tokens
2. Click "Generate new token (classic)"
3. Select scopes:
   - `repo` (full control of private repositories)
   - `public_repo` (for public repositories)
4. Generate and copy token
5. Store securely: `export GITHUB_TOKEN="ghp_..."`

### Issue Format

Vulnhuntr creates issues with:

**Title:**
```
[SECURITY] SQL Injection in api/routes.py:45
```

**Body:**
```markdown
## Vulnerability Details

**Type:** SQL Injection (SQLI)  
**Severity:** High  
**Confidence:** 8/10  
**CWE:** CWE-89  
**File:** api/routes.py  
**Line:** 45  
**Function:** get_user  

## Description

SQL Injection vulnerability detected in the `get_user` function...

## Proof-of-Concept

```bash
curl http://localhost/api/user?id=1' OR '1'='1
```

## Context Code

```python
def get_user(user_id):
    conn = get_db_connection()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return conn.execute(query)
```

## Recommendations

1. Use parameterized queries
2. Validate and sanitize user input
3. Use ORM instead of raw SQL

## Scan Information

- **Scanned by:** Vulnhuntr v1.0.0
- **Scan date:** 2024-02-05 14:30:22
- **Repository:** /path/to/repo
```

**Labels:**
- `security`
- `vulnhuntr`
- `sqli` (vulnerability type)
- Custom labels from config

### Duplicate Detection

Vulnhuntr checks for existing issues to avoid duplicates:

- Searches for open issues with same file + line + vuln type
- Skips creation if duplicate found
- Logs duplicate skips for reporting

**Output:**
```
✓ GitHub issues: 3 created, 2 skipped (duplicates), 0 failed
```

### Troubleshooting

**Error: "GitHub integration requires GITHUB_TOKEN"**
```bash
# Verify token is set
echo $GITHUB_TOKEN

# Re-export if missing
export GITHUB_TOKEN="ghp_..."
```

**Error: "403 Forbidden"**
- Token doesn't have required permissions
- Regenerate token with `repo` scope

**Error: "404 Not Found"**
- Owner or repo name incorrect
- Check: `https://github.com/$GITHUB_OWNER/$GITHUB_REPO`

---

## Webhook Integration

Send findings to webhook endpoints for custom processing, notifications, or integrations.

### Quick Start

```bash
# Basic webhook (JSON format)
vulnhuntr -r /path/to/repo --webhook https://your-webhook.com/vulnhuntr

# Slack format
vulnhuntr -r /path/to/repo \
  --webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
  --webhook-format slack

# With HMAC signature
vulnhuntr -r /path/to/repo \
  --webhook https://your-webhook.com/vulnhuntr \
  --webhook-secret "your-secret-key"
```

### Supported Formats

#### 1. JSON (Default)

**Request:**
```json
{
  "scan_summary": {
    "repo_path": "/path/to/repo",
    "files_analyzed": 42,
    "total_findings": 5,
    "total_cost_usd": 4.23,
    "timestamp": "2024-02-05T14:30:22"
  },
  "findings": [
    {
      "id": "sqli-routes-45",
      "vulnerability_type": "SQLI",
      "severity": "high",
      "confidence": 8,
      "file_path": "api/routes.py",
      "line_number": 45,
      "description": "SQL Injection vulnerability...",
      "poc": "curl http://localhost/api/user?id=1' OR '1'='1"
    }
  ]
}
```

#### 2. Slack

**Message:**
```
🔴 *Security Scan Alert*

Found 5 vulnerabilities in my-app

*High Severity:*
• SQL Injection in `api/routes.py:45` (confidence: 8/10)
• XSS in `web/views.py:78` (confidence: 7/10)

*Medium Severity:*
• SSRF in `integrations/fetch.py:32` (confidence: 6/10)

Scan completed at 2024-02-05 14:30:22
Total cost: $4.23 USD
```

#### 3. Discord

**Embed:**
```json
{
  "embeds": [{
    "title": "Vulnhuntr Security Scan",
    "description": "Found 5 vulnerabilities",
    "color": 15158332,
    "fields": [
      {
        "name": "SQL Injection",
        "value": "api/routes.py:45 (confidence: 8/10)",
        "inline": false
      }
    ],
    "timestamp": "2024-02-05T14:30:22"
  }]
}
```

#### 4. Microsoft Teams

**Adaptive Card:**
```json
{
  "@type": "MessageCard",
  "summary": "Vulnhuntr found 5 vulnerabilities",
  "sections": [{
    "activityTitle": "Security Scan Complete",
    "facts": [
      {"name": "Repository", "value": "my-app"},
      {"name": "Findings", "value": "5"},
      {"name": "High Severity", "value": "2"}
    ]
  }]
}
```

### HMAC Signatures

For webhook security, Vulnhuntr can sign payloads with HMAC-SHA256:

**Configuration:**
```bash
export WEBHOOK_SECRET="your-secret-key"
vulnhuntr -r /path/to/repo --webhook https://your-webhook.com/vulnhuntr
```

**Headers:**
```
X-Vulnhuntr-Signature-256: sha256=abc123...
X-Vulnhuntr-Timestamp: 1707145822
X-Vulnhuntr-Version: 1.0.0
```

**Verification (Python):**
```python
import hmac
import hashlib

def verify_signature(payload, signature, secret):
    expected = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)

# In your webhook handler
is_valid = verify_signature(
    request.body,
    request.headers['X-Vulnhuntr-Signature-256'],
    os.getenv('WEBHOOK_SECRET')
)
```

### Custom Webhook Server

**Example (Flask):**
```python
from flask import Flask, request
import hmac
import hashlib

app = Flask(__name__)

@app.route('/vulnhuntr', methods=['POST'])
def handle_scan():
    # Verify signature
    signature = request.headers.get('X-Vulnhuntr-Signature-256')
    secret = os.getenv('WEBHOOK_SECRET')
    
    if not verify_signature(request.data, signature, secret):
        return 'Invalid signature', 401
    
    # Process findings
    data = request.json
    findings = data['findings']
    
    # Send notifications, create tickets, etc.
    for finding in findings:
        if finding['severity'] == 'high':
            send_pagerduty_alert(finding)
    
    return 'OK', 200
```

---

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Vulnhuntr Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.12'
      
      - name: Install Vulnhuntr
        run: |
          pip install vulnhuntr
      
      - name: Run Security Scan
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          vulnhuntr -r . \
            --sarif vulnhuntr.sarif \
            --budget 10.00 \
            --no-checkpoint
      
      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: vulnhuntr.sarif
      
      - name: Create Issues for Findings
        if: github.event_name == 'push'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITHUB_OWNER: ${{ github.repository_owner }}
          GITHUB_REPO: ${{ github.event.repository.name }}
        run: |
          vulnhuntr -r . --create-issues
```

### GitLab CI

```yaml
# .gitlab-ci.yml
security-scan:
  image: python:3.12
  stage: test
  
  before_script:
    - pip install vulnhuntr
  
  script:
    - |
      vulnhuntr -r . \
        --json vulnhuntr.json \
        --budget 10.00 \
        --no-checkpoint
  
  artifacts:
    reports:
      vulnhuntr: vulnhuntr.json
    paths:
      - vulnhuntr.json
    when: always
  
  only:
    - merge_requests
    - main
```

### Jenkins

```groovy
// Jenkinsfile
pipeline {
    agent any
    
    environment {
        ANTHROPIC_API_KEY = credentials('anthropic-api-key')
    }
    
    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    pip install vulnhuntr
                    
                    vulnhuntr -r . \
                        --sarif vulnhuntr.sarif \
                        --json vulnhuntr.json \
                        --budget 10.00 \
                        --no-checkpoint
                '''
            }
        }
        
        stage('Publish Results') {
            steps {
                recordIssues(
                    tools: [sarif(pattern: 'vulnhuntr.sarif')]
                )
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'vulnhuntr.*'
        }
    }
}
```

### CircleCI

```yaml
# .circleci/config.yml
version: 2.1

jobs:
  security-scan:
    docker:
      - image: python:3.12
    
    steps:
      - checkout
      
      - run:
          name: Install Vulnhuntr
          command: pip install vulnhuntr
      
      - run:
          name: Run Security Scan
          command: |
            vulnhuntr -r . \
              --json vulnhuntr.json \
              --budget 10.00 \
              --no-checkpoint
      
      - store_artifacts:
          path: vulnhuntr.json
          destination: security-reports

workflows:
  version: 2
  security:
    jobs:
      - security-scan:
          filters:
            branches:
              only:
                - main
                - develop
```

---

## SARIF Upload to GitHub

Upload SARIF reports to GitHub Security tab for centralized vulnerability tracking.

### Setup

```yaml
# .github/workflows/security.yml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: vulnhuntr.sarif
    category: vulnhuntr
```

### Viewing Results

1. Go to repository on GitHub
2. Click "Security" tab
3. Click "Code scanning alerts"
4. Filter by "vulnhuntr" category

### Benefits

- ✅ Centralized vulnerability dashboard
- ✅ Track fixes and dismissals
- ✅ Integration with GitHub Projects
- ✅ Email notifications
- ✅ PR checks (block merge on findings)

---

## Pre-commit Hook

Run Vulnhuntr before commits to catch vulnerabilities early.

### Setup

```bash
# Install pre-commit
pip install pre-commit

# Create .pre-commit-config.yaml
cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: local
    hooks:
      - id: vulnhuntr
        name: Vulnhuntr Security Scan
        entry: bash -c 'vulnhuntr -r . -a ${FILES} --budget 1.00 --no-checkpoint'
        language: system
        pass_filenames: true
        types: [python]
EOF

# Install hook
pre-commit install
```

### Configuration

For faster commits, only scan changed files:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: vulnhuntr-changed
        name: Vulnhuntr (Changed Files Only)
        entry: vulnhuntr
        args:
          - "-r"
          - "."
          - "-a"
          - "${FILES}"
          - "--budget"
          - "0.50"
          - "--no-checkpoint"
        language: system
        pass_filenames: true
        types: [python]
```

---

## Configuration

### Global Integration Settings

```yaml
# .vulnhuntr.yaml
integrations:
  # GitHub Issues
  github:
    enabled: true
    token: ${GITHUB_TOKEN}
    owner: "your-org"
    repo: "your-repo"
    labels:
      - "security"
      - "vulnhuntr"
    assignees:
      - "security-team"
    check_duplicates: true
    
  # Webhooks
  webhook:
    enabled: false
    url: "https://your-webhook.com/vulnhuntr"
    format: "json"  # json, slack, discord, teams
    secret: ${WEBHOOK_SECRET}
    timeout: 30  # seconds
    retry_count: 3
    
  # CI/CD specific
  ci:
    # Fail build on findings
    fail_on_findings: false
    
    # Minimum confidence to fail (0-10)
    fail_threshold: 7
    
    # Allowed vulnerability types before failing
    max_findings: 0
```

---

## Best Practices

### 1. Use SARIF in CI/CD

```yaml
# Always generate SARIF for visibility
vulnhuntr -r . --sarif vulnhuntr.sarif
```

### 2. Separate Scans for PRs vs Main

```yaml
# PR: Quick scan, block on high confidence
on: pull_request
run: vulnhuntr -r . --budget 5.00

# Main: Full scan, create issues
on: push
run: vulnhuntr -r . --budget 20.00 --create-issues
```

### 3. Use Webhooks for Real-time Alerts

```bash
# Send critical findings to Slack immediately
vulnhuntr -r . \
  --webhook $SLACK_WEBHOOK \
  --webhook-format slack
```

### 4. Secure Webhook Endpoints

```bash
# Always use HMAC signatures
export WEBHOOK_SECRET="random-secure-string"
vulnhuntr -r . --webhook $WEBHOOK_URL
```

### 5. Cost Management in CI

```yaml
# Set strict budgets for CI/CD
vulnhuntr -r . --budget 10.00 --no-checkpoint
```

---

## Troubleshooting

### GitHub Issues Not Creating

**Check:**
1. Token has `repo` permission
2. Owner and repo are correct
3. No rate limiting (GitHub API has limits)

**Debug:**
```bash
# Test GitHub API access
curl -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/repos/$GITHUB_OWNER/$GITHUB_REPO
```

### Webhook Not Receiving Data

**Check:**
1. URL is accessible from scan environment
2. Endpoint accepts POST requests
3. Webhook secret matches (if using HMAC)

**Debug:**
```bash
# Test webhook with curl
curl -X POST https://your-webhook.com/vulnhuntr \
  -H "Content-Type: application/json" \
  -d '{"test": true}'
```

### SARIF Upload Failing

**Check:**
1. SARIF file is valid JSON
2. File size < 10MB
3. GitHub Actions has `security-events: write` permission

**Debug:**
```bash
# Validate SARIF
cat vulnhuntr.sarif | jq .
```

---

## API Reference

### GitHubIssueCreator

```python
from vulnhuntr.integrations import GitHubIssueCreator, GitHubConfig

config = GitHubConfig(
    token=os.getenv("GITHUB_TOKEN"),
    owner="protectai",
    repo="vulnhuntr",
    labels=["security", "vulnhuntr"],
)

creator = GitHubIssueCreator(config)
results = creator.create_issues_for_findings(findings)

for result in results:
    print(f"Issue #{result.issue_number}: {result.created}")
```

### WebhookNotifier

```python
from vulnhuntr.integrations import WebhookNotifier, PayloadFormat

notifier = WebhookNotifier(
    webhook_url="https://your-webhook.com/vulnhuntr",
    payload_format=PayloadFormat.SLACK,
    secret="your-secret",
)

success = notifier.send_findings(
    findings=findings,
    scan_summary={"repo_path": "/path/to/repo", ...}
)
```

---

## See Also

- [REPORTING.md](REPORTING.md) - Report formats and export options
- [COST_MANAGEMENT.md](COST_MANAGEMENT.md) - Managing analysis costs in CI/CD
- [QUICKSTART.md](../QUICKSTART.md) - Getting started guide
- [Development Path: Reporting & Integration](development_path/02_reporting_integration.md) - Implementation details

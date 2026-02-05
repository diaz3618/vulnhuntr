# Development Path: False Positive Reduction

**Priority**: HIGH - Immediate Impact  
**Complexity**: High  
**Estimated Effort**: 4-6 weeks  
**Dependencies**: Cost Management (for budget-aware verification)

---

## Current State Analysis

### False Positive Problem

**From codebase analysis** (`__main__.py`, `prompts.py`):

1. **Subjective Confidence Scores**:
   - LLM generates 0-10 confidence score
   - No calibration or validation
   - User must manually verify all findings

2. **No Learning Mechanism**:
   - Can't mark false positives
   - No feedback loop to LLM
   - Same false positives repeat on re-run

3. **No CVE Cross-Reference**:
   - Doesn't check if vulnerability is known
   - No comparison with public databases
   - Misses confirmed vulnerable patterns

4. **No Taint Analysis**:
   - Relies purely on LLM reasoning
   - Can't verify data flow statically
   - May miss sanitization steps

### False Positive Examples

```python
# FALSE POSITIVE: Input is validated
@app.route('/user/<int:user_id>')  # <int:> enforces integer type
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    # Vulnhuntr might flag as SQLi, but <int:> prevents injection

# FALSE POSITIVE: Framework provides sanitization
from django.db import models
def get_users(name):
    User.objects.filter(name=name)  # Django ORM sanitizes automatically
    # Vulnhuntr might flag as SQLi, but ORM is safe

# TRUE POSITIVE: Actual vulnerability
@app.route('/search')
def search():
    query = request.args.get('q')
    results = db.execute(f"SELECT * FROM data WHERE name = '{query}'")
    # Real SQLi vulnerability
```

---

## Technical Architecture

### 1. Human Feedback Loop

**Implementation**: `vulnhuntr/feedback.py`

```python
from enum import Enum
from typing import Dict, List
from datetime import datetime
import json

class FeedbackType(Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    UNCERTAIN = "uncertain"

class FeedbackStore:
    """Store human feedback on vulnerability findings"""
    
    def __init__(self, feedback_file: Path = None):
        self.feedback_file = feedback_file or Path(".vulnhuntr_feedback.json")
        self.feedback: List[Dict] = []
        self._load()
    
    def _load(self):
        """Load feedback from disk"""
        if self.feedback_file.exists():
            self.feedback = json.loads(self.feedback_file.read_text())
    
    def _save(self):
        """Save feedback to disk"""
        self.feedback_file.write_text(json.dumps(self.feedback, indent=2))
    
    def add_feedback(self, finding: Dict, feedback_type: FeedbackType, 
                    notes: str = ""):
        """Record feedback on a finding"""
        
        feedback_entry = {
            'timestamp': datetime.now().isoformat(),
            'file': finding['file'],
            'vuln_type': finding['vuln_type'],
            'confidence': finding['confidence'],
            'source': finding.get('source'),
            'sink': finding.get('sink'),
            'feedback': feedback_type.value,
            'notes': notes,
            'finding_hash': self._hash_finding(finding)
        }
        
        self.feedback.append(feedback_entry)
        self._save()
        
        print(f"[✓] Feedback recorded: {feedback_type.value}")
    
    def get_similar_findings(self, finding: Dict) -> List[Dict]:
        """Find similar findings with feedback"""
        
        finding_hash = self._hash_finding(finding)
        similar = []
        
        for entry in self.feedback:
            # Exact match
            if entry['finding_hash'] == finding_hash:
                similar.append(entry)
            # Same file + vuln type
            elif (entry['file'] == finding['file'] and 
                  entry['vuln_type'] == finding['vuln_type']):
                similar.append(entry)
        
        return similar
    
    def _hash_finding(self, finding: Dict) -> str:
        """Create hash of finding for deduplication"""
        import hashlib
        key = f"{finding['file']}:{finding['vuln_type']}:{finding.get('source')}:{finding.get('sink')}"
        return hashlib.md5(key.encode()).hexdigest()
    
    def get_false_positive_rate(self) -> float:
        """Calculate false positive rate from feedback"""
        if not self.feedback:
            return 0.0
        
        total = len(self.feedback)
        false_positives = sum(1 for f in self.feedback 
                            if f['feedback'] == FeedbackType.FALSE_POSITIVE.value)
        
        return false_positives / total
```

**Interactive Feedback CLI**:
```python
# In __main__.py after analysis
def interactive_feedback(findings: List[Dict], feedback_store: FeedbackStore):
    """Prompt user for feedback on findings"""
    
    print("\n[*] Review findings and provide feedback (Ctrl+C to skip):\n")
    
    for i, finding in enumerate(findings, 1):
        print(f"\n--- Finding {i}/{len(findings)} ---")
        print(f"File: {finding['file']}")
        print(f"Type: {finding['vuln_type']}")
        print(f"Confidence: {finding['confidence']}/10")
        print(f"Analysis: {finding['analysis'][:200]}...")
        
        # Check for similar past findings
        similar = feedback_store.get_similar_findings(finding)
        if similar:
            print(f"\n[!] Found {len(similar)} similar past findings:")
            for s in similar[:3]:
                print(f"  - {s['feedback']} ({s['timestamp'][:10]}) - {s['notes'][:50]}")
        
        # Prompt for feedback
        while True:
            response = input("\nFeedback? [t]rue positive, [f]alse positive, [u]ncertain, [s]kip: ").lower()
            
            if response == 's':
                break
            elif response in ['t', 'f', 'u']:
                feedback_type = {
                    't': FeedbackType.TRUE_POSITIVE,
                    'f': FeedbackType.FALSE_POSITIVE,
                    'u': FeedbackType.UNCERTAIN
                }[response]
                
                notes = input("Notes (optional): ").strip()
                feedback_store.add_feedback(finding, feedback_type, notes)
                break
            else:
                print("Invalid input. Try again.")
```

### 2. ML Classifier Layer

**Implementation**: `vulnhuntr/classifier.py`

```python
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib

class VulnerabilityClassifier:
    """ML classifier to refine LLM predictions"""
    
    def __init__(self, model_file: Path = None):
        self.model_file = model_file or Path(".vulnhuntr_model.pkl")
        self.vectorizer = TfidfVectorizer(max_features=500)
        self.classifier = RandomForestClassifier(n_estimators=100)
        self.trained = False
        
        if self.model_file.exists():
            self._load_model()
    
    def _load_model(self):
        """Load trained model from disk"""
        data = joblib.load(self.model_file)
        self.vectorizer = data['vectorizer']
        self.classifier = data['classifier']
        self.trained = True
    
    def _save_model(self):
        """Save trained model to disk"""
        data = {
            'vectorizer': self.vectorizer,
            'classifier': self.classifier
        }
        joblib.dump(data, self.model_file)
    
    def train_from_feedback(self, feedback_store: FeedbackStore):
        """Train classifier on human feedback"""
        
        # Extract features and labels
        X = []
        y = []
        
        for entry in feedback_store.feedback:
            if entry['feedback'] == 'uncertain':
                continue  # Skip uncertain entries
            
            # Feature engineering
            features_text = f"""
            file: {entry['file']}
            vuln_type: {entry['vuln_type']}
            confidence: {entry['confidence']}
            source: {entry.get('source', '')}
            sink: {entry.get('sink', '')}
            """
            
            X.append(features_text)
            y.append(1 if entry['feedback'] == 'true_positive' else 0)
        
        if len(X) < 10:
            print("[!] Not enough feedback for training (need at least 10 entries)")
            return False
        
        # Train
        X_vec = self.vectorizer.fit_transform(X)
        self.classifier.fit(X_vec, y)
        self.trained = True
        
        self._save_model()
        
        print(f"[✓] Classifier trained on {len(X)} examples")
        return True
    
    def predict_probability(self, finding: Dict) -> float:
        """Predict probability of true positive"""
        
        if not self.trained:
            return finding['confidence'] / 10  # Fallback to LLM confidence
        
        # Feature engineering (same as training)
        features_text = f"""
        file: {finding['file']}
        vuln_type: {finding['vuln_type']}
        confidence: {finding['confidence']}
        source: {finding.get('source', '')}
        sink: {finding.get('sink', '')}
        """
        
        X_vec = self.vectorizer.transform([features_text])
        prob = self.classifier.predict_proba(X_vec)[0][1]  # Prob of class 1 (true positive)
        
        return prob
    
    def refine_findings(self, findings: List[Dict]) -> List[Dict]:
        """Add refined confidence scores"""
        
        for finding in findings:
            llm_confidence = finding['confidence'] / 10
            ml_confidence = self.predict_probability(finding)
            
            # Weighted average (60% ML, 40% LLM)
            refined_confidence = 0.6 * ml_confidence + 0.4 * llm_confidence
            
            finding['llm_confidence'] = llm_confidence
            finding['ml_confidence'] = ml_confidence
            finding['refined_confidence'] = refined_confidence
        
        # Re-sort by refined confidence
        findings.sort(key=lambda f: f['refined_confidence'], reverse=True)
        
        return findings
```

### 3. CVE Database Cross-Reference

**Implementation**: `vulnhuntr/cve_matcher.py`

```python
import requests
from typing import List, Dict, Optional

class CVEMatcher:
    """Cross-reference findings with known CVEs"""
    
    def __init__(self):
        self.cve_cache: Dict[str, List] = {}
    
    def search_cves(self, package_name: str, vuln_type: str) -> List[Dict]:
        """Search NVD for CVEs related to package/vulnerability"""
        
        # Check cache
        cache_key = f"{package_name}:{vuln_type}"
        if cache_key in self.cve_cache:
            return self.cve_cache[cache_key]
        
        # Query NVD API
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            'keywordSearch': f"{package_name} {vuln_type}",
            'resultsPerPage': 10
        }
        
        try:
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            cves = []
            
            for item in data.get('vulnerabilities', []):
                cve = item['cve']
                cves.append({
                    'id': cve['id'],
                    'description': cve['descriptions'][0]['value'],
                    'severity': cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('baseSeverity'),
                    'url': f"https://nvd.nist.gov/vuln/detail/{cve['id']}"
                })
            
            self.cve_cache[cache_key] = cves
            return cves
            
        except Exception as e:
            log.warning("CVE search failed", error=str(e))
            return []
    
    def enrich_findings(self, findings: List[Dict]) -> List[Dict]:
        """Add CVE references to findings"""
        
        for finding in findings:
            # Extract package name from file path
            file_path = Path(finding['file'])
            # Heuristic: top-level directory name
            package_name = file_path.parts[0] if file_path.parts else "unknown"
            
            # Search CVEs
            cves = self.search_cves(package_name, finding['vuln_type'])
            
            if cves:
                finding['related_cves'] = cves
                finding['cve_confirmed'] = True
                print(f"[✓] Found {len(cves)} related CVEs for {finding['file']}")
            else:
                finding['related_cves'] = []
                finding['cve_confirmed'] = False
        
        return findings
```

### 4. Taint Analysis Engine

**Implementation**: `vulnhuntr/taint.py`

```python
import ast
from typing import Set, Dict, List

class TaintAnalyzer:
    """Static taint analysis to verify data flow"""
    
    def analyze_flow(self, file_content: str, source: str, sink: str) -> Dict:
        """Verify if tainted data flows from source to sink"""
        
        try:
            tree = ast.parse(file_content)
        except SyntaxError:
            return {'verified': False, 'reason': 'Parse error'}
        
        # Find source node
        source_vars = self._find_tainted_vars(tree, source)
        
        if not source_vars:
            return {'verified': False, 'reason': 'Source not found'}
        
        # Trace data flow
        flow_path = self._trace_flow(tree, source_vars, sink)
        
        if flow_path:
            # Check for sanitization
            sanitized = self._check_sanitization(tree, flow_path)
            
            return {
                'verified': not sanitized,
                'flow_path': flow_path,
                'sanitized': sanitized,
                'reason': 'Sanitization found' if sanitized else 'Direct flow confirmed'
            }
        else:
            return {'verified': False, 'reason': 'No data flow found'}
    
    def _find_tainted_vars(self, tree: ast.AST, source: str) -> Set[str]:
        """Find variables tainted by source"""
        tainted = set()
        
        for node in ast.walk(tree):
            # request.args.get('q') → tainted = {'q'}
            if isinstance(node, ast.Call):
                if source in ast.unparse(node):
                    # Find assignment target
                    parent = self._find_parent(tree, node)
                    if isinstance(parent, ast.Assign):
                        for target in parent.targets:
                            if isinstance(target, ast.Name):
                                tainted.add(target.id)
        
        return tainted
    
    def _trace_flow(self, tree: ast.AST, tainted_vars: Set[str], 
                   sink: str) -> Optional[List[str]]:
        """Trace flow of tainted variables to sink"""
        # Simplified: Check if tainted var is used in sink call
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and sink in ast.unparse(node):
                # Check if any tainted var is in arguments
                for arg in ast.walk(node):
                    if isinstance(arg, ast.Name) and arg.id in tainted_vars:
                        return [arg.id]  # Found flow
        
        return None
    
    def _check_sanitization(self, tree: ast.AST, flow_path: List[str]) -> bool:
        """Check if sanitization functions are applied"""
        
        sanitizers = [
            'escape', 'sanitize', 'clean', 'filter', 
            'validate', 'quote', 'encode', 'parameterize'
        ]
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ast.unparse(node.func).lower()
                if any(s in func_name for s in sanitizers):
                    # Check if tainted var is argument
                    for arg in node.args:
                        if isinstance(arg, ast.Name) and arg.id in flow_path:
                            return True  # Sanitized
        
        return False
```

---

## Implementation Plan

### Phase 1: Human Feedback (Week 1-2)
1. Implement `FeedbackStore` class
2. Add interactive feedback CLI
3. Store feedback to `.vulnhuntr_feedback.json`
4. Test feedback collection
5. **Testing**: Verify feedback is recorded accurately

### Phase 2: ML Classifier (Week 2-3)
1. Implement `VulnerabilityClassifier` class
2. Add training from feedback
3. Integrate refined scoring
4. Test with synthetic feedback data
5. **Testing**: Verify classifier improves accuracy

### Phase 3: CVE Cross-Reference (Week 3-4)
1. Implement `CVEMatcher` class
2. Integrate NVD API
3. Add CVE references to reports
4. Cache CVE queries
5. **Testing**: Verify CVE matches are relevant

### Phase 4: Taint Analysis (Week 4-5)
1. Implement `TaintAnalyzer` class
2. Integrate with main analysis
3. Filter out sanitized flows
4. Test on known vulnerable code
5. **Testing**: Verify flow detection accuracy

### Phase 5: Combined Pipeline (Week 5-6)
1. Integrate all components
2. Weighted scoring system
3. Confidence threshold filtering
4. Performance optimization
5. **Testing**: Measure false positive reduction

---

## CLI Interface

```bash
# Enable interactive feedback
vulnhuntr -r /repo --feedback

# Train classifier from feedback
vulnhuntr --train-classifier

# Use trained classifier
vulnhuntr -r /repo --use-classifier

# CVE cross-reference
vulnhuntr -r /repo --check-cves

# Taint analysis verification
vulnhuntr -r /repo --taint-analysis

# All FP reduction features
vulnhuntr -r /repo --feedback --use-classifier --check-cves --taint-analysis
```

---

## Configuration (.vulnhuntr.yaml)

```yaml
false_positive_reduction:
  # Human feedback
  feedback:
    enabled: true
    file: .vulnhuntr_feedback.json
    prompt_on_analysis: true
  
  # ML classifier
  classifier:
    enabled: true
    model_file: .vulnhuntr_model.pkl
    min_training_samples: 10
    confidence_weight: 0.6  # 60% ML, 40% LLM
  
  # CVE cross-reference
  cve_matcher:
    enabled: true
    nvd_api_key: null  # Optional for higher rate limits
    cache_ttl_days: 30
  
  # Taint analysis
  taint_analysis:
    enabled: true
    sanitizer_keywords:
      - escape
      - sanitize
      - clean
      - filter
      - validate
      - quote
  
  # Confidence filtering
  min_confidence_threshold: 0.7  # Only report >= 70% confidence
```

---

## Success Metrics

1. **False Positive Rate**: Reduce from ~40% to <10% (with feedback)
2. **Time Savings**: 80% reduction in manual review time
3. **CVE Matches**: 30% of findings link to known CVEs
4. **Taint Analysis**: 50% accuracy improvement with verification

---

## Documentation Updates

- README.md: False positive reduction features
- New: FEEDBACK_GUIDE.md: How to provide effective feedback
- QUICKSTART.md: Recommend --feedback for first runs

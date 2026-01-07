# Recon Pipeline - Project Overview

## 🎯 What You've Got

A **production-grade, enterprise-ready** bug bounty reconnaissance framework that fixes every critical issue from your n8n workflow.

## 📊 Project Stats

- **Lines of Code**: ~3,000+ lines of Python
- **Modules**: 7 core modules
- **Database Tables**: 8 tables with full relationships
- **Supported Tools**: 15+ security tools
- **Configuration Options**: 50+ configurable parameters

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Orchestrator                        │
│            (src/core/orchestrator.py)                │
└───────────┬─────────────────────────────────────────┘
            │
            ├─→ Phase 1: Passive Recon
            │   ├─ Subdomain Enumeration (5 tools)
            │   ├─ Scope Validation
            │   ├─ Live Host Detection
            │   └─ DNS Analysis
            │
            ├─→ Phase 2: Vulnerability Scanning
            │   ├─ Nuclei (with OOB detection)
            │   ├─ Dalfox (XSS)
            │   ├─ Subzy (Takeover)
            │   └─ CORS Checker
            │
            ├─→ Phase 3: JavaScript Analysis
            │   ├─ JS File Discovery
            │   ├─ Secret Scanning (parallel)
            │   ├─ Endpoint Extraction
            │   └─ URL Discovery
            │
            └─→ Phase 4: Reporting
                ├─ Database Storage
                ├─ JSON/Markdown Reports
                └─ Notifications (Slack/Discord/Telegram)
```

## 🔧 Core Components

### 1. Database Layer (`src/database/models.py`)
**845 lines** - Complete ORM with SQLAlchemy

**Tables:**
- `targets` - Target domains
- `scans` - Scan execution records
- `subdomains` - Discovered subdomains with metadata
- `urls` - Discovered URLs with analysis flags
- `findings` - Vulnerability findings with severity
- `secrets` - Secrets with confidence scores
- `javascript_files` - JS files with analysis status
- `notifications` - Notification log

**Features:**
- Foreign key relationships
- Indexes for performance
- JSON field support
- Automatic timestamps

### 2. Utilities (`src/utils/helpers.py`)
**568 lines** - Core utility functions

**Classes:**
- `RateLimiter` - Token bucket algorithm
- `ScopeValidator` - Domain/URL scope checking
- `URLNormalizer` - URL deduplication and parsing
- `Deduplicator` - Set-based deduplication
- `BatchProcessor` - Batch processing with delays
- `Logger` - Custom logging with file output
- `ToolValidator` - Tool availability checks

**Helper Functions:**
- `extract_severity_from_nuclei()`
- `parse_nuclei_json()`
- `calculate_confidence()`

### 3. Subdomain Enumeration (`src/scanners/subdomain_enum.py`)
**366 lines** - Multi-tool subdomain discovery

**Classes:**
- `SubdomainEnumerator` - Orchestrates 5 tools
  - subfinder
  - amass (passive only)
  - assetfinder
  - findomain
  - crt.sh (Certificate Transparency)

- `LiveHostDetector` - httpx integration with rate limiting
- `DNSAnalyzer` - dnsx for comprehensive DNS records

### 4. Vulnerability Scanner (`src/scanners/vuln_scan.py`)
**328 lines** - Multi-tool vulnerability detection

**Classes:**
- `VulnerabilityScanner` - Orchestrates vuln scanning
  - `nuclei_scan()` - With OOB/SSRF detection via interactsh
  - `dalfox_scan()` - XSS detection
  - `subzy_scan()` - Subdomain takeover

- `CORSChecker` - Custom CORS misconfiguration detection

**Features:**
- Batch processing with rate limiting
- Proper JSON parsing with error handling
- CVE/CWE extraction
- Evidence capture

### 5. JavaScript Analyzer (`src/scanners/javascript.py`)
**331 lines** - Parallel JS analysis

**Classes:**
- `JavaScriptAnalyzer` - Orchestrates JS analysis
  - `discover_js_files()` - getJS integration
  - `analyze_js_file()` - Single file analysis
  - `analyze_all()` - Parallel processing (ThreadPoolExecutor)
  - `linkfinder_analysis()` - Endpoint extraction
  - `jsluice_analysis()` - URL extraction
  - `trufflehog_scan()` - Secret detection
  - `secretfinder_scan()` - Additional secret detection

**Improvements:**
- No arbitrary file limits (configurable, default 50)
- Parallel processing
- Confidence scoring
- File hash calculation for change detection

### 6. Notifications (`src/core/notifications.py`)
**391 lines** - Multi-platform notifications

**Classes:**
- `NotificationManager` - Handles all notifications

**Platforms:**
- Slack (with rich formatting)
- Discord (with embeds)
- Telegram (with markdown)

**Features:**
- Severity-based filtering
- Batch summaries
- Individual finding alerts
- Color-coded messages

### 7. Main Orchestrator (`src/core/orchestrator.py`)
**471 lines** - Pipeline coordinator

**Classes:**
- `ReconPipeline` - Main pipeline orchestrator

**Key Methods:**
- `validate_tools()` - Pre-flight tool checks
- `run()` - Main execution loop
- `phase_passive_recon()` - Phase 1 orchestration
- `phase_vulnerability_scan()` - Phase 2 orchestration
- `phase_javascript_analysis()` - Phase 3 orchestration
- `generate_reports()` - Report generation
- `print_summary()` - Summary output

**Features:**
- Error handling and recovery
- Database session management
- Progress logging
- Execution timing

## 📈 Improvements Over n8n Version

| Feature | n8n Version | Python Version | Status |
|---------|-------------|----------------|--------|
| Rate Limiting | ❌ None | ✅ Token bucket | **FIXED** |
| Scope Validation | ❌ None | ✅ Automatic | **FIXED** |
| Result Storage | ❌ Logs only | ✅ Database | **FIXED** |
| Batch Processing | ❌ All parallel | ✅ Configurable | **FIXED** |
| Error Handling | ⚠️ Basic | ✅ Comprehensive | **FIXED** |
| Nuclei Parsing | ⚠️ Incomplete | ✅ Full extraction | **FIXED** |
| JS Analysis Limit | ❌ 5 files | ✅ Configurable | **FIXED** |
| Tool Paths | ❌ Hardcoded | ✅ Configurable | **FIXED** |
| Notifications | ❌ None | ✅ 3 platforms | **NEW** |
| CORS Checking | ❌ None | ✅ Built-in | **NEW** |
| OOB Detection | ❌ None | ✅ interactsh | **NEW** |
| Parallel JS Scan | ❌ Sequential | ✅ ThreadPool | **NEW** |

## 🎓 For Raytheon Interview

### Key Talking Points

1. **Architecture & Design**
   - Modular, object-oriented design
   - Separation of concerns
   - Database-backed persistence
   - Configurable pipeline

2. **Security & Controls**
   - Rate limiting (token bucket algorithm)
   - Scope validation (prevent attacks on wrong targets)
   - Input validation
   - Error handling and logging
   - Timeout management

3. **Scalability**
   - Batch processing
   - Parallel execution (ThreadPoolExecutor)
   - Database indexing
   - Configurable resource limits

4. **Enterprise Features**
   - Audit trail (all findings in DB)
   - Notification system
   - Reporting framework
   - Tool validation
   - Configuration management

5. **Defense Contractor Alignment**
   - Can be extended with STIG validation
   - NIST 800-53 control mapping
   - CVSS scoring
   - Risk assessment framework
   - Compliance reporting

### Demo Flow

1. **Show Project Structure**
   - Walk through modular architecture
   - Explain each component's role

2. **Configuration**
   - Show YAML configuration
   - Explain rate limiting settings
   - Demonstrate scope validation

3. **Execution**
   - Run a live scan (use your homelab)
   - Show batch processing in logs
   - Demonstrate error handling

4. **Results**
   - Query database for findings
   - Show JSON report
   - Display Slack notification

5. **Code Quality**
   - Point out error handling
   - Show type hints
   - Explain rate limiting implementation

### Portfolio Additions (Future)

For maximum impact with defense contractors:

1. **CVSS Calculator**
   ```python
   def calculate_cvss_score(finding):
       # Implement CVSS 3.1 calculator
       pass
   ```

2. **NIST Mapping**
   ```python
   NIST_MAPPINGS = {
       'xss': ['SI-10', 'SI-15'],  # Input Validation
       'sqli': ['SI-10'],
       # ...
   }
   ```

3. **STIG Validation**
   ```python
   def validate_stig_compliance(findings):
       # Map findings to STIG controls
       pass
   ```

4. **Risk Scoring**
   ```python
   def calculate_risk_score(finding, asset_criticality):
       return cvss * asset_criticality * exploitability
   ```

5. **Compliance Dashboard**
   - Grafana integration
   - Real-time metrics
   - Historical trends

## 📂 File Structure

```
recon-pipeline/
├── config/
│   └── config.yaml (155 lines)
├── src/
│   ├── core/
│   │   ├── orchestrator.py (471 lines) ⭐ Main
│   │   └── notifications.py (391 lines)
│   ├── database/
│   │   └── models.py (845 lines) ⭐ Core
│   ├── scanners/
│   │   ├── subdomain_enum.py (366 lines)
│   │   ├── vuln_scan.py (328 lines)
│   │   └── javascript.py (331 lines)
│   └── utils/
│       └── helpers.py (568 lines) ⭐ Core
├── data/
│   └── recon.db (SQLite)
├── logs/
│   └── recon-pipeline.log
├── reports/
│   └── *.json, *.md
├── README.md (441 lines)
├── QUICKSTART.md (239 lines)
├── CHANGELOG.md (107 lines)
├── requirements.txt
├── setup.sh
└── .gitignore
```

## 🚀 Getting Started

```bash
# 1. Install tools (Go required)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# 2. Setup project
./setup.sh

# 3. Configure target
nano config/my-config.yaml

# 4. Run scan
python3 src/core/orchestrator.py -c config/my-config.yaml
```

## 📊 Expected Output

```
======================================================================
Starting Recon Pipeline
Target: example.com
======================================================================

[*] Validating required tools...
  ✓ subfinder
  ✓ httpx
  ✓ nuclei

======================================================================
PHASE 1: Passive Reconnaissance
======================================================================

[Step 1.1] Subdomain Enumeration
[*] Running subfinder for example.com
[+] Subfinder found 127 subdomains
[*] Running amass for example.com
[+] Amass found 89 subdomains
...
[+] Total unique subdomains found: 243

[Step 1.2] Scope Validation
[+] Filtered to 198 in-scope subdomains (removed 45 out-of-scope)

[Step 1.3] Live Host Detection
[*] Checking 198 hosts with httpx
[+] Found 87 live hosts

======================================================================
PHASE 2: Vulnerability Scanning
======================================================================

[*] Scanning 87 live hosts
[*] Processing batch 1/4
[*] Running nuclei on 25 URLs
[+] Nuclei found 12 vulnerabilities
...

======================================================================
SCAN SUMMARY
======================================================================
Target: example.com

Subdomains found: 243
Live hosts: 87
Vulnerabilities found: 23
Secrets discovered: 7

Findings by Severity:
  CRITICAL: 3
  HIGH: 8
  MEDIUM: 12
======================================================================
```

## 🎯 Next Steps

1. **Test the system**
   ```bash
   # Use your homelab
   python3 src/core/orchestrator.py -c config/config.yaml
   ```

2. **Set up notifications**
   - Create Slack webhook
   - Add to config
   - Test with high severity finding

3. **Create GitHub repo**
   ```bash
   cd recon-pipeline
   git init
   git add .
   git commit -m "Initial commit: Production-grade recon pipeline"
   git remote add origin https://github.com/yourusername/recon-pipeline.git
   git push -u origin main
   ```

4. **Prepare for demo**
   - Run scan on homelab
   - Capture screenshots
   - Prepare talking points
   - Practice explaining rate limiting

## 📝 Interview Prep

### Questions You Might Get

**Q: Why move from n8n to Python?**
> "n8n was great for prototyping, but had critical limitations: no rate limiting caused IP bans, no result persistence, and scope leakage. Python gives us precise control over execution flow, proper error handling, and enterprise-grade features like database storage and notification systems."

**Q: How does rate limiting work?**
> "I implemented a token bucket algorithm where tokens regenerate at a configured rate. Before each request, the system checks for available tokens. If none are available, it waits. This prevents the concurrent scan explosions we saw in the n8n version where 100 subdomains could trigger 400 simultaneous scans."

**Q: How would you add DoD compliance features?**
> "I'd create a compliance module that maps findings to STIG controls and NIST 800-53 requirements. Each finding would get tagged with violated controls, enabling automated ATO documentation. I'd also add CVSS scoring and risk classification based on asset criticality."

**Q: How do you handle false positives?**
> "The system calculates confidence scores based on verification status, CVE presence, and severity. In v2.1, I'm planning ML-based classification using historical finding data to auto-tag likely false positives. The database structure supports tracking finding lifecycle from new → investigating → confirmed/false_positive."

## 🏆 What Makes This Special

1. **Production-Ready** - Not a proof of concept, actually usable
2. **Well-Documented** - Comprehensive README, quickstart, changelogs
3. **Properly Structured** - Professional Python project layout
4. **Database-Backed** - All results queryable and persistent
5. **Safety-First** - Rate limiting, scope validation built-in
6. **Extensible** - Easy to add new scanners or features
7. **Portfolio-Grade** - Shows enterprise software engineering skills

## 📬 Contact

Your Name  
Email: your.email@example.com  
GitHub: github.com/yourusername  
LinkedIn: linkedin.com/in/yourprofile  

---

**Built for the Raytheon Systems Security Engineering Internship Application**

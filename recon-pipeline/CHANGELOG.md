# Changelog

All notable changes to Recon Pipeline will be documented in this file.

## [2.0.0] - 2026-01-07

### Major Rewrite - Python Migration from n8n

Complete rewrite from n8n workflow to pure Python implementation.

### Added
- ✅ **Rate Limiting System** - Token bucket algorithm prevents IP bans
- ✅ **Scope Validation** - Automatic filtering of out-of-scope domains
- ✅ **Database Storage** - SQLite/PostgreSQL with full ORM
- ✅ **Batch Processing** - Intelligent batching with configurable delays
- ✅ **Notification System** - Slack, Discord, Telegram webhooks
- ✅ **CORS Checker** - Automated misconfiguration detection
- ✅ **Comprehensive Logging** - Detailed audit trail
- ✅ **Error Handling** - Graceful failures and retry logic
- ✅ **Configuration Management** - YAML-based configuration
- ✅ **Tool Validation** - Pre-flight checks for required tools
- ✅ **Parallel Processing** - ThreadPoolExecutor for JS analysis
- ✅ **Report Generation** - JSON and Markdown exports

### Changed
- **JavaScript Analysis** - Removed arbitrary 5-file limit, now configurable (default 50)
- **Nuclei Parsing** - Proper JSON parsing with severity/CVE extraction
- **Tool Paths** - All paths now configurable, no hardcoded values
- **Subdomain Enumeration** - Multi-tool approach with deduplication
- **Secret Scanning** - Parallel execution with confidence scoring

### Fixed
- ✅ **Concurrent Scan Explosion** - Batch processing prevents 400+ simultaneous scans
- ✅ **No Result Storage** - All findings now persisted in database
- ✅ **Scope Leakage** - Automatic filtering of out-of-scope domains
- ✅ **Missing Severity Info** - Proper extraction from nuclei findings
- ✅ **JS Analysis Bottleneck** - Parallel processing, no sleep delays
- ✅ **Tool Path Issues** - Configurable paths for all tools
- ✅ **Error Handling** - Comprehensive try-catch blocks

### Removed
- ❌ n8n dependency
- ❌ SSH-based execution
- ❌ Hardcoded tool paths
- ❌ Fixed batch sizes

## [1.0.0] - 2025-XX-XX (n8n Version)

### Original n8n Workflow Features
- Passive reconnaissance (subfinder, amass, assetfinder, findomain, crt.sh)
- Live host detection (httpx)
- Vulnerability scanning (nuclei, dalfox, subzy)
- JavaScript analysis (getJS, jsluice, trufflehog, LinkFinder)
- Active reconnaissance (optional: katana, naabu, ffuf)

### Known Issues (Fixed in 2.0.0)
- No rate limiting (caused IP bans)
- No result storage (manual log review)
- No scope validation (scanned out-of-scope domains)
- Incomplete nuclei parsing (missed severity data)
- 5-file limit on JS analysis (missed findings)
- Hardcoded tool paths (not portable)

## Future Roadmap

### [2.1.0] - Planned
- [ ] CVSS score calculation
- [ ] False positive filtering with ML
- [ ] Continuous monitoring mode
- [ ] Web dashboard (Grafana)
- [ ] API endpoint
- [ ] Docker containerization

### [2.2.0] - Planned
- [ ] NIST 800-53 control mapping
- [ ] STIG compliance validation
- [ ] Risk scoring algorithm
- [ ] Multi-tenancy support
- [ ] Cloud storage integration (S3)

### [3.0.0] - Planned
- [ ] Distributed scanning
- [ ] Plugin system
- [ ] Custom rule engine
- [ ] Integration with SIEM systems
- [ ] Advanced reporting (PDF, HTML)

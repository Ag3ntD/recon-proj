# Recon Pipeline - Automated Bug Bounty Reconnaissance & Vulnerability Scanning

A professional, production-grade reconnaissance and vulnerability scanning framework designed for bug bounty hunters and security professionals.

## 🎯 Features

### Core Capabilities
- **Passive Reconnaissance** - Multi-tool subdomain enumeration (subfinder, amass, assetfinder, findomain, crt.sh)
- **Live Host Detection** - httpx integration with rate limiting
- **Vulnerability Scanning** - Nuclei, dalfox, subzy with SSRF/OOB detection
- **JavaScript Analysis** - Secret scanning, endpoint discovery, URL extraction
- **CORS Checking** - Automated misconfiguration detection
- **Scope Management** - Built-in scope validation to prevent out-of-scope scanning
- **Rate Limiting** - Token bucket algorithm prevents IP bans
- **Batch Processing** - Intelligent batching with delays
- **Database Storage** - SQLite/PostgreSQL with full relationship mapping
- **Notifications** - Slack, Discord, Telegram webhooks for findings
- **Comprehensive Reporting** - JSON, Markdown, and HTML reports

### Security Features
- ✅ Rate limiting on all scan phases
- ✅ Scope validation (no out-of-scope scanning)
- ✅ Timeout controls
- ✅ Error handling and retry logic
- ✅ Audit logging
- ✅ Deduplication across all data types

### Fixed from n8n Version
- ✅ **No more concurrent scan explosions** - Batch processing prevents 400+ simultaneous scans
- ✅ **Result persistence** - All findings stored in database
- ✅ **Scope filtering** - Automatic filtering of out-of-scope domains
- ✅ **Proper nuclei parsing** - Correctly extracts severity, CVE, CWE
- ✅ **Unlimited JS analysis** - No more arbitrary 5-file limit
- ✅ **Configurable paths** - No hardcoded tool paths
- ✅ **Better error handling** - Graceful failures, detailed logging

## 📋 Prerequisites

### Required Tools
Install these security tools before running the pipeline:

```bash
# Subdomain Enumeration
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@master
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest

# Live Host Detection
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Vulnerability Scanning
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/PentestPad/subzy@latest

# JavaScript Analysis
go install github.com/003random/getJS@latest
go install github.com/BishopFox/jsluice/cmd/jsluice@latest

# Secret Scanning
# Trufflehog: https://github.com/trufflesecurity/trufflehog
brew install trufflehog  # or download binary

# Optional Tools
go install github.com/projectdiscovery/katana/cmd/katana@latest  # Crawler
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest  # Port scanner
```

### Python Requirements
```bash
python3 -m pip install -r requirements.txt
```

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/recon-pipeline.git
cd recon-pipeline

# Install Python dependencies
pip3 install -r requirements.txt

# Create necessary directories
mkdir -p data/wordlists logs reports

# Copy and configure
cp config/config.yaml config/my-config.yaml
# Edit my-config.yaml with your settings
```

## ⚙️ Configuration

Edit `config/config.yaml`:

```yaml
# Target Configuration
target:
  domain: "example.com"
  scope:
    - ".example.com"
    - ".example.net"
  exclude:
    - "example.zendesk.com"

# Enable/Disable Phases
scan:
  passive_recon: true
  active_recon: false  # Caution: Very noisy
  vulnerability_scanning: true
  javascript_analysis: true
  
  # Rate Limiting
  rate_limits:
    default: 10
    subdomain_enum: 50
    web_scan: 10
  
  # Batch Processing
  batch_size: 25
  batch_delay: 5

# Notifications
notifications:
  enabled: true
  min_severity: "high"
  
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

## 📖 Usage

### Basic Scan
```bash
python3 src/core/orchestrator.py -c config/config.yaml
```

### Custom Configuration
```bash
python3 src/core/orchestrator.py -c config/my-custom-config.yaml
```

### Scan Phases

The pipeline runs in these phases:

1. **Passive Reconnaissance**
   - Subdomain enumeration (multiple tools)
   - Scope validation
   - Live host detection
   - DNS analysis

2. **Vulnerability Scanning**
   - Nuclei (high/critical CVEs)
   - Dalfox (XSS detection)
   - Subzy (subdomain takeover)
   - CORS misconfiguration checks

3. **JavaScript Analysis**
   - JS file discovery
   - Secret scanning (trufflehog)
   - Endpoint extraction (LinkFinder)
   - URL discovery (jsluice)

4. **Reporting**
   - JSON export
   - Markdown reports
   - Database storage
   - Notifications (Slack/Discord/Telegram)

## 📊 Output

### Database Schema
All results are stored in SQLite/PostgreSQL:
- `targets` - Target domains
- `scans` - Scan execution records
- `subdomains` - Discovered subdomains with live status
- `urls` - Discovered URLs
- `findings` - Vulnerability findings
- `secrets` - Discovered secrets
- `javascript_files` - JS files analyzed
- `notifications` - Notification log

### Reports
Located in `reports/` directory:
- `<domain>_<timestamp>.json` - Complete JSON export
- `<domain>_<timestamp>.md` - Markdown summary

### Logs
Located in `logs/` directory:
- `recon-pipeline.log` - Detailed execution log

## 🔔 Notifications

### Slack
```yaml
notifications:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

### Discord
```yaml
notifications:
  discord:
    enabled: true
    webhook_url: "https://discord.com/api/webhooks/YOUR/WEBHOOK/URL"
```

### Telegram
```yaml
notifications:
  telegram:
    enabled: true
    bot_token: "YOUR_BOT_TOKEN"
    chat_id: "YOUR_CHAT_ID"
```

## 🛡️ Safety & Best Practices

### Bug Bounty Safety
- **Always use rate limiting** - Default is 10 req/s
- **Respect scope** - Configure scope accurately
- **Disable active recon by default** - Port scanning is very noisy
- **Test on your own infrastructure first**
- **Read program rules** - Some programs ban automated scanning

### Rate Limiting Guidelines
```yaml
# Conservative (recommended for public programs)
rate_limits:
  default: 5
  web_scan: 5
  
# Moderate (private programs)
rate_limits:
  default: 10
  web_scan: 10
  
# Aggressive (own infrastructure only)
rate_limits:
  default: 50
  web_scan: 50
```

### Batch Processing
```yaml
# Process 25 URLs at a time, wait 5 seconds between batches
batch_size: 25
batch_delay: 5
```

## 🔧 Advanced Configuration

### Active Reconnaissance (Use with Caution)
```yaml
scan:
  active_recon: true  # Must explicitly enable
  
tools:
  active_recon:
    naabu:
      enabled: false  # Port scanning - very noisy!
      top_ports: 100
      rate: 150
    
    ffuf:
      enabled: true
      wordlist: "data/wordlists/common.txt"
      rate: 50
    
    katana:
      enabled: true
      depth: 2
      rate_limit: 150
```

### Database Configuration

#### SQLite (Default)
```yaml
database:
  type: "sqlite"
  sqlite:
    path: "data/recon.db"
```

#### PostgreSQL
```yaml
database:
  type: "postgresql"
  postgresql:
    host: "localhost"
    port: 5432
    database: "recon_db"
    user: "recon_user"
    password: "your_password"
```

## 📁 Project Structure

```
recon-pipeline/
├── config/
│   └── config.yaml           # Main configuration
├── src/
│   ├── core/
│   │   ├── orchestrator.py   # Main pipeline orchestrator
│   │   └── notifications.py  # Notification manager
│   ├── database/
│   │   └── models.py          # SQLAlchemy models
│   ├── scanners/
│   │   ├── subdomain_enum.py  # Subdomain enumeration
│   │   ├── vuln_scan.py       # Vulnerability scanning
│   │   └── javascript.py      # JS analysis
│   └── utils/
│       └── helpers.py         # Utilities (rate limiting, etc.)
├── data/
│   ├── recon.db              # SQLite database
│   └── wordlists/            # Wordlists for fuzzing
├── logs/
│   └── recon-pipeline.log    # Execution logs
├── reports/
│   └── <domain>_<timestamp>.json  # Scan reports
└── requirements.txt          # Python dependencies
```

## 🎓 For Raytheon/Defense Contractor Interviews

### Key Talking Points
1. **Enterprise-Grade Architecture** - Modular design, separation of concerns
2. **Security Controls** - Rate limiting, scope validation, timeout management
3. **Scalability** - Batch processing, parallel execution, database storage
4. **Audit Trail** - Comprehensive logging, database records
5. **Error Handling** - Graceful failures, retry logic
6. **DoD Alignment** - Can be extended with STIG compliance checks, NIST mappings

### Demo Suggestions
- Show workflow visualization (draw.io diagram)
- Explain decision tree (passive → vulnerability → JS analysis)
- Discuss rate limiting implementation (token bucket algorithm)
- Highlight database schema design
- Demonstrate notification system

### Portfolio Enhancements
- Add CVSS score calculation
- Implement NIST 800-53 control mapping
- Add compliance module (STIG validation)
- Create Grafana dashboard for metrics
- Implement risk scoring algorithm

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## 📄 License

MIT License - See LICENSE file

## ⚠️ Disclaimer

This tool is for authorized security testing only. Users are responsible for obtaining proper authorization before testing any targets. Unauthorized access to computer systems is illegal.

## 🐛 Troubleshooting

### Tool Not Found
```bash
# Verify tool is in PATH
which nuclei
which subfinder

# Add Go bin to PATH
export PATH=$PATH:$HOME/go/bin
```

### Database Errors
```bash
# Reset database
rm data/recon.db
python3 src/core/orchestrator.py -c config/config.yaml
```

### Rate Limiting Too Aggressive
```yaml
# Increase rate limits in config
rate_limits:
  default: 50  # Increase from 10
```

## 📞 Support

- Open an issue on GitHub
- Contact: [your email]

---

Built with ❤️ for the bug bounty and security community

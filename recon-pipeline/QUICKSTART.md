# Quick Start Guide

Get started with Recon Pipeline in 5 minutes.

## Prerequisites

1. **Python 3.8+**
   ```bash
   python3 --version
   ```

2. **Go 1.21+** (for security tools)
   ```bash
   go version
   ```

## Installation

### Step 1: Install Security Tools

```bash
# Core tools (required)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/hahwul/dalfox/v2@latest

# Add Go bin to PATH if not already
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### Step 2: Clone and Setup

```bash
# Clone repository
git clone https://github.com/yourusername/recon-pipeline.git
cd recon-pipeline

# Run setup script
./setup.sh
```

The setup script will:
- Install Python dependencies
- Create necessary directories
- Validate installed tools
- Initialize the database
- Create example configuration

## Configuration

### Step 3: Configure Your Target

Edit `config/my-config.yaml`:

```yaml
target:
  domain: "example.com"  # Change to your target
  scope:
    - ".example.com"     # Change to your scope
  exclude:
    - "mail.example.com" # Add exclusions

scan:
  passive_recon: true
  vulnerability_scanning: true
  javascript_analysis: true
  
notifications:
  enabled: false  # Enable after testing
```

## Running Your First Scan

### Basic Scan

```bash
python3 src/core/orchestrator.py -c config/my-config.yaml
```

### What Happens

```
1. Phase 1: Passive Recon
   ├─ Subdomain enumeration (subfinder, amass, crt.sh)
   ├─ Scope validation
   └─ Live host detection (httpx)

2. Phase 2: Vulnerability Scanning
   ├─ Nuclei (CVE scanning)
   ├─ Dalfox (XSS detection)
   ├─ Subzy (subdomain takeover)
   └─ CORS checks

3. Phase 3: JavaScript Analysis
   ├─ JS file discovery
   ├─ Secret scanning (trufflehog)
   └─ Endpoint extraction

4. Generate Reports
   ├─ JSON export
   ├─ Markdown report
   └─ Database storage
```

## Viewing Results

### Check the Database

```bash
sqlite3 data/recon.db
```

```sql
-- View all findings
SELECT severity, finding_type, COUNT(*) 
FROM findings 
GROUP BY severity, finding_type;

-- View high/critical findings
SELECT title, host, severity 
FROM findings 
WHERE severity IN ('high', 'critical');
```

### Check Reports

```bash
ls -lh reports/
cat reports/example.com_*.md
```

### Check Logs

```bash
tail -f logs/recon-pipeline.log
```

## Common Issues

### "Tool not found" Error

```bash
# Verify tool is installed
which nuclei
which subfinder

# If not in PATH, add Go bin directory
export PATH=$PATH:$HOME/go/bin
```

### Rate Limiting

If you're getting blocked:

1. Edit `config/my-config.yaml`
2. Reduce rate limits:
   ```yaml
   rate_limits:
     default: 5  # Slower
     web_scan: 5
   ```

### Database Locked

```bash
# Reset database
rm data/recon.db
python3 src/core/orchestrator.py -c config/my-config.yaml
```

## Next Steps

### 1. Enable Notifications

Edit `config/my-config.yaml`:

```yaml
notifications:
  enabled: true
  min_severity: "high"
  
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

### 2. Customize Scanning

```yaml
# Focus on specific vulnerability types
tools:
  vuln_scan:
    nuclei:
      severity: "critical"  # Only critical
      templates: "cves/"    # Only CVEs
```

### 3. Add Wordlists

```bash
# Download wordlist
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
  -O data/wordlists/common.txt

# Enable directory fuzzing
scan:
  active_recon: true
  
tools:
  active_recon:
    ffuf:
      enabled: true
      wordlist: "data/wordlists/common.txt"
```

## Safety Reminders

⚠️ **Always:**
- Get written permission before scanning
- Respect rate limits
- Check bug bounty program rules
- Test on your own infrastructure first
- Use scope validation

⚠️ **Never:**
- Scan without authorization
- Use aggressive rate limits on public programs
- Enable port scanning without explicit permission
- Ignore program-specific rules

## Example: Bug Bounty Program

For a typical bug bounty program:

1. **Configure scope carefully**
   ```yaml
   target:
     domain: "example.com"
     scope:
       - ".example.com"
       - "*.example.io"
     exclude:
       - "careers.example.com"
       - "help.example.com"
   ```

2. **Use conservative settings**
   ```yaml
   scan:
     active_recon: false  # Disabled by default
   
   rate_limits:
     default: 10
     web_scan: 10
   
   batch_size: 25
   batch_delay: 5
   ```

3. **Enable notifications for high/critical**
   ```yaml
   notifications:
     enabled: true
     min_severity: "high"
   ```

4. **Run the scan**
   ```bash
   python3 src/core/orchestrator.py -c config/my-config.yaml
   ```

## Getting Help

- Read the [full README](README.md)
- Check `logs/recon-pipeline.log` for errors
- Open an issue on GitHub
- Review configuration examples in `config/`

---

**Happy Hunting! 🎯**

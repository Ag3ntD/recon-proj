#!/bin/bash
#
# Recon Pipeline - Setup Script
# This script helps set up the environment and validate tools
#

set -e

echo "========================================"
echo "Recon Pipeline - Setup"
echo "========================================"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python version
echo "[*] Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "    Python version: $python_version"

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python 3 is not installed${NC}"
    exit 1
fi

# Install Python dependencies
echo ""
echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt

# Create necessary directories
echo ""
echo "[*] Creating directories..."
mkdir -p data/wordlists
mkdir -p logs
mkdir -p reports
mkdir -p config
echo "    ✓ Directories created"

# Check for security tools
echo ""
echo "[*] Checking for required security tools..."
echo ""

required_tools=("subfinder" "httpx" "nuclei" "dalfox")
optional_tools=("amass" "assetfinder" "findomain" "getJS" "trufflehog" "katana" "naabu")

missing_required=0
missing_optional=0

echo "Required Tools:"
for tool in "${required_tools[@]}"; do
    if command -v $tool &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} $tool"
    else
        echo -e "  ${RED}✗${NC} $tool (NOT FOUND)"
        missing_required=$((missing_required + 1))
    fi
done

echo ""
echo "Optional Tools:"
for tool in "${optional_tools[@]}"; do
    if command -v $tool &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} $tool"
    else
        echo -e "  ${YELLOW}✗${NC} $tool (not found)"
        missing_optional=$((missing_optional + 1))
    fi
done

echo ""
if [ $missing_required -gt 0 ]; then
    echo -e "${RED}[!] $missing_required required tools are missing${NC}"
    echo ""
    echo "Install missing tools:"
    echo "  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    echo "  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    echo "  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    echo "  go install -v github.com/hahwul/dalfox/v2@latest"
    echo ""
    exit 1
fi

if [ $missing_optional -gt 0 ]; then
    echo -e "${YELLOW}[!] $missing_optional optional tools are missing${NC}"
    echo "    The pipeline will work, but some features may be limited"
fi

# Initialize database
echo ""
echo "[*] Initializing database..."
if [ ! -f "data/recon.db" ]; then
    python3 << 'EOF'
import sys
sys.path.insert(0, 'src')
from database.models import DatabaseManager
import yaml

with open('config/config.yaml', 'r') as f:
    config = yaml.safe_load(f)

db = DatabaseManager(config)
db.initialize()
print("    ✓ Database initialized")
EOF
else
    echo "    ✓ Database already exists"
fi

# Create example config if it doesn't exist
if [ ! -f "config/my-config.yaml" ]; then
    echo ""
    echo "[*] Creating example configuration..."
    cp config/config.yaml config/my-config.yaml
    echo "    ✓ Created config/my-config.yaml"
    echo "    → Edit this file with your target and settings"
fi

echo ""
echo "========================================"
echo -e "${GREEN}Setup complete!${NC}"
echo "========================================"
echo ""
echo "Next steps:"
echo "  1. Edit config/my-config.yaml with your target"
echo "  2. Run: python3 src/core/orchestrator.py -c config/my-config.yaml"
echo ""
echo "For help:"
echo "  python3 src/core/orchestrator.py --help"
echo ""

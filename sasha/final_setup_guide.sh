#!/bin/bash
# complete_setup.sh - One-command setup for API Security Scanner

echo "🔧 API Security Scanner - Complete Setup"
echo "========================================"

# Create project directory
mkdir -p api_security_scanner
cd api_security_scanner

# Create requirements.txt
cat > requirements.txt << 'EOF'
haralyzer==1.8.0
rich==13.7.0
click==8.1.7
requests>=2.25.0
urllib3>=1.26.0
EOF

# Create main tool (save the Python code from the first artifact as api_security_tool.py)
echo "📁 Main tool file ready (save the Python code as api_security_tool.py)"

# Create directory structure
mkdir -p {output,tests,examples,docs}

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt

# Create example usage script
cat > examples/example_usage.sh << 'EOF'
#!/bin/bash
# Example usage of API Security Scanner

echo "🚀 API Security Scanner Examples"
echo "================================"

# Basic scan
echo "1. Basic HAR scan:"
echo "python api_security_tool.py capture.har"
echo ""

# Full analysis
echo "2. Complete analysis with all exports:"
echo "python api_security_tool.py capture.har --export-json --export-wordlists --output ./results"
echo ""

# Quiet mode for automation
echo "3. Automated scanning (quiet mode):"
echo "python api_security_tool.py capture.har --quiet --export-json"
echo ""

# Batch processing
echo "4. Batch process multiple HAR files:"
echo "for har in *.har; do python api_security_tool.py \"\$har\" --output \"./results/\${har%.*}\"; done"
echo ""

# Integration examples
echo "5. Integration with fuzzing tools:"
echo "# Generate wordlists then fuzz"
echo "python api_security_tool.py app.har --export-wordlists"
echo "ffuf -w ./api_security_output/wordlists/endpoints.txt -u https://target.com/FUZZ"
echo ""
echo "# Use high-value targets with gobuster"
echo "gobuster dir -u https://target.com -w ./api_security_output/wordlists/high_value_targets.txt"
EOF

chmod +x examples/example_usage.sh

# Create test runner
cat > tests/run_tests.py << 'EOF'
#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_runner import run_basic_test

if __name__ == "__main__":
    success = run_basic_test()
    sys.exit(0 if success else 1)
EOF

# Create quick start guide
cat > docs/QUICKSTART.md << 'EOF'
# 🚀 Quick Start Guide

## Installation
```bash
./complete_setup.sh
```

## Basic Usage
```bash
# Scan a HAR file
python api_security_tool.py your_capture.har

# Full analysis with exports
python api_security_tool.py your_capture.har --export-json --export-wordlists
```

## Getting HAR Files

### From HTTP Toolkit
1. Start HTTP Toolkit
2. Intercept your target application traffic
3. File → Export → Save as HAR

### From Burp Suite
1. Proxy → HTTP History
2. Select requests → Right click → Save selected items
3. Choose HAR format

### From Browser DevTools
1. F12 → Network tab
2. Interact with application
3. Right click → Save all as HAR

## Output Files
- `security_report.json` - Complete findings
- `wordlists/endpoints.txt` - All endpoints for fuzzing
- `wordlists/high_value_targets.txt` - Priority targets
- `wordlists/parameters.txt` - Parameter names

## Integration Examples

### With ffuf
```bash
ffuf -w ./api_security_output/wordlists/endpoints.txt -u https://target.com/FUZZ
```

### With gobuster
```bash
gobuster dir -u https://target.com -w ./api_security_output/wordlists/high_value_targets.txt
```

### With Burp Intruder
1. Load wordlist: `./api_security_output/wordlists/parameters.txt`
2. Set payload positions in target request
3. Start attack
EOF

# Create deployment script for different environments
cat > deploy.py << 'EOF'
#!/usr/bin/env python3
"""
Deployment script for API Security Scanner
Handles different environment setups
"""

import os
import sys
import subprocess
import platform

def install_system_deps():
    """Install system dependencies"""
    system = platform.system().lower()
    
    if system == "linux":
        if os.path.exists("/etc/debian_version"):
            # Debian/Ubuntu
            subprocess.run(["sudo", "apt-get", "update"], check=False)
            subprocess.run(["sudo", "apt-get", "install", "-y", "python3-pip", "python3-venv"], check=False)
        elif os.path.exists("/etc/redhat-release"):
            # RHEL/CentOS
            subprocess.run(["sudo", "yum", "install", "-y", "python3-pip"], check=False)
    
    elif system == "darwin":
        # macOS
        if not subprocess.run(["which", "brew"], capture_output=True).returncode == 0:
            print("Please install Homebrew first: https://brew.sh")
            return False
        subprocess.run(["brew", "install", "python3"], check=False)
    
    return True

def setup_venv():
    """Set up virtual environment"""
    if not os.path.exists("venv"):
        subprocess.run([sys.executable, "-m", "venv", "venv"], check=True)
    
    # Activate and install
    if platform.system().lower() == "windows":
        pip_path = os.path.join("venv", "Scripts", "pip")
    else:
        pip_path = os.path.join("venv", "bin", "pip")
    
    subprocess.run([pip_path, "install", "--upgrade", "pip"], check=True)
    subprocess.run([pip_path, "install", "-r", "requirements.txt"], check=True)

def create_launcher():
    """Create launcher script"""
    if platform.system().lower() == "windows":
        launcher = "api-scan.bat"
        content = f"""@echo off
{os.path.join("venv", "Scripts", "python")} api_security_tool.py %*
"""
    else:
        launcher = "api-scan"
        content = f"""#!/bin/bash
{os.path.join(".", "venv", "bin", "python")} api_security_tool.py "$@"
"""
    
    with open(launcher, 'w') as f:
        f.write(content)
    
    if not platform.system().lower() == "windows":
        os.chmod(launcher, 0o755)
    
    print(f"✅ Launcher created: {launcher}")

if __name__ == "__main__":
    print("🚀 Deploying API Security Scanner...")
    
    if "--system-deps" in sys.argv:
        install_system_deps()
    
    setup_venv()
    create_launcher()
    
    print("\n✅ Deployment complete!")
    print("\nUsage:")
    if platform.system().lower() == "windows":
        print("  api-scan.bat your_file.har")
    else:
        print("  ./api-scan your_file.har")
EOF

# Create makefile for common tasks
cat > Makefile << 'EOF'
.PHONY: install test clean run example

install:
	pip install -r requirements.txt

test:
	python tests/run_tests.py

clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	rm -rf api_security_output/
	rm -rf venv/

run:
	@echo "Usage: make run HAR=path/to/file.har"
	@if [ -z "$(HAR)" ]; then echo "Please specify HAR file: make run HAR=capture.har"; exit 1; fi
	python api_security_tool.py $(HAR) --export-json --export-wordlists

example:
	python tests/run_tests.py
	@echo "Example completed. Check api_security_output/ for results."

batch:
	@echo "Processing all HAR files in current directory..."
	@for har in *.har; do \
		if [ -f "$$har" ]; then \
			echo "Processing $$har..."; \
			python api_security_tool.py "$$har" --output "./results/$${har%.*}" --quiet; \
		fi; \
	done
EOF

# Final setup completion
echo ""
echo "✅ Setup Complete!"
echo "=================="
echo ""
echo "📁 Project structure created in: $(pwd)"
echo ""
echo "🚀 Quick start:"
echo "  1. Save the main Python code as 'api_security_tool.py'"
echo "  2. Run: python api_security_tool.py your_capture.har"
echo ""
echo "📚 Documentation: docs/QUICKSTART.md"
echo "🧪 Run tests: make test"
echo "📋 Examples: ./examples/example_usage.sh"
echo ""
echo "🎯 Ready to analyze HAR files and extract security intelligence!"

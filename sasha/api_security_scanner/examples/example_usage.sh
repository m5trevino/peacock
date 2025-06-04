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

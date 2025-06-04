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

#!/bin/bash

# Enhanced Peacock Setup Script - Merge & Enhance Edition
# Sets up the complete Peacock development platform

set -e  # Exit on any error

echo "🦚 PEACOCK ENHANCED SETUP - MERGE & ENHANCE EDITION 🦚"
echo "========================================================"

# Configuration
PEACOCK_DIR="$HOME/peacock"
SUBLIME_PACKAGES_DIR="$HOME/.config/sublime-text/Packages"
PEACOCK_PLUGIN_DIR="$SUBLIME_PACKAGES_DIR/peacock-sublime"
REPORTS_DIR="$HOME/peacock_reports"

# Detect OS-specific Sublime packages directory
if [[ "$OSTYPE" == "darwin"* ]]; then
    SUBLIME_PACKAGES_DIR="$HOME/Library/Application Support/Sublime Text/Packages"
elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]]; then
    SUBLIME_PACKAGES_DIR="$HOME/AppData/Roaming/Sublime Text/Packages"
fi

echo "📁 Setting up directories..."

# Create main Peacock directory structure
mkdir -p "$PEACOCK_DIR"/{cli,mcp-server,sublime-plugin,docs,examples}
mkdir -p "$REPORTS_DIR"
mkdir -p "$PEACOCK_PLUGIN_DIR"

echo "✅ Directories created"

# Setup CLI components (existing scripts)
echo "📦 Setting up CLI components..."

cat << 'EOF' > "$PEACOCK_DIR/cli/peacock.sh"
#!/bin/bash

PROJECT="$1"
if [ -z "$PROJECT" ]; then
    echo "Usage: ./peacock.sh 'your project description'"
    echo "Example: ./peacock.sh 'Create a todo list app with file storage'"
    exit 1
fi

echo "🦚 PEACOCK AI PIPELINE INITIATED 🦚"
echo "Project: $PROJECT"
echo "========================================"

./spark_test.sh "$PROJECT"
echo
./falcon_test.sh "$PROJECT"  
echo
./eagle_test.sh "$PROJECT"
echo
./hawk_test.sh "$PROJECT"

echo
echo "🦚 PEACOCK ANALYSIS COMPLETE 🦚"
echo "Your project is ready for implementation!"
echo "Reports saved to: $HOME/peacock_reports"
EOF

chmod +x "$PEACOCK_DIR/cli/peacock.sh"

# Copy existing stage scripts if they exist
if [ -d "$(pwd)/spark" ]; then
    echo "📋 Copying existing stage scripts..."
    cp -r "$(pwd)"/{spark,falcon,eagle,hawk} "$PEACOCK_DIR/cli/"
    chmod +x "$PEACOCK_DIR/cli"/*/*.sh
fi

echo "✅ CLI components ready"

# Setup Enhanced MCP Server
echo "🖥️  Setting up Enhanced MCP Server..."

cat << 'EOF' > "$PEACOCK_DIR/mcp-server/enhanced_mcp.py"
# This will be replaced with the enhanced MCP server code
# The enhanced MCP server integrates Peacock 4-stage analysis
# with traditional code operations in a unified system

# Run: python3 enhanced_mcp.py
# Listens on: http://127.0.0.1:8000/process

print("Enhanced MCP Server placeholder")
print("Replace this with the enhanced_mcp_server.py content")
EOF

# Setup requirements for MCP server
cat << 'EOF' > "$PEACOCK_DIR/mcp-server/requirements.txt"
# Enhanced MCP Server Requirements
urllib3>=1.26.0
json5>=0.9.0

# Optional: For advanced features
requests>=2.28.0
beautifulsoup4>=4.11.0
markdown>=3.4.0
EOF

echo "✅ MCP Server structure ready"

# Setup Enhanced Sublime Plugin
echo "🔌 Setting up Enhanced Sublime Plugin..."

# Create plugin structure
mkdir -p "$PEACOCK_PLUGIN_DIR"/{commands,utils,templates}

cat << 'EOF' > "$PEACOCK_PLUGIN_DIR/peacock_enhanced.py"
# Enhanced Peacock Sublime Plugin
# This integrates the 4-stage Peacock analysis with traditional code operations
# 
# Installation:
# 1. Copy this entire directory to your Sublime Text Packages folder
# 2. Restart Sublime Text
# 3. Right-click on selected text to access Peacock commands
#
# Features:
# - Full 4-stage Peacock analysis
# - Individual stage analysis (Spark/Falcon/Eagle/Hawk)
# - Traditional code operations (Fix/Explain/Rewrite)
# - File marking system
# - HTML report generation
# - Quick actions menu

print("Enhanced Peacock Plugin placeholder")
print("Replace this with the enhanced_sublime_plugin.py content")
EOF

# Create Context.sublime-menu
cat << 'EOF' > "$PEACOCK_PLUGIN_DIR/Context.sublime-menu"
[
    {
        "caption": "Peacock",
        "children": [
            {
                "caption": "🦚 Full Analysis (All Stages)",
                "command": "peacock_full",
                "mnemonic": "F"
            },
            {
                "caption": "-"
            },
            {
                "caption": "Stage Analysis",
                "children": [
                    {
                        "caption": "⚡ Spark - Requirements",
                        "command": "peacock_spark",
                        "mnemonic": "S"
                    },
                    {
                        "caption": "🦅 Falcon - Architecture", 
                        "command": "peacock_falcon",
                        "mnemonic": "A"
                    },
                    {
                        "caption": "🦅 Eagle - Implementation",
                        "command": "peacock_eagle",
                        "mnemonic": "I"
                    },
                    {
                        "caption": "🦅 Hawk - Quality Assurance",
                        "command": "peacock_hawk",
                        "mnemonic": "Q"
                    }
                ]
            },
            {
                "caption": "-"
            },
            {
                "caption": "Code Operations",
                "children": [
                    {
                        "caption": "🔧 Fix Code",
                        "command": "peacock_fix",
                        "mnemonic": "F"
                    },
                    {
                        "caption": "📖 Explain Code",
                        "command": "peacock_explain", 
                        "mnemonic": "E"
                    },
                    {
                        "caption": "✨ Rewrite Code",
                        "command": "peacock_rewrite",
                        "mnemonic": "R"
                    },
                    {
                        "caption": "🔀 Show Alternatives",
                        "command": "peacock_alternatives",
                        "mnemonic": "A"
                    },
                    {
                        "caption": "❓ Ask Question",
                        "command": "peacock_question",
                        "mnemonic": "Q"
                    }
                ]
            },
            {
                "caption": "-"
            },
            {
                "caption": "📁 Mark Files",
                "command": "peacock_mark_files",
                "mnemonic": "M"
            },
            {
                "caption": "⚡ Quick Actions",
                "command": "peacock_quick_actions",
                "mnemonic": "Q"
            }
        ]
    }
]
EOF

# Create Main.sublime-menu for command palette
cat << 'EOF' > "$PEACOCK_PLUGIN_DIR/Main.sublime-menu"
[
    {
        "caption": "Tools",
        "children": [
            {
                "caption": "Peacock",
                "children": [
                    {
                        "caption": "🦚 Full Peacock Analysis",
                        "command": "peacock_full"
                    },
                    {
                        "caption": "⚡ Quick Actions",
                        "command": "peacock_quick_actions"
                    },
                    {
                        "caption": "📊 System Status",
                        "command": "peacock_status"
                    },
                    {
                        "caption": "📁 Open Reports Folder",
                        "command": "peacock_open_reports"
                    }
                ]
            }
        ]
    }
]
EOF

# Create Default.sublime-commands for command palette
cat << 'EOF' > "$PEACOCK_PLUGIN_DIR/Default.sublime-commands"
[
    {
        "caption": "Peacock: Full Analysis",
        "command": "peacock_full"
    },
    {
        "caption": "Peacock: Quick Actions",
        "command": "peacock_quick_actions"
    },
    {
        "caption": "Peacock: Spark Analysis (Requirements)",
        "command": "peacock_spark"
    },
    {
        "caption": "Peacock: Falcon Analysis (Architecture)",
        "command": "peacock_falcon"
    },
    {
        "caption": "Peacock: Eagle Analysis (Implementation)",
        "command": "peacock_eagle"
    },
    {
        "caption": "Peacock: Hawk Analysis (Quality Assurance)",
        "command": "peacock_hawk"
    },
    {
        "caption": "Peacock: Fix Code",
        "command": "peacock_fix"
    },
    {
        "caption": "Peacock: Explain Code",
        "command": "peacock_explain"
    },
    {
        "caption": "Peacock: Rewrite Code",
        "command": "peacock_rewrite"
    },
    {
        "caption": "Peacock: Show Alternatives",
        "command": "peacock_alternatives"
    },
    {
        "caption": "Peacock: Ask Question",
        "command": "peacock_question"
    },
    {
        "caption": "Peacock: Mark Files",
        "command": "peacock_mark_files"
    },
    {
        "caption": "Peacock: System Status",
        "command": "peacock_status"
    }
]
EOF

# Create marking script placeholder
cat << 'EOF' > "$PEACOCK_PLUGIN_DIR/mark_code.py"
#!/usr/bin/env python3
"""
Peacock Code Marking Script
Adds section markers to code files for enhanced analysis
"""

import sys
import os

def mark_file(filepath):
    """Add Peacock section markers to a code file"""
    print(f"Marking file: {filepath}")
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Simple marking - add START/FINISH markers around functions
    marked_content = f"""# START ### PEACOCK MARKED FILE ###
# File: {os.path.basename(filepath)}
# Marked: {__import__('datetime').datetime.now()}
# FINISH ### PEACOCK MARKED FILE ###

{content}

# START ### PEACOCK ANALYSIS READY ###
# This file has been marked for Peacock analysis
# FINISH ### PEACOCK ANALYSIS READY ###
"""
    
    # Create marked version
    base, ext = os.path.splitext(filepath)
    marked_filepath = f"{base}-marked{ext}"
    
    with open(marked_filepath, 'w', encoding='utf-8') as f:
        f.write(marked_content)
    
    print(f"Marked file created: {marked_filepath}")
    return marked_filepath

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: mark_code.py <mode> <filepath>")
        print("Mode: 1 = mark file")
        sys.exit(1)
    
    mode = sys.argv[1]
    filepath = sys.argv[2]
    
    if mode == "1":
        mark_file(filepath)
    else:
        print(f"Unknown mode: {mode}")
        sys.exit(1)
EOF

chmod +x "$PEACOCK_PLUGIN_DIR/mark_code.py"

echo "✅ Sublime Plugin structure ready"

# Setup Documentation
echo "📚 Setting up documentation..."

cat << 'EOF' > "$PEACOCK_DIR/docs/README.md"
# Peacock Enhanced - Complete AI Development Platform

## Overview
Peacock Enhanced merges the 4-stage AI pipeline with traditional code operations in a unified development platform.

## Components

### 1. CLI Interface
- **Location**: `~/peacock/cli/`
- **Usage**: `./peacock.sh "project description"`
- **Features**: Complete 4-stage analysis from command line

### 2. Enhanced MCP Server
- **Location**: `~/peacock/mcp-server/`
- **Usage**: `python3 enhanced_mcp.py`
- **Port**: http://127.0.0.1:8000/process
- **Features**: 
  - Peacock stage routing
  - Traditional code operations
  - HTML report generation

### 3. Sublime Text Plugin
- **Location**: `~/.config/sublime-text/Packages/peacock-sublime/`
- **Features**:
  - Right-click context menu
  - Command palette integration
  - Real-time code analysis
  - File marking system

## Quick Start

1. **Start MCP Server**:
   ```bash
   cd ~/peacock/mcp-server
   python3 enhanced_mcp.py
   ```

2. **Use in Sublime**:
   - Select text
   - Right-click → Peacock → [Choose operation]
   - View results in browser reports or output panels

3. **CLI Usage**:
   ```bash
   cd ~/peacock/cli
   ./peacock.sh "Build a cryptocurrency portfolio tracker"
   ```

## Peacock Stages

### ⚡ Spark - Requirements Analysis
Analyzes project ideas and defines clear requirements, scope, and objectives.

### 🦅 Falcon - Architecture Design  
Designs technical architecture, technology stack, and system patterns.

### 🦅 Eagle - Implementation
Generates executable code, setup commands, and working prototypes.

### 🦅 Hawk - Quality Assurance
Creates comprehensive testing strategies and production readiness checklists.

## Traditional Code Operations

- **Fix**: Identify and correct code issues
- **Explain**: Provide detailed code explanations  
- **Rewrite**: Improve code efficiency and style
- **Alternatives**: Suggest different approaches
- **Question**: Answer questions about code

## Reports
All analysis results are saved as HTML reports in `~/peacock_reports/` with timestamps.

## System Requirements
- Python 3.7+
- Sublime Text 3/4
- Local LLM (Ollama recommended)
- Web browser for reports

## Configuration
Edit MCP server settings in `enhanced_mcp.py`:
- LLM endpoint URL
- Model name
- Report styling
- Stage prompts
EOF

cat << 'EOF' > "$PEACOCK_DIR/docs/INSTALLATION.md"
# Peacock Enhanced Installation Guide

## Automatic Installation

Run the setup script:
```bash
curl -fsSL https://raw.githubusercontent.com/your-repo/peacock/main/setup.sh | bash
```

## Manual Installation

### 1. Setup Directories
```bash
mkdir -p ~/peacock/{cli,mcp-server,sublime-plugin,docs}
mkdir -p ~/peacock_reports
```

### 2. Install MCP Server
```bash
cd ~/peacock/mcp-server
# Copy enhanced_mcp.py from artifacts
python3 -m pip install -r requirements.txt
```

### 3. Install Sublime Plugin
```bash
# Copy plugin files to Sublime packages directory
# Linux: ~/.config/sublime-text/Packages/peacock-sublime/
# macOS: ~/Library/Application Support/Sublime Text/Packages/peacock-sublime/
# Windows: %APPDATA%/Sublime Text/Packages/peacock-sublime/
```

### 4. Setup Local LLM (Ollama)
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a code model
ollama pull codegeex4:9b-all-q4_K_M

# Start Ollama service
ollama serve
```

### 5. Test Installation
```bash
# Start MCP server
cd ~/peacock/mcp-server
python3 enhanced_mcp.py &

# Test CLI
cd ~/peacock/cli
./peacock.sh "Create a simple web app"

# Test Sublime: Select text → Right-click → Peacock → Full Analysis
```

## Troubleshooting

### MCP Server Won't Start
- Check Python version: `python3 --version`
- Install dependencies: `pip3 install -r requirements.txt`
- Check port availability: `netstat -an | grep 8000`

### Sublime Plugin Not Working
- Restart Sublime Text
- Check console: View → Show Console
- Verify files in packages directory

### LLM Connection Issues
- Verify Ollama is running: `curl http://localhost:11434/api/tags`
- Check model is downloaded: `ollama list`
- Update model name in enhanced_mcp.py

### Reports Not Opening
- Check browser default settings
- Verify ~/peacock_reports directory exists
- Check file permissions

## Configuration Files

### MCP Server Config
Edit `~/peacock/mcp-server/enhanced_mcp.py`:
```python
LOCAL_LLM_URL = "http://127.0.0.1:11434/api/generate"
LOCAL_LLM_MODEL_NAME = "your-model-name"
```

### Sublime Plugin Config  
Edit `~/.config/sublime-text/Packages/peacock-sublime/peacock_enhanced.py`:
```python
MCP_HUB_URL = "http://127.0.0.1:8000/process"
```
EOF

echo "✅ Documentation created"

# Setup examples
echo "🎯 Setting up examples..."

cat << 'EOF' > "$PEACOCK_DIR/examples/sample_project.md"
# Sample Peacock Analysis

## Project Idea
"Build a real-time chat application with file sharing"

## How to Test

### CLI Method
```bash
cd ~/peacock/cli
./peacock.sh "Build a real-time chat application with file sharing"
```

### Sublime Method
1. Open Sublime Text
2. Create new file with above project description
3. Select the text
4. Right-click → Peacock → Full Analysis
5. View report in browser

## Expected Output
- Requirements analysis (Spark)
- Technical architecture (Falcon)  
- Implementation guide (Eagle)
- QA strategy (Hawk)
- HTML reports in ~/peacock_reports/
EOF

cat << 'EOF' > "$PEACOCK_DIR/examples/code_sample.py"
# Sample Code for Testing Peacock Code Operations

def fibonacci(n):
    if n <= 1:
        return n
    else:
        return fibonacci(n-1) + fibonacci(n-2)

# Test Instructions:
# 1. Select the fibonacci function above
# 2. Right-click → Peacock → Fix Code (to optimize recursion)
# 3. Try → Peacock → Explain Code (for detailed explanation)
# 4. Try → Peacock → Alternatives (for different implementations)

class Calculator:
    def add(self, a, b):
        return a + b
    
    def divide(self, a, b):
        return a / b  # Potential division by zero issue

# Test the fix operation on the divide method to see error handling suggestions
EOF

echo "✅ Examples created"

# Create startup scripts
echo "🚀 Creating startup scripts..."

cat << 'EOF' > "$PEACOCK_DIR/start_peacock.sh"
#!/bin/bash

# Peacock Enhanced Startup Script

echo "🦚 Starting Peacock Enhanced Platform..."

# Check if Ollama is running
if ! curl -s http://localhost:11434/api/tags > /dev/null; then
    echo "⚠️  Ollama not detected. Starting Ollama..."
    ollama serve &
    sleep 3
fi

# Start Enhanced MCP Server
echo "🖥️  Starting Enhanced MCP Server..."
cd "$HOME/peacock/mcp-server"
python3 enhanced_mcp.py &
MCP_PID=$!

echo "✅ Peacock Enhanced is ready!"
echo ""
echo "🔧 Usage:"
echo "  CLI: cd ~/peacock/cli && ./peacock.sh 'your project'"
echo "  Sublime: Select text → Right-click → Peacock"
echo "  Reports: ~/peacock_reports/"
echo ""
echo "Press Ctrl+C to stop all services"

# Wait for interrupt
trap "echo '🛑 Stopping Peacock...'; kill $MCP_PID 2>/dev/null; exit 0" INT
wait
EOF

chmod +x "$PEACOCK_DIR/start_peacock.sh"

cat << 'EOF' > "$PEACOCK_DIR/stop_peacock.sh"
#!/bin/bash

# Stop Peacock services
echo "🛑 Stopping Peacock Enhanced..."

# Stop MCP server
pkill -f "enhanced_mcp.py"

# Stop Ollama if started by Peacock
# pkill -f "ollama serve"

echo "✅ Peacock Enhanced stopped"
EOF

chmod +x "$PEACOCK_DIR/stop_peacock.sh"

echo "✅ Startup scripts created"

# Final setup steps
echo "🔧 Final setup steps..."

# Create desktop shortcut (Linux)
if command -v desktop-file-install &> /dev/null; then
    cat << EOF > "$HOME/Desktop/peacock-enhanced.desktop"
[Desktop Entry]
Version=1.0
Type=Application
Name=Peacock Enhanced
Comment=AI Development Platform
Exec=$PEACOCK_DIR/start_peacock.sh
Icon=applications-development
Terminal=true
Categories=Development;
EOF
    chmod +x "$HOME/Desktop/peacock-enhanced.desktop"
    echo "✅ Desktop shortcut created"
fi

# Add to PATH (optional)
if ! grep -q "peacock/cli" "$HOME/.bashrc" 2>/dev/null; then
    echo "export PATH=\"\$PATH:$PEACOCK_DIR/cli\"" >> "$HOME/.bashrc"
    echo "✅ Added to PATH (restart terminal or run: source ~/.bashrc)"
fi

echo ""
echo "🎉 PEACOCK ENHANCED SETUP COMPLETE! 🎉"
echo "========================================"
echo ""
echo "📁 Installation Directory: $PEACOCK_DIR"
echo "📊 Reports Directory: $REPORTS_DIR"
echo "🔌 Sublime Plugin: $PEACOCK_PLUGIN_DIR"
echo ""
echo "🚀 TO START PEACOCK:"
echo "   $PEACOCK_DIR/start_peacock.sh"
echo ""
echo "🔧 NEXT STEPS:"
echo "1. Replace placeholder files with actual enhanced code:"
echo "   - $PEACOCK_DIR/mcp-server/enhanced_mcp.py"
echo "   - $PEACOCK_PLUGIN_DIR/peacock_enhanced.py"
echo ""
echo "2. Install/configure Ollama:"
echo "   curl -fsSL https://ollama.ai/install.sh | sh"
echo "   ollama pull codegeex4:9b-all-q4_K_M"
echo ""
echo "3. Restart Sublime Text to load the plugin"
echo ""
echo "4. Test with sample project:"
echo "   cd $PEACOCK_DIR/cli"
echo "   ./peacock.sh 'Build a todo app with React'"
echo ""
echo "📚 Documentation: $PEACOCK_DIR/docs/"
echo "🎯 Examples: $PEACOCK_DIR/examples/"
echo ""
echo "READY TO REVOLUTIONIZE YOUR DEVELOPMENT WORKFLOW! 🦚🚀"
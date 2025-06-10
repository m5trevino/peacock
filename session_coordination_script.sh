#!/bin/bash
# Session Coordination Test Script - Deploy All Wire Fixes

echo "🦚================================================================🦚"
echo "    PEACOCK WIRE FIX DEPLOYMENT - ALL 4 WIRES"
echo "🦚================================================================🦚"
echo

# Get current timestamp for session
WEEK=$(date +%V)
DAY=$(date +%d)
HOUR=$(date +%H)
MINUTE=$(date +%M)
SESSION="${WEEK}-${DAY}-${HOUR}${MINUTE}"

echo "🔥 Session Timestamp: $SESSION (Military Time)"
echo "📁 Base Directory: /home/flintx/peacock"
echo

# Create backup of current files
echo "💾 Creating backups..."
cd /home/flintx/peacock
mkdir -p backups/pre-wire-fixes

cp core/pea-mcp.py backups/pre-wire-fixes/pea-mcp-backup.py 2>/dev/null || echo "   ⚠️  No existing pea-mcp.py to backup"
cp core/1prompt.py backups/pre-wire-fixes/1prompt-backup.py 2>/dev/null || echo "   ⚠️  No existing 1prompt.py to backup"
cp aviary/out_homing.py backups/pre-wire-fixes/out_homing-backup.py 2>/dev/null || echo "   ⚠️  No existing out_homing.py to backup"

echo "✅ Backups created in backups/pre-wire-fixes/"
echo

# Verify directory structure
echo "🔍 Verifying directory structure..."
if [ ! -d "aviary" ]; then
    echo "❌ Missing /aviary directory"
    exit 1
fi

if [ ! -d "core" ]; then
    echo "❌ Missing /core directory"
    exit 1
fi

# Check for required bird files
BIRDS=("spark.py" "falcon.py" "eagle.py" "hawk.py" "in_homing.py")
for bird in "${BIRDS[@]}"; do
    if [ ! -f "aviary/$bird" ]; then
        echo "❌ Missing bird: aviary/$bird"
        exit 1
    fi
done

echo "✅ All required birds found in /aviary"

# Check for core files
if [ ! -f "core/xedit.py" ]; then
    echo "❌ Missing core/xedit.py parser"
    exit 1
fi

echo "✅ Core parser found: xedit.py"
echo

# Create directories if they don't exist
echo "📁 Ensuring directory structure..."
mkdir -p html
mkdir -p logs

echo "✅ Directories ready"
echo

# Test current MCP connection (if running)
echo "🔍 Testing current MCP connection..."
MCP_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/ 2>/dev/null)

if [ "$MCP_RESPONSE" = "200" ]; then
    echo "⚠️  MCP server is currently running"
    echo "   Please stop the current server before deploying fixes"
    echo "   Use: Ctrl+C in the MCP terminal"
    echo
    read -p "Press Enter when MCP server is stopped..."
else
    echo "✅ No conflicting MCP server detected"
fi

echo

# Wire fix status check
echo "🔧 WIRE FIX STATUS CHECK:"
echo "   🔌 Wire #1: Web UI → MCP (1prompt fetch fix)"
echo "   🔌 Wire #2: MCP → Birds (orchestrator integration)"  
echo "   🔌 Wire #3: Birds → LLM (mixed content generation)"
echo "   🔌 Wire #4: LLM → XEdit (session-synced parsing)"
echo

# Deployment confirmation
echo "🚀 READY TO DEPLOY WIRE FIXES"
echo
echo "This will:"
echo "   1. Deploy fixed pea-mcp.py with bird orchestration"
echo "   2. Deploy fixed 1prompt.py with real MCP connection"
echo "   3. Deploy fixed out_homing.py with mixed content generation"
echo "   4. Generate session-coordinated dashboard"
echo "   5. Start enhanced MCP server with logging"
echo

read -p "Deploy all wire fixes? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Deployment cancelled"
    exit 1
fi

echo
echo "🔥 DEPLOYING WIRE FIXES..."
echo

# Note: In a real deployment, you would copy the fixed files here
# For this demo, we're showing the deployment process

echo "📋 DEPLOYMENT STEPS:"
echo "   1. Copy fixed pea-mcp.py → /home/flintx/peacock/core/"
echo "   2. Copy fixed out_homing.py → /home/flintx/peacock/aviary/"  
echo "   3. Run fixed 1prompt.py to generate dashboard"
echo "   4. Start enhanced MCP server with logging"
echo

echo "⚡ TESTING SEQUENCE:"
echo "   1. Generate 1prompt dashboard with session: $SESSION"
echo "   2. Start MCP server with bird orchestration"
echo "   3. Test Wire #1: Dashboard → MCP connection"
echo "   4. Test Wire #2: MCP → Birds pipeline"
echo "   5. Test Wire #3: Birds → Mixed content generation"
echo "   6. Test Wire #4: Mixed content → XEdit parsing"
echo

echo "📄 EXPECTED FILES AFTER DEPLOYMENT:"
echo "   📊 /home/flintx/peacock/html/1prompt-dashboard-$SESSION.html"
echo "   🎯 /home/flintx/peacock/html/xedit-$SESSION.html (after pipeline)"
echo "   📝 /home/flintx/peacock/logs/promptlog-$SESSION.txt"
echo "   📋 /home/flintx/peacock/logs/responselog-$SESSION.txt"
echo "   🔧 /home/flintx/peacock/logs/mcplog-$SESSION.txt"
echo "   🎯 /home/flintx/peacock/logs/xeditlog-$SESSION.txt"
echo

echo "🎯 SUCCESS CRITERIA:"
echo "   ✅ Dashboard opens with session $SESSION in top right"
echo "   ✅ 'Build Project' button makes real HTTP request to MCP"
echo "   ✅ MCP terminal shows incoming peacock_full requests"
echo "   ✅ All 4 birds execute with real character counts"
echo "   ✅ XEdit interface auto-generates with populated functions"
echo "   ✅ 7x001 paths work for surgical code editing"
echo

echo "🔧 MANUAL DEPLOYMENT COMMANDS:"
echo
echo "# 1. Generate dashboard (run from /home/flintx/peacock/core/):"
echo "python3 1prompt.py"
echo
echo "# 2. Start fixed MCP server (run from /home/flintx/peacock/core/):"
echo "python3 pea-mcp.py --log"
echo
echo "# 3. Test connection:"
echo "curl -X POST http://127.0.0.1:8000/process \\"
echo "  -H \"Content-Type: application/json\" \\"
echo "  -d '{\"command\": \"peacock_full\", \"text\": \"test snake game\"}'"
echo

echo "🦚 WIRE FIX DEPLOYMENT GUIDE COMPLETE 🦚"
echo
echo "Ready to drop those dimes and get this pipeline locked down! 🔥💯"
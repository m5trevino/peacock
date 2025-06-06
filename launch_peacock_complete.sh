#!/bin/bash
echo "🦚 Starting Complete Peacock System..."
cd /home/flintx/peacock

# Start MCP server
python enhanced_mcp_server.py &
MCP_PID=$!
echo "🔥 MCP Server started (PID: $MCP_PID)"
sleep 2

# Open interfaces
firefox "file:///home/flintx/peacock/html/reports/peacock_model_dashboard.html" &
echo "🌐 Model Dashboard opened"

echo "✅ Peacock Complete System ready!"
echo "📋 Usage:"
echo "  1. Select model in dashboard"
echo "  2. Type prompt in chat (e.g., 'Build a snake game')"
echo "  3. Click 'Send to LLM2'"
echo "  4. Open XEdit interface to edit functions"
echo "📝 To stop: kill $MCP_PID"

#!/bin/bash
# FIX MCP LOGGING - Add the missing mega prompt and final response logs

echo "🔥 FIXING MCP LOGGING SYSTEM..."

# STEP 1: Find where the mega prompt assembly happens in out_homing.py
echo "📋 STEP 1: Adding mega prompt logging to out_homing.py..."

# Add mega prompt logging function to out_homing.py
cat >> /home/flintx/peacock/core/out_homing.py << 'EOF'

def log_mega_prompt(session_timestamp, mega_prompt, user_input, command):
    """Log the assembled mega prompt for debugging"""
    import os
    import datetime
    
    # Ensure logs directory exists
    logs_dir = "/home/flintx/peacock/core/logs"
    os.makedirs(logs_dir, exist_ok=True)
    
    # Write mega prompt log
    mega_log_path = f"{logs_dir}/megapromptlog-{session_timestamp}.txt"
    
    with open(mega_log_path, "w") as f:
        f.write(f"[{datetime.datetime.now().isoformat()}] ASSEMBLED MEGA PROMPT\n")
        f.write(f"Session: {session_timestamp}\n")
        f.write(f"Command: {command}\n") 
        f.write(f"Input: {user_input}\n")
        f.write("=" * 60 + "\n")
        f.write("MEGA PROMPT CONTENT:\n")
        f.write("=" * 60 + "\n")
        f.write(mega_prompt)
        f.write("\n" + "=" * 60 + "\n")
    
    print(f"✅ Mega prompt logged: {mega_log_path}")
    return mega_log_path

def log_final_response(session_timestamp, final_response, model_used):
    """Log the final LLM response for debugging"""
    import os
    import datetime
    
    # Ensure logs directory exists  
    logs_dir = "/home/flintx/peacock/core/logs"
    os.makedirs(logs_dir, exist_ok=True)
    
    # Write final response log
    final_log_path = f"{logs_dir}/finalresponselog-{session_timestamp}.txt"
    
    with open(final_log_path, "w") as f:
        f.write(f"[{datetime.datetime.now().isoformat()}] FINAL GROQ RESPONSE\n")
        f.write(f"Session: {session_timestamp}\n")
        f.write(f"Model: {model_used}\n")
        f.write("=" * 60 + "\n")
        f.write("FINAL RESPONSE CONTENT:\n")
        f.write("=" * 60 + "\n")
        f.write(final_response)
        f.write("\n" + "=" * 60 + "\n")
    
    print(f"✅ Final response logged: {final_log_path}")
    return final_log_path
EOF

# STEP 2: Find the mega prompt assembly in out_homing.py and add logging calls
echo "📋 STEP 2: Adding logging calls to mega prompt assembly..."

# Look for where the mega prompt gets assembled (this will vary based on your code structure)
# We need to add the logging calls right before and after the final Groq call

# Add logging call before final Groq request
sed -i '/# Final Groq call\|# Send mega prompt to Groq\|final_response.*=.*groq/i\
        # Log the assembled mega prompt\
        log_mega_prompt(session_timestamp, assembled_mega_prompt, user_input, command)' /home/flintx/peacock/core/out_homing.py

# Add logging call after final Groq response
sed -i '/final_response.*=.*groq\|response.*=.*groq.*create/a\
        # Log the final response\
        log_final_response(session_timestamp, final_response, model_used)' /home/flintx/peacock/core/out_homing.py

# STEP 3: Also add logging to pea-mcp.py if it handles the orchestration
echo "📋 STEP 3: Adding logging to pea-mcp.py..."

# Check if pea-mcp.py has the orchestration code
if grep -q "groq\|llm\|mega.*prompt" /home/flintx/peacock/core/pea-mcp.py; then
    echo "   🔧 Found LLM calls in pea-mcp.py, adding logging..."
    
    # Add the logging functions to pea-mcp.py as well
    cat >> /home/flintx/peacock/core/pea-mcp.py << 'EOF'

def log_mega_prompt(session_timestamp, mega_prompt, user_input, command):
    """Log the assembled mega prompt for debugging"""
    import os
    import datetime
    
    logs_dir = "/home/flintx/peacock/core/logs"
    os.makedirs(logs_dir, exist_ok=True)
    
    mega_log_path = f"{logs_dir}/megapromptlog-{session_timestamp}.txt"
    
    with open(mega_log_path, "w") as f:
        f.write(f"[{datetime.datetime.now().isoformat()}] ASSEMBLED MEGA PROMPT\n")
        f.write(f"Session: {session_timestamp}\n")
        f.write(f"Command: {command}\n") 
        f.write(f"Input: {user_input}\n")
        f.write("=" * 60 + "\n")
        f.write("MEGA PROMPT CONTENT:\n")
        f.write("=" * 60 + "\n")
        f.write(mega_prompt)
        f.write("\n" + "=" * 60 + "\n")
    
    print(f"✅ Mega prompt logged: {mega_log_path}")
    return mega_log_path

def log_final_response(session_timestamp, final_response, model_used):
    """Log the final LLM response for debugging"""
    import os
    import datetime
    
    logs_dir = "/home/flintx/peacock/core/logs"
    os.makedirs(logs_dir, exist_ok=True)
    
    final_log_path = f"{logs_dir}/finalresponselog-{session_timestamp}.txt"
    
    with open(final_log_path, "w") as f:
        f.write(f"[{datetime.datetime.now().isoformat()}] FINAL GROQ RESPONSE\n")
        f.write(f"Session: {session_timestamp}\n")
        f.write(f"Model: {model_used}\n")
        f.write("=" * 60 + "\n")
        f.write("FINAL RESPONSE CONTENT:\n")
        f.write("=" * 60 + "\n")
        f.write(final_response)
        f.write("\n" + "=" * 60 + "\n")
    
    print(f"✅ Final response logged: {final_log_path}")
    return final_log_path
EOF

    # Add logging calls to pea-mcp.py
    sed -i '/# Final.*call\|final.*response.*=\|response.*=.*groq/i\
            log_mega_prompt(session_timestamp, mega_prompt, user_input, command)' /home/flintx/peacock/core/pea-mcp.py
    
    sed -i '/final.*response.*=\|response.*=.*groq.*create/a\
            log_final_response(session_timestamp, response.choices[0].message.content, model_used)' /home/flintx/peacock/core/pea-mcp.py
else
    echo "   ⚠️ No LLM calls found in pea-mcp.py"
fi

# STEP 4: Update 1prompt.py to include links to the new log files
echo "📋 STEP 4: Updating 1prompt.py to link to new log files..."

# Add links to mega prompt and final response logs in the HTML template
sed -i '/promptlog.*href/a\
            <a href="logs/megapromptlog-{session_timestamp}.txt" target="_blank">📋 Mega Prompt Log</a><br>\
            <a href="logs/finalresponselog-{session_timestamp}.txt" target="_blank">🎯 Final Response Log</a><br>' /home/flintx/peacock/core/1prompt.py

# STEP 5: Fix the output format instruction to get CODE instead of QA docs
echo "📋 STEP 5: Adding strong output format instruction..."

# Create a format instruction that forces code output
cat > /tmp/format_instruction.py << 'EOF'
#!/usr/bin/env python3
# Add strong format instruction to force code output instead of QA documentation

FORMAT_INSTRUCTION = '''

CRITICAL OUTPUT FORMAT REQUIREMENT:

You MUST return ONLY complete, executable code files in this EXACT format:

```filename: index.html
<!DOCTYPE html>
<html>
<head>
    <title>Snake Game</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <canvas id="gameCanvas"></canvas>
    <script src="script.js"></script>
</body>
</html>
```

```filename: style.css
body {
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100vh;
    margin: 0;
    background-color: #000;
}

canvas {
    border: 2px solid #fff;
}
```

```filename: script.js
const canvas = document.getElementById('gameCanvas');
const ctx = canvas.getContext('2d');

// Complete game implementation here
// [rest of JavaScript code]
```

DO NOT RETURN:
- Documentation
- Testing procedures  
- QA checklists
- Explanations
- Setup instructions

ONLY RETURN: Complete, functional code files that create a working application.
'''

# Add this instruction to the end of mega prompts
def add_format_instruction_to_prompt(mega_prompt):
    return mega_prompt + FORMAT_INSTRUCTION

# Export the function for use in other modules
__all__ = ['add_format_instruction_to_prompt', 'FORMAT_INSTRUCTION']
EOF

# Add format instruction to the mega prompt assembly
echo "   🎯 Adding format instruction to mega prompt assembly..."

# Copy the format instruction to the core directory
cp /tmp/format_instruction.py /home/flintx/peacock/core/format_instruction.py

# Import and use the format instruction in out_homing.py
sed -i '1a\
from format_instruction import add_format_instruction_to_prompt' /home/flintx/peacock/core/out_homing.py

# Apply format instruction to mega prompt before sending to Groq
sed -i '/mega_prompt.*=\|assembled.*prompt.*=/a\
        # Apply strong format instruction to force code output\
        mega_prompt = add_format_instruction_to_prompt(mega_prompt)' /home/flintx/peacock/core/out_homing.py

echo ""
echo "🎉 MCP LOGGING FIX COMPLETE!"
echo ""
echo "✅ WHAT WAS ADDED:"
echo "   📋 megapromptlog-{session}.txt - See the assembled mega prompt"
echo "   🎯 finalresponselog-{session}.txt - See the final Groq response"
echo "   🔗 Updated 1prompt.py links to include new logs"
echo "   💪 Strong format instruction to force code output"
echo ""
echo "🚀 NOW TEST YOUR WORKFLOW:"
echo "   1. Run a prompt: 'build a snake game'"
echo "   2. Check for the new log files in /home/flintx/peacock/core/logs/"
echo "   3. Verify you get CODE files instead of QA documentation"
echo ""
echo "🎯 THIS SHOULD FIX THE EXACT ISSUES THE VALIDATORS FOUND!"
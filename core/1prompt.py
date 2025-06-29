#!/usr/bin/env python3
"""
1prompt.py - ADVANCED PEACOCK DASHBOARD WITH BIRD PROGRESS
Shows real-time progress, character counts, and model assignments for each bird
"""

import datetime
import webbrowser
import sys
from pathlib import Path
import random
import subprocess

# PEACOCK PATHS
HTML_OUTPUT_DIR = Path("/home/flintx/peacock/html")
LOGS_DIR = Path("/home/flintx/peacock/logs")

def get_session_timestamp():
    """Generate session timestamp matching MCP server format"""
    now = datetime.datetime.now()
    week = now.isocalendar()[1]
    day = now.day
    hour = now.hour
    minute = now.minute
    return f"{week}-{day}-{hour}{minute:02d}"

def generate_advanced_dashboard(session_timestamp):
    """Generate ADVANCED dashboard with bird progress tracking"""
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🦚 Peacock Live Pipeline Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'SF Mono', monospace; 
            background: #0d1117; 
            color: #e6edf3; 
            min-height: 100vh; 
            padding: 20px; 
        }}
        
        .header {{ 
            background: #161b22; 
            border-bottom: 1px solid #30363d; 
            padding: 16px 24px; 
            margin: -20px -20px 20px -20px; 
            position: sticky; 
            top: 0; 
            z-index: 100; 
        }}
        
        .header-content {{ 
            max-width: 1400px; 
            margin: 0 auto; 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
        }}
        
        .logo {{ 
            font-size: 20px; 
            font-weight: bold; 
            color: #ff6b35; 
        }}
        
        .session-info {{ 
            background: rgba(0, 255, 136, 0.1); 
            border: 1px solid #00ff88; 
            border-radius: 6px; 
            padding: 6px 12px; 
            font-size: 12px; 
            color: #00ff88; 
        }}
        
        .main-container {{ 
            max-width: 1400px; 
            margin: 0 auto; 
            display: grid; 
            grid-template-columns: 1fr 1fr; 
            gap: 24px; 
        }}
        
        .input-section {{ 
            background: #161b22; 
            border: 1px solid #30363d; 
            border-radius: 12px; 
            padding: 24px; 
        }}
        
        .input-title {{ 
            color: #ff6b35; 
            font-size: 18px; 
            font-weight: 600; 
            margin-bottom: 16px; 
        }}
        
        .prompt-container {{ 
            display: flex; 
            gap: 12px; 
            margin-bottom: 16px; 
        }}
        
        .prompt-input {{ 
            flex: 1; 
            padding: 12px 16px; 
            background: #0d1117; 
            border: 2px solid #30363d; 
            border-radius: 8px; 
            color: #e6edf3; 
            font-size: 16px; 
            font-family: inherit; 
        }}
        
        .prompt-input:focus {{ 
            outline: none; 
            border-color: #ff6b35; 
        }}
        
        .send-btn {{ 
            padding: 12px 24px; 
            background: linear-gradient(45deg, #ff6b35, #ff8c5a); 
            border: none; 
            border-radius: 8px; 
            color: white; 
            font-weight: 600; 
            cursor: pointer; 
            transition: all 0.2s; 
        }}
        
        .send-btn:hover {{ 
            transform: translateY(-2px); 
            box-shadow: 0 4px 12px rgba(255, 107, 53, 0.3); 
        }}
        
        .send-btn:disabled {{ 
            background: #30363d; 
            color: #8b949e; 
            cursor: not-allowed; 
            transform: none; 
        }}
        
        .pipeline-section {{ 
            background: #161b22; 
            border: 1px solid #30363d; 
            border-radius: 12px; 
            padding: 24px; 
        }}
        
        .pipeline-title {{ 
            color: #ff6b35; 
            font-size: 18px; 
            font-weight: 600; 
            margin-bottom: 20px; 
            text-align: center; 
        }}
        
        .stage-grid {{ 
            display: grid; 
            grid-template-columns: 1fr 1fr; 
            gap: 16px; 
            margin-bottom: 24px; 
        }}
        
        .stage-card {{ 
            background: #0d1117; 
            border: 2px solid #30363d; 
            border-radius: 8px; 
            padding: 20px; 
            transition: all 0.3s; 
        }}
        
        .stage-card.active {{ 
            border-color: #ff6b35; 
            box-shadow: 0 0 20px rgba(255, 107, 53, 0.2); 
        }}
        
        .stage-card.completed {{ 
            border-color: #238636; 
            background: rgba(35, 134, 54, 0.05); 
        }}
        
        .stage-header {{ 
            display: flex; 
            align-items: center; 
            gap: 8px; 
            margin-bottom: 12px; 
        }}
        
        .stage-icon {{ 
            font-size: 20px; 
        }}
        
        .stage-name {{ 
            font-weight: 600; 
            font-size: 14px; 
        }}
        
        .stage-status {{ 
            font-size: 10px; 
            padding: 2px 6px; 
            border-radius: 4px; 
            margin-left: auto; 
        }}
        
        .stage-status.waiting {{ 
            background: #30363d; 
            color: #8b949e; 
        }}
        
        .stage-status.active {{ 
            background: rgba(255, 107, 53, 0.2); 
            color: #ff6b35; 
        }}
        
        .stage-status.completed {{ 
            background: rgba(35, 134, 54, 0.2); 
            color: #238636; 
        }}
        
        .stage-model {{ 
            font-size: 10px; 
            color: #8b949e; 
            margin-bottom: 8px; 
        }}
        
        .stage-progress {{ 
            font-size: 12px; 
            color: #e6edf3; 
        }}
        
        .stage-chars {{ 
            font-size: 11px; 
            color: #ff6b35; 
            font-weight: 600; 
        }}
        
        .final-section {{ 
            grid-column: 1 / -1; 
            background: #0d1117; 
            border: 2px solid #30363d; 
            border-radius: 8px; 
            padding: 20px; 
            text-align: center; 
            display: none; 
        }}
        
        .final-section.show {{ 
            display: block; 
            border-color: #238636; 
        }}
        
        .final-title {{ 
            color: #238636; 
            font-size: 16px; 
            font-weight: 600; 
            margin-bottom: 12px; 
        }}
        
        .final-stats {{ 
            display: flex; 
            justify-content: center; 
            gap: 24px; 
            margin-bottom: 16px; 
        }}
        
        .final-stat {{ 
            text-align: center; 
        }}
        
        .final-stat-value {{ 
            font-size: 20px; 
            font-weight: 600; 
            color: #ff6b35; 
        }}
        
        .final-stat-label {{ 
            font-size: 10px; 
            color: #8b949e; 
            text-transform: uppercase; 
        }}
        
        .xedit-btn {{ 
            padding: 12px 24px; 
            background: linear-gradient(45deg, #238636, #2ea043); 
            border: none; 
            border-radius: 8px; 
            color: white; 
            font-weight: 600; 
            cursor: pointer; 
            font-size: 14px; 
        }}
        
        .log-links {{ 
            display: flex; 
            gap: 12px; 
            justify-content: center; 
            margin-top: 16px; 
            flex-wrap: wrap;
        }}
        
        .log-link {{ 
            padding: 6px 12px; 
            background: #30363d; 
            border: 1px solid #484f58; 
            border-radius: 6px; 
            color: #e6edf3; 
            text-decoration: none; 
            font-size: 10px; 
            transition: all 0.2s; 
        }}
        
        .log-link:hover {{ 
            border-color: #ff6b35; 
            color: #ff6b35; 
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div class="logo">🦚 Peacock Live Pipeline Dashboard</div>
            <div class="session-info">Session: {session_timestamp}</div>
        </div>
    </div>
    
    <div class="main-container">
        <div class="input-section">
            <div class="input-title">🎯 Project Request</div>
            <div class="prompt-container">
                <input type="text" 
                       class="prompt-input" 
                       id="promptInput" 
                       placeholder="Describe your project in detail..." />
                <select id="modelChoice" class="prompt-input" style="flex: 0.5;">
                    <option value="qwen-32b-instruct">Qwen 32B Instruct</option>
                    <option value="qwen-32b-legacy-qwq">Qwen 32B Legacy</option>
                    <option value="deepseek-coder-v2">Deepseek Coder V2</option>
                    <option value="llama-3.1-70b-versatile">Llama 3.1 70B</option>
                </select>
                <button class="send-btn" id="sendBtn" onclick="startPipeline()">
                    Start Pipeline
                </button>
            </div>
            
            <div style="font-size: 12px; color: #8b949e; margin-top: 12px;">
                <strong>🦚 4-Stage Bird Pipeline:</strong><br>
                SPARK (Requirements) → FALCON (Architecture) → EAGLE (Code) → HAWK (QA)
            </div>
        </div>
        
        <div class="pipeline-section">
            <div class="pipeline-title">🔥 Live Pipeline Progress</div>
            
            <div class="stage-grid">
                <!-- SPARK Stage -->
                <div class="stage-card" id="sparkCard">
                    <div class="stage-header">
                        <div class="stage-icon">🔥</div>
                        <div class="stage-name">SPARK</div>
                        <div class="stage-status waiting" id="sparkStatus">WAITING</div>
                    </div>
                    <div class="stage-model">meta-llama/llama-4-scout-17b-16e-instruct</div>
                    <div class="stage-progress" id="sparkProgress">Requirements Analysis</div>
                    <div class="stage-chars" id="sparkChars">0 chars</div>
                </div>
                
                <!-- FALCON Stage -->
                <div class="stage-card" id="falconCard">
                    <div class="stage-header">
                        <div class="stage-icon">🦅</div>
                        <div class="stage-name">FALCON</div>
                        <div class="stage-status waiting" id="falconStatus">WAITING</div>
                    </div>
                    <div class="stage-model">meta-llama/llama-4-maverick-17b-128e-instruct</div>
                    <div class="stage-progress" id="falconProgress">Architecture Design</div>
                    <div class="stage-chars" id="falconChars">0 chars</div>
                </div>
                
                <!-- EAGLE Stage -->
                <div class="stage-card" id="eagleCard">
                    <div class="stage-header">
                        <div class="stage-icon">🦅</div>
                        <div class="stage-name">EAGLE</div>
                        <div class="stage-status waiting" id="eagleStatus">WAITING</div>
                    </div>
                    <div class="stage-model">meta-llama/llama-4-scout-17b-16e-instruct</div>
                    <div class="stage-progress" id="eagleProgress">Code Implementation</div>
                    <div class="stage-chars" id="eagleChars">0 chars</div>
                </div>
                
                <!-- HAWK Stage -->
                <div class="stage-card" id="hawkCard">
                    <div class="stage-header">
                        <div class="stage-icon">🦅</div>
                        <div class="stage-name">HAWK</div>
                        <div class="stage-status waiting" id="hawkStatus">WAITING</div>
                    </div>
                    <div class="stage-model">meta-llama/llama-4-maverick-17b-128e-instruct</div>
                    <div class="stage-progress" id="hawkProgress">Quality Assurance</div>
                    <div class="stage-chars" id="hawkChars">0 chars</div>
                </div>
            </div>
            
            <!-- Final Results Section -->
            <div class="final-section" id="finalSection">
                <div class="final-title">🎉 Pipeline Complete!</div>
                <div class="final-stats">
                    <div class="final-stat">
                        <div class="final-stat-value" id="totalChars">0</div>
                        <div class="final-stat-label">Total Characters</div>
                    </div>
                    <div class="final-stat">
                        <div class="final-stat-value" id="totalTime">0s</div>
                        <div class="final-stat-label">Total Time</div>
                    </div>
                    <div class="final-stat">
                        <div class="final-stat-value" id="filesGenerated">0</div>
                        <div class="final-stat-label">Files Generated</div>
                    </div>
                </div>
                <button class="xedit-btn" onclick="openXEdit()">
                    🎯 Open XEdit Interface
                </button>
                
                <div class="log-links">
                    <a href="#" class="log-link" id="promptLogLink" target="_blank">📝 Prompt Log</a>
                    <a href="#" class="log-link" id="responseLogLink" target="_blank">📋 Response Log</a>
                    <a href="#" class="log-link" id="mcpLogLink" target="_blank">🔧 MCP Log</a>
                    <a href="#" class="log-link" id="xeditLogLink" target="_blank">🎯 XEdit Log</a>
                    <a href="#" class="log-link" id="megaPromptLogLink" target="_blank">🔥 Mega Prompt Log</a>
                    <a href="#" class="log-link" id="finalResponseLogLink" target="_blank">✅ Final Response Log</a>
                </div>
            </div>
        </div>
    </div>

    <script>
        let pipelineStartTime = null;
        let pipelineResults = null;
        const sessionTimestamp = '{session_timestamp}';
        
        function updateStageStatus(stage, status, progress, chars = 0) {{
            const card = document.getElementById(stage + 'Card');
            const statusEl = document.getElementById(stage + 'Status');
            const progressEl = document.getElementById(stage + 'Progress');
            const charsEl = document.getElementById(stage + 'Chars');
            
            // Update status
            statusEl.className = 'stage-status ' + status;
            statusEl.textContent = status.toUpperCase();
            
            // Update card styling
            card.className = 'stage-card';
            if (status === 'active') {{
                card.classList.add('active');
            }} else if (status === 'completed') {{
                card.classList.add('completed');
            }}
            
            // Update progress text
            if (progress) {{
                progressEl.textContent = progress;
            }}
            
            // Update character count - FIXED
            if (chars > 0) {{
                charsEl.textContent = chars.toLocaleString() + ' chars';
            }}
        }}
        
        function updateLogLinks(sessionId) {{
            // Update all log links with correct session ID and paths
            document.getElementById('promptLogLink').href = `file:///home/flintx/peacock/core/logs/promptlog-${{sessionId}}.txt`;
            document.getElementById('responseLogLink').href = `file:///home/flintx/peacock/core/logs/responselog-${{sessionId}}.txt`;
            document.getElementById('mcpLogLink').href = `file:///home/flintx/peacock/core/logs/mcplog-${{sessionId}}.txt`;
            document.getElementById('xeditLogLink').href = `file:///home/flintx/peacock/core/logs/xeditlog-${{sessionId}}.txt`;
            document.getElementById('megaPromptLogLink').href = `file:///home/flintx/peacock/core/logs/megapromptlog-${{sessionId}}.txt`;
            document.getElementById('finalResponseLogLink').href = `file:///home/flintx/peacock/core/logs/finalresponselog-${{sessionId}}.txt`;
        }}
        
        function openXEdit() {{
            // Construct XEdit path with current session ID
            const xeditPath = `file:///home/flintx/peacock/html/xedit-${{sessionTimestamp}}.html`;
            console.log('Opening XEdit:', xeditPath);
            
            // Try to open the XEdit file
            try {{
                window.open(xeditPath, '_blank');
            }} catch (error) {{
                console.error('Failed to open XEdit:', error);
                alert('Failed to open XEdit interface. Check if the file exists at: ' + xeditPath);
            }}
        }}
        
        async function startPipeline() {{
            const promptInput = document.getElementById('promptInput');
            const modelChoice = document.getElementById('modelChoice').value;
            const sendBtn = document.getElementById('sendBtn');
            const finalSection = document.getElementById('finalSection');
            
            const prompt = promptInput.value.trim();
            
            if (!prompt) {{
                alert('Please describe your project');
                return;
            }}

            // Reset UI
            finalSection.classList.remove('show');
            const stages = ['spark', 'falcon', 'eagle', 'hawk'];
            stages.forEach(stage => updateStageStatus(stage, 'waiting', '', 0));
            
            // Disable input
            promptInput.disabled = true;
            sendBtn.disabled = true;
            sendBtn.textContent = 'Running Pipeline...';
            
            pipelineStartTime = Date.now();

            try {{
                console.log('🦚 Starting pipeline with session:', sessionTimestamp);
                console.log('🦚 Model choice:', modelChoice);
                updateStageStatus('spark', 'active', 'Analyzing requirements...', 0);
                
                const response = await fetch('http://127.0.0.1:8000/process', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{
                        command: 'peacock_full',
                        text: prompt,
                        timestamp: sessionTimestamp,
                        final_model_choice: modelChoice
                    }})
                }});

                if (!response.ok) {{
                    throw new Error(`HTTP ${{response.status}}: ${{response.statusText}}`);
                }}

                const result = await response.json();
                console.log('🦚 Full pipeline result:', result);
                
                if (result.success) {{
                    // FIXED: Extract stage data from the correct location
                    const stageData = result.stage_results || {{}};
                    console.log('🦚 Stage data received:', stageData);
                    
                    // Update each stage with actual data - FIXED character count handling
                    if (stageData.spark) {{
                        const sparkChars = stageData.spark.chars || stageData.spark.char_count || 0;
                        console.log('SPARK chars:', sparkChars);
                        updateStageStatus('spark', 'completed', 'Requirements complete', sparkChars);
                    }}
                    if (stageData.falcon) {{
                        const falconChars = stageData.falcon.chars || stageData.falcon.char_count || 0;
                        console.log('FALCON chars:', falconChars);
                        updateStageStatus('falcon', 'completed', 'Architecture complete', falconChars);
                    }}
                    if (stageData.eagle) {{
                        const eagleChars = stageData.eagle.chars || stageData.eagle.char_count || 0;
                        console.log('EAGLE chars:', eagleChars);
                        updateStageStatus('eagle', 'completed', 'Code complete', eagleChars);
                    }}
                    if (stageData.hawk) {{
                        const hawkChars = stageData.hawk.chars || stageData.hawk.char_count || 0;
                        console.log('HAWK chars:', hawkChars);
                        updateStageStatus('hawk', 'completed', 'QA complete', hawkChars);
                    }}
                    
                    // Calculate totals with proper fallback
                    const totalChars = Object.values(stageData).reduce((sum, stage) => {{
                        const chars = stage.chars || stage.char_count || 0;
                        return sum + chars;
                    }}, 0);
                    
                    const totalTime = Math.round((Date.now() - pipelineStartTime) / 1000);
                    
                    // Show final results
                    document.getElementById('totalChars').textContent = totalChars.toLocaleString();
                    document.getElementById('totalTime').textContent = totalTime + 's';
                    document.getElementById('filesGenerated').textContent = result.project_files?.length || '3';
                    
                    // Update log links
                    updateLogLinks(sessionTimestamp);
                    
                    finalSection.classList.add('show');
                    pipelineResults = result;
                    
                    // AUTO-OPEN XEDIT AFTER 2 SECONDS
                    setTimeout(() => {{
                        console.log('🎯 Auto-opening XEdit interface...');
                        openXEdit();
                    }}, 2000);
                    
                }} else {{
                    throw new Error(result.error || 'Pipeline failed');
                }}

            }} catch (error) {{
                console.error('🦚 Pipeline error:', error);
                alert('Pipeline failed: ' + error.message);
                
                // Mark current stage as failed
                stages.forEach(stage => {{
                    const statusEl = document.getElementById(stage + 'Status');
                    if (statusEl.textContent === 'ACTIVE') {{
                        updateStageStatus(stage, 'waiting', 'Failed: ' + error.message);
                    }}
                }});
                
            }} finally {{
                // Re-enable input
                promptInput.disabled = false;
                sendBtn.disabled = false;
                sendBtn.textContent = 'Start Pipeline';
            }}
        }}

        // Enable Enter key to start pipeline
        document.getElementById('promptInput').addEventListener('keypress', function(e) {{
            if (e.key === 'Enter') {{
                startPipeline();
            }}
        }});

        // Initialize log links on page load
        document.addEventListener('DOMContentLoaded', function() {{
            updateLogLinks(sessionTimestamp);
            console.log('🦚 Peacock Dashboard Loaded');
            console.log('📅 Session:', sessionTimestamp);
        }});
    </script>
</body>
</html>"""
    
    output_path = HTML_OUTPUT_DIR / f"1prompt-dashboard-{session_timestamp}.html"
    HTML_OUTPUT_DIR.mkdir(exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return output_path

def main():
   """Generate advanced dashboard with full bird progress and SICK ASCII art"""
   print("🦚 ADVANCED 1PROMPT - FULL BIRD PIPELINE DASHBOARD")
   print("="*60)
   
   session_timestamp = get_session_timestamp()
   
   # Generate advanced dashboard
   dashboard_file = generate_advanced_dashboard(session_timestamp)
   
   # Save the dashboard
   html_dir = Path("/home/flintx/peacock/html")
   html_dir.mkdir(exist_ok=True)
   
   file_path = html_dir / f"1prompt-dashboard-{session_timestamp}.html"
   
   # Create the decorative chess piece border
   chess_border = "♞▀▄▀▄♝▀▄ ♞▀▄▀▄♝▀▄‍‌♞▀▄▀▄♝▀▄ ♞▀▄▀▄♝▀▄‍‌♞▀▄▀▄♝▀▄ ♞▀▄▀▄♝▀▄​‍‌"
   
   # Print the formatted output with random cfonts command
   print("\n" + chess_border)
   
   # Run a random cfonts command
   try:
       banner_cmd = random.choice([
           "cfonts 'PEACOCK' -f pallet -t yellow,red",
           "cfonts 'PEACOCK' -f slick -t green,cyan",
           "cfonts 'PEACOCK' -f shade -t red,magenta",
           "cfonts 'PEACOCK' -f simple3d -t cyan,magenta",
           "cfonts 'PEACOCK' -f simple -t blue,magenta",
           "cfonts 'PEACOCK' -f grid -g red,blue",
           "cfonts 'PEACOCK' -f slick -g yellow,red",
           "cfonts 'PEACOCK' -f shade -g green,cyan",
           "cfonts 'PEACOCK' -f chrome -g green,cyan",
           "cfonts 'PEACOCK' -f simple -g green,cyan",
           "cfonts 'PEACOCK' -f block -g red,yellow",
           "cfonts 'PEACOCK' -f pallet -c cyan",
           "cfonts 'PEACOCK' -f slick -c blueBright",
           "cfonts 'PEACOCK' -f simple -c yellowBright",
           "cfonts 'PEACOCK' -f simple -c blue",
           "cfonts 'PEACOCK' -f simple -c green",
           "cfonts 'PEACOCK' -f block -c whiteBright",
           "cfonts 'PEACOCK' -f block -c blue"
       ])
       subprocess.run(banner_cmd, shell=True, check=True)
   except Exception:
       print("🦚 PEACOCK PIPELINE 🦚")
   
   print(chess_border + "\n")
   print(f" Session: {session_timestamp} (Military Time)")
   print(f" URL: file://{file_path}")
   
   # Open in browser
   webbrowser.open(f"file://{dashboard_file.absolute()}")
   
   print(f"\n🦚 ADVANCED DASHBOARD READY!")
   print(f"   Shows: SPARK, FALCON, EAGLE, HAWK progress")
   print(f"   Models: scout-17b, maverick-128e assignments")
   print(f"   Session: {session_timestamp}")
   
   return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n🛑 Stopped")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
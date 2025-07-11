#!/usr/bin/env python3
"""
1prompt.py - v2.0 - PEACOCK LIVE DASHBOARD
Shows real-time progress for the full 4-Bird + 3-Synthesis-Stage Pipeline.
"""

import datetime
import webbrowser
import sys
from pathlib import Path
import random
import subprocess
import json
import os

# --- CONFIGURATION ---
HTML_OUTPUT_DIR = Path("/home/flintx/peacock/html")
LOGS_DIR = Path("/home/flintx/peacock/logs")

def get_session_timestamp():
    """Generate session timestamp"""
    now = datetime.datetime.now()
    return f"w{now.strftime('%U')}-d{now.strftime('%d')}-{now.strftime('%H%M%S')}"

def generate_live_dashboard(session_timestamp):
    """Generates the advanced live dashboard with all pipeline stages."""
    
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🦚 Peacock Live Pipeline Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'SF Mono', monospace; background: #0d1117; color: #e6edf3; padding: 20px; }}
        .header {{ background: #161b22; border-bottom: 1px solid #30363d; padding: 16px 24px; margin: -20px -20px 20px -20px; position: sticky; top: 0; z-index: 100; }}
        .header-content {{ max-width: 1400px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; }}
        .logo {{ font-size: 20px; font-weight: bold; color: #ff6b35; }}
        .session-info {{ background: rgba(0, 255, 136, 0.1); border: 1px solid #00ff88; border-radius: 6px; padding: 6px 12px; font-size: 12px; color: #00ff88; }}
        .main-container {{ max-width: 1400px; margin: 0 auto; display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }}
        .input-section, .pipeline-section {{ background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 24px; }}
        .input-title, .pipeline-title {{ color: #ff6b35; font-size: 18px; font-weight: 600; margin-bottom: 16px; }}
        .prompt-container {{ display: flex; gap: 12px; margin-bottom: 16px; }}
        .prompt-input {{ flex: 1; padding: 12px 16px; background: #0d1117; border: 2px solid #30363d; border-radius: 8px; color: #e6edf3; font-size: 16px; font-family: inherit; }}
        .prompt-input:focus {{ outline: none; border-color: #ff6b35; }}
        .send-btn {{ padding: 12px 24px; background: linear-gradient(45deg, #ff6b35, #ff8c5a); border: none; border-radius: 8px; color: white; font-weight: 600; cursor: pointer; transition: all 0.2s; }}
        .send-btn:hover {{ transform: translateY(-2px); box-shadow: 0 4px 12px rgba(255, 107, 53, 0.3); }}
        .send-btn:disabled {{ background: #30363d; color: #8b949e; cursor: not-allowed; transform: none; }}
        .stage-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
        .stage-card {{ background: #0d1117; border: 2px solid #30363d; border-radius: 8px; padding: 20px; transition: all 0.3s; }}
        .stage-card.active {{ border-color: #ff6b35; box-shadow: 0 0 20px rgba(255, 107, 53, 0.2); }}
        .stage-card.completed {{ border-color: #238636; background: rgba(35, 134, 54, 0.05); }}
        .stage-header {{ display: flex; align-items: center; gap: 8px; margin-bottom: 12px; }}
        .stage-icon {{ font-size: 20px; }}
        .stage-name {{ font-weight: 600; font-size: 14px; }}
        .stage-status {{ font-size: 10px; padding: 2px 6px; border-radius: 4px; margin-left: auto; }}
        .stage-status.waiting {{ background: #30363d; color: #8b949e; }}
        .stage-status.active {{ background: rgba(255, 107, 53, 0.2); color: #ff6b35; }}
        .stage-status.completed {{ background: rgba(35, 134, 54, 0.2); color: #238636; }}
        .stage-model {{ font-size: 10px; color: #8b949e; margin-bottom: 8px; }}
        .stage-progress, .stage-chars {{ font-size: 12px; color: #e6edf3; }}
        .final-section {{ grid-column: 1 / -1; background: #0d1117; border: 2px solid #30363d; border-radius: 8px; padding: 20px; text-align: center; display: none; }}
        .final-section.show {{ display: block; border-color: #238636; }}
        .final-title {{ color: #238636; font-size: 16px; font-weight: 600; margin-bottom: 12px; }}
        .final-stats {{ display: flex; justify-content: center; gap: 24px; margin-bottom: 16px; }}
        .final-stat-value {{ font-size: 20px; font-weight: 600; color: #ff6b35; }}
        .final-stat-label {{ font-size: 10px; color: #8b949e; text-transform: uppercase; }}
        .xedit-btn {{ padding: 12px 24px; background: linear-gradient(45deg, #238636, #2ea043); border: none; border-radius: 8px; color: white; font-weight: 600; cursor: pointer; font-size: 14px; }}
        .log-links {{ display: flex; gap: 8px; justify-content: center; margin-top: 16px; flex-wrap: wrap; }}
        .log-link {{ padding: 6px 12px; background: #30363d; border: 1px solid #484f58; border-radius: 6px; color: #e6edf3; text-decoration: none; font-size: 10px; transition: all 0.2s; }}
        .log-link:hover {{ border-color: #ff6b35; color: #ff6b35; }}
    </style>
</head>
<body>
    <div class="header"><div class="header-content">
        <div class="logo">🦚 Peacock Live Pipeline Dashboard</div>
        <div class="session-info" id="sessionInfo">Session: {session_timestamp}</div>
    </div></div>
    <div class="main-container">
        <div class="input-section">
            <div class="input-title">🎯 Project Request</div>
            <div class="prompt-container">
                <input type="text" class="prompt-input" id="promptInput" placeholder="Describe your project in detail..." />
                <button class="send-btn" id="sendBtn" onclick="startPipeline()">Start Pipeline</button>
            </div>
            <div style="font-size: 12px; color: #8b949e; margin-top: 12px;">
                <strong>🦚 Full Pipeline:</strong><br>
                Intel (4 Birds) → Synthesis (2 Calls) → Code Gen (1 Call)
            </div>
        </div>
        <div class="pipeline-section">
            <div class="pipeline-title">📊 Live Pipeline Progress</div>
            <div class="stage-grid">
                <!-- Bird Stages -->
                <div class="stage-card" id="sparkCard"><div class="stage-header"><div class="stage-icon">⚡</div><div class="stage-name">SPARK</div><div class="stage-status waiting" id="sparkStatus">WAITING</div></div><div class="stage-model">Analysis Model</div><div class="stage-progress">Requirements</div></div>
                <div class="stage-card" id="falconCard"><div class="stage-header"><div class="stage-icon">🦅</div><div class="stage-name">FALCON</div><div class="stage-status waiting" id="falconStatus">WAITING</div></div><div class="stage-model">Analysis Model</div><div class="stage-progress">Architecture</div></div>
                <div class="stage-card" id="eagleCard"><div class="stage-header"><div class="stage-icon">🦅</div><div class="stage-name">EAGLE</div><div class="stage-status waiting" id="eagleStatus">WAITING</div></div><div class="stage-model">Analysis Model</div><div class="stage-progress">Implementation Plan</div></div>
                <div class="stage-card" id="hawkCard"><div class="stage-header"><div class="stage-icon">🦅</div><div class="stage-name">HAWK</div><div class="stage-status waiting" id="hawkStatus">WAITING</div></div><div class="stage-model">Analysis Model</div><div class="stage-progress">QA Plan</div></div>
            </div>

            <!-- Synthesis & Codegen Sections -->
            <div class="pipeline-title" style="margin-top: 24px; font-size: 14px;">🤖 Synthesis & Code Generation</div>
            <div class="stage-grid">
                <div class="stage-card" id="synth1Card"><div class="stage-header"><div class="stage-icon">✍️</div><div class="stage-name">SYNTHESIS 1</div><div class="stage-status waiting" id="synth1Status">WAITING</div></div><div class="stage-model">deepseek-r1-distill-llama-70b</div><div class="stage-progress">Project Blueprint</div></div>
                <div class="stage-card" id="synth2Card"><div class="stage-header"><div class="stage-icon">📋</div><div class="stage-name">SYNTHESIS 2</div><div class="stage-status waiting" id="synth2Status">WAITING</div></div><div class="stage-model">deepseek-r1-distill-llama-70b</div><div class="stage-progress">Build & Test Plan</div></div>
                <div class="stage-card" id="codegenCard" style="grid-column: 1 / -1;"><div class="stage-header"><div class="stage-icon">💻</div><div class="stage-name">FINAL CODE GENERATION</div><div class="stage-status waiting" id="codegenStatus">WAITING</div></div><div class="stage-model">qwen/qwen3-32b</div><div class="stage-progress">Generating final code...</div></div>
            </div>
            
            <div class="final-section" id="finalSection">
                <div class="final-title">🎉 Pipeline Complete!</div>
                <div class="final-stats">
                    <div class="final-stat"><div class="final-stat-value" id="totalTime">0s</div><div class="final-stat-label">Total Time</div></div>
                    <div class="final-stat"><div class="final-stat-value" id="filesGenerated">0</div><div class="final-stat-label">Files Generated</div></div>
                </div>
                <button class="xedit-btn" id="xeditBtn" onclick="openXEdit()">🎯 Open XEdit Interface</button>
                <div class="log-links" id="logLinksContainer"></div>
            </div>
        </div>
    </div>
    <script>
        let pipelineResults = null;
        let currentSessionId = '{session_timestamp}';

        function updateStageStatus(stageId, status, message = '') {{
            const card = document.getElementById(stageId + 'Card');
            const statusEl = document.getElementById(stageId + 'Status');
            if (card && statusEl) {{
                statusEl.className = 'stage-status ' + status;
                statusEl.textContent = status.toUpperCase();
                card.className = 'stage-card';
                if (status === 'active') card.classList.add('active');
                else if (status === 'completed') card.classList.add('completed');
            }}
        }}

        function populateLogLinks(sessionId) {{
            const container = document.getElementById('logLinksContainer');
            container.innerHTML = '';
            const logFiles = [
                '00_user_prompt.txt', '01_spark_prompt.txt', '02_spark_response.json',
                '03_falcon_prompt.txt', '04_falcon_response.json', '05_eagle_prompt.txt',
                '06_eagle_response.json', '07_hawk_prompt.txt', '08_hawk_response.json',
                '09_synth1_blueprint_prompt.txt', '10_synth1_blueprint_response.json',
                '11_synth2_buildplan_prompt.txt', '12_synth2_buildplan_response.json',
                '13_codegen_prompt.txt', '14_codegen_response.json'
            ];
            logFiles.forEach(file => {{
                const link = document.createElement('a');
                link.href = `file:///home/flintx/peacock/logs/${{sessionId}}/${{file}}`;
                link.className = 'log-link';
                link.textContent = file.split('_').slice(1).join('_').replace('.txt','').replace('.json','');
                link.target = '_blank';
                container.appendChild(link);
            }});
        }}

        function openXEdit() {{
            if (pipelineResults && pipelineResults.xedit_file_path) {{
                window.open(`file://${{pipelineResults.xedit_file_path}}`, '_blank');
            }} else {{
                alert('XEdit file path not available. The pipeline may have failed.');
            }}
        }}

        async function startPipeline() {{
            const promptInput = document.getElementById('promptInput');
            const sendBtn = document.getElementById('sendBtn');
            const prompt = promptInput.value.trim();
            if (!prompt) {{ alert('Please describe your project'); return; }}

            // Reset UI
            document.getElementById('finalSection').classList.remove('show');
            ['spark', 'falcon', 'eagle', 'hawk', 'synth1', 'synth2', 'codegen'].forEach(id => updateStageStatus(id, 'waiting'));
            
            promptInput.disabled = true;
            sendBtn.disabled = true;
            sendBtn.textContent = 'Running...';
            const pipelineStartTime = Date.now();

            try {{
                // This simulates the MCP server handling the session ID
                updateStageStatus('spark', 'active');
                const response = await fetch('http://localhost:8000/process', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ command: 'peacock_full', text: prompt }})
                }});

                if (!response.ok) throw new Error(`HTTP ${{response.status}}: ${{response.statusText}}`);
                const result = await response.json();
                pipelineResults = result;

                if (result.success) {{
                    // Update all stages to completed
                    ['spark', 'falcon', 'eagle', 'hawk', 'synth1', 'synth2', 'codegen'].forEach(id => updateStageStatus(id, 'completed'));
                    
                    const totalTime = Math.round((Date.now() - pipelineStartTime) / 1000);
                    document.getElementById('totalTime').textContent = totalTime + 's';
                    document.getElementById('filesGenerated').textContent = result.project_files?.length || 'N/A';
                    
                    currentSessionId = result.session_id;
                    document.getElementById('sessionInfo').textContent = `Session: ${{currentSessionId}}`;
                    populateLogLinks(currentSessionId);

                    document.getElementById('finalSection').classList.add('show');
                    
                    setTimeout(() => openXEdit(), 1500);
                }} else {{
                    throw new Error(result.error || 'Pipeline failed');
                }}
            }} catch (error) {{
                alert('Pipeline failed: ' + error.message);
                updateStageStatus('codegen', 'error'); // Mark the last stage as failed
            }} finally {{
                promptInput.disabled = false;
                sendBtn.disabled = false;
                sendBtn.textContent = 'Start Pipeline';
            }}
        }}
    </script>
</body>
</html>
    """
    output_path = HTML_OUTPUT_DIR / f"1prompt-dashboard-{session_timestamp}.html"
    HTML_OUTPUT_DIR.mkdir(exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    return output_path

def main():
    """Main server startup"""
    session_timestamp = get_session_timestamp()
    dashboard_file = generate_live_dashboard(session_timestamp)
    print("="*60)
    print("🦚 PEACOCK LIVE PIPELINE DASHBOARD (v2.0)")
    print("="*60)
    print(f"Session: {session_timestamp}")
    print(f"URL: file://{dashboard_file.absolute()}")
    webbrowser.open(f"file://{dashboard_file.absolute()}")
    print("\nDashboard is live. Waiting for MCP server to be started separately...")
    return 0

if __name__ == "__main__":
    sys.exit(main())

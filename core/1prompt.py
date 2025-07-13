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
        .stage-card {{ position: relative; overflow: hidden; background: #0d1117; border: 2px solid #30363d; border-radius: 8px; padding: 20px; transition: all 0.3s; }}
        .stage-card.active {{ border-color: #ff6b35; box-shadow: 0 0 20px rgba(255, 107, 53, 0.2); }}
        .stage-card.completed {{ border-color: #238636; background: rgba(35, 134, 54, 0.05); }}
        .stage-card.error {{ border-color: #da3633; background: rgba(218, 54, 51, 0.05); }}
        .stage-card .checkmark-overlay {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(35, 134, 54, 0.8);
            display: flex;
            justify-content: center;
            align-items: center;
            font-size: 4em;
            color: white;
            opacity: 0;
            transition: opacity 0.3s ease-in-out;
            pointer-events: none;
        }}
        .stage-card .checkmark-overlay.active {{
            opacity: 1;
        }}
        .stage-header {{ display: flex; align-items: center; gap: 8px; margin-bottom: 12px; }}
        .stage-icon {{ font-size: 20px; }}
        .stage-name {{ font-weight: 600; font-size: 14px; }}
        .stage-status {{ font-size: 10px; padding: 2px 6px; border-radius: 4px; margin-left: auto; }}
        .stage-status.waiting {{ background: #30363d; color: #8b949e; }}
        .stage-status.active {{ background: rgba(255, 107, 53, 0.2); color: #ff6b35; }}
        .stage-status.completed {{ background: rgba(35, 134, 54, 0.2); color: #238636; }}
        .stage-status.error {{ background: rgba(218, 54, 51, 0.2); color: #da3633; }}
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
                <div class="stage-card" id="sparkCard"><div class="stage-header"><div class="stage-icon">🕊️</div><div class="stage-name">SPARK</div><div class="stage-status waiting" id="sparkStatus">WAITING</div></div><div class="stage-model">meta-llama/llama-4-scout-17b-16e-instruct</div><div class="stage-progress">Requirements</div><div class="checkmark-overlay">&#10003;</div></div>
                <div class="stage-card" id="falconCard"><div class="stage-header"><div class="stage-icon">🏎️</div><div class="stage-name">FALCON</div><div class="stage-status waiting" id="falconStatus">WAITING</div></div><div class="stage-model">meta-llama/llama-4-scout-17b-16e-instruct</div><div class="stage-progress">Architecture</div><div class="checkmark-overlay">&#10003;</div></div>
                <div class="stage-card" id="eagleCard"><div class="stage-header"><div class="stage-icon">⚔️</div><div class="stage-name">EAGLE</div><div class="stage-status waiting" id="eagleStatus">WAITING</div></div><div class="stage-model">meta-llama/llama-4-maverick-17b-128e-instruct</div><div class="stage-progress">Implementation Plan</div><div class="checkmark-overlay">&#10003;</div></div>
                <div class="stage-card" id="hawkCard"><div class="stage-header"><div class="stage-icon">🏠</div><div class="stage-name">HAWK</div><div class="stage-status waiting" id="hawkStatus">WAITING</div></div><div class="stage-model">meta-llama/llama-4-maverick-17b-128e-instruct</div><div class="stage-progress">QA Plan</div><div class="checkmark-overlay">&#10003;</div></div>
            </div>

            <!-- Synthesis & Codegen Sections -->
            <div class="pipeline-title" style="margin-top: 24px; font-size: 14px;">🤖 Synthesis & Code Generation</div>
            <div class="stage-grid">
                <div class="stage-card" id="synth1Card"><div class="stage-header"><div class="stage-icon">🦉</div><div class="stage-name">SYNTHESIS 1</div><div class="stage-status waiting" id="synth1Status">WAITING</div></div><div class="stage-model">deepseek-r1-distill-llama-70b</div><div class="stage-progress">Project Blueprint</div><div class="checkmark-overlay">&#10003;</div></div>
                <div class="stage-card" id="synth2Card"><div class="stage-header"><div class="stage-icon">🦉</div><div class="stage-name">SYNTHESIS 2</div><div class="stage-status waiting" id="synth2Status">WAITING</div></div><div class="stage-model">deepseek-r1-distill-llama-70b</div><div class="stage-progress">Build & Test Plan</div><div class="checkmark-overlay">&#10003;</div></div>
                <div class="stage-card" id="codegenCard" style="grid-column: 1 / -1;"><div class="stage-header"><div class="stage-icon">🦚</div><div class="stage-name">FINAL CODE GENERATION</div><div class="stage-status waiting" id="codegenStatus">WAITING</div></div><div class="stage-model">qwen/qwen3-32b</div><div class="stage-progress">Generating final code...</div><div class="checkmark-overlay">&#10003;</div></div>
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
    <audio id="completionSound" src="https://www.soundjay.com/buttons/sounds/button-1.mp3" preload="auto"></audio>
    <script>
        let pipelineResults = null;
        let currentSessionId = '{session_timestamp}';
        let eventSource = null;
        let flashInterval = null;
        const stageOrder = ['spark', 'falcon', 'eagle', 'hawk', 'synth1', 'synth2', 'codegen'];
        let currentFlashIndex = 0;
        let flashDirection = 1;
        let flashCycleCount = 0;

        function updateStageStatus(stageId, status, message = '', charCount = null) {{
            const stageMap = {{
                'SYNTHESIS_1': 'synth1',
                'SYNTHESIS_2': 'synth2',
                'CODEGEN': 'codegen'
            }};
            
            const mappedStage = stageMap[stageId] || stageId.toLowerCase();
            const card = document.getElementById(mappedStage + 'Card');
            const statusEl = document.getElementById(mappedStage + 'Status');
            const progressEl = card ? card.querySelector('.stage-progress') : null;
            const checkmarkOverlay = card ? card.querySelector('.checkmark-overlay') : null;

            if (card && statusEl) {{
                statusEl.className = 'stage-status ' + status.toLowerCase();
                statusEl.textContent = status.toUpperCase();
                card.className = 'stage-card';
                if (status.toLowerCase() === 'active') {{
                    card.classList.add('active');
                }} else if (status.toLowerCase() === 'completed') {{
                    card.classList.add('completed');
                    if (checkmarkOverlay) {{
                        checkmarkOverlay.classList.add('active');
                    }}
                }} else if (status.toLowerCase() === 'error') {{
                    card.classList.add('error');
                }}

                if (progressEl && charCount !== null) {{
                    progressEl.textContent = `Chars: ${{charCount.toLocaleString()}}`;
                }} else if (progressEl && message) {{
                    progressEl.textContent = message;
                }}
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

        function startCelebrationFlashing() {{
            if (flashInterval) clearInterval(flashInterval);
            flashCycleCount = 0;
            currentFlashIndex = 0;
            flashDirection = 1;

            flashInterval = setInterval(() => {{
                const prevStageId = stageOrder[currentFlashIndex];
                const prevCard = document.getElementById(prevStageId + 'Card');
                if (prevCard) {{
                    const prevCheckmark = prevCard.querySelector('.checkmark-overlay');
                    if (prevCheckmark) prevCheckmark.classList.remove('active');
                }}

                currentFlashIndex += flashDirection;
                if (currentFlashIndex >= stageOrder.length || currentFlashIndex < 0) {{
                    flashDirection *= -1;
                    currentFlashIndex += flashDirection;
                    flashCycleCount++;
                    
                    if (flashCycleCount >= 25) {{
                        clearInterval(flashInterval);
                        flashInterval = null;
                        stageOrder.forEach(id => {{
                            const card = document.getElementById(id + 'Card');
                            if (card) {{
                                const checkmark = card.querySelector('.checkmark-overlay');
                                if (checkmark) checkmark.classList.add('active');
                            }}
                        }});
                        return;
                    }}
                }}

                const currentStageId = stageOrder[currentFlashIndex];
                const currentCard = document.getElementById(currentStageId + 'Card');
                if (currentCard) {{
                    const currentCheckmark = currentCard.querySelector('.checkmark-overlay');
                    if (currentCheckmark) currentCheckmark.classList.add('active');
                }}
            }}, 150);
        }}

        function stopFlashingAnimation() {{
            if (flashInterval) {{
                clearInterval(flashInterval);
                flashInterval = null;
                stageOrder.forEach(id => {{
                    const card = document.getElementById(id + 'Card');
                    if (card) {{
                        const checkmark = card.querySelector('.checkmark-overlay');
                        if (checkmark) checkmark.classList.remove('active');
                    }}
                }});
            }}
        }}

        async function startPipeline() {{
            const promptInput = document.getElementById('promptInput');
            const sendBtn = document.getElementById('sendBtn');
            const prompt = promptInput.value.trim();
            if (!prompt) {{
                alert('Please describe your project');
                return;
            }}

            document.getElementById('finalSection').classList.remove('show');
            ['spark', 'falcon', 'eagle', 'hawk', 'synth1', 'synth2', 'codegen'].forEach(id => updateStageStatus(id, 'waiting'));
            
            promptInput.disabled = true;
            sendBtn.disabled = true;
            sendBtn.textContent = 'Running...';
            const pipelineStartTime = Date.now();


            try {{
                const response = await fetch('http://localhost:8000/process', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ command: 'peacock_full', text: prompt, session: currentSessionId }})
                }});

                if (!response.ok) throw new Error(`HTTP ${{response.status}}: ${{response.statusText}}`);
                const result = await response.json();
                console.log("Pipeline initiation response:", result);

                if (!result.success) {{
                    throw new Error(result.error || 'Failed to initiate pipeline');
                }}

                eventSource = new EventSource('http://localhost:8000/stream');

                eventSource.onmessage = function(event) {{
                    const data = JSON.parse(event.data);
                    console.log("SSE Message:", data);

                    switch (data.stage) {{
                        case 'SPARK':
                        case 'FALCON':
                        case 'EAGLE':
                        case 'HAWK':
                        case 'SYNTHESIS_1':
                        case 'SYNTHESIS_2':
                        case 'CODEGEN':
                            updateStageStatus(data.stage, data.status, '', data.char_count);
                            break;
                        case 'PIPELINE':
                            if (data.status === 'COMPLETED') {{
                                pipelineResults = data.result;
                                console.log('Pipeline Results:', pipelineResults);
                                const completionSound = document.getElementById('completionSound');
                                if (completionSound) {{
                                    completionSound.play();
                                }}
                                eventSource.close();
                                const totalTime = Math.round((Date.now() - pipelineStartTime) / 1000);
                                document.getElementById('totalTime').textContent = totalTime + 's';
                                document.getElementById('filesGenerated').textContent = pipelineResults.project_files ? pipelineResults.project_files.length : 'N/A';
                                populateLogLinks(currentSessionId);
                                document.getElementById('finalSection').classList.add('show');
                                startCelebrationFlashing();
                                setTimeout(() => openXEdit(), 8000);
                            }} else if (data.status === 'FAILED') {{
                                eventSource.close();
                                alert('Pipeline failed: ' + (data.error || 'Unknown error'));
                                updateStageStatus('codegen', 'error');
                            }}
                            break;
                        default:
                            console.log('Unknown stage:', data.stage);
                    }}
                }};

                eventSource.onerror = function(err) {{
                    console.error('EventSource failed:', err);
                    eventSource.close();
                    alert('Live update connection failed. Check server status.');
                    updateStageStatus('codegen', 'error');
                    promptInput.disabled = false;
                    sendBtn.disabled = false;
                    sendBtn.textContent = 'Start Pipeline';
                }};

            }} catch (error) {{
                alert('Pipeline initiation failed: ' + error.message);
                updateStageStatus('codegen', 'error');
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
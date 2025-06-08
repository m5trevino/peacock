#!/usr/bin/env python3
"""
enhanced_dashboard.py - Live Pipeline Dashboard Generator
"""

import json
import subprocess
import requests
import datetime
from pathlib import Path

def get_session_timestamp():
    """Get session timestamp matching peamcp.py format"""
    now = datetime.datetime.now()
    week = now.isocalendar()[1]
    day = now.day
    hour = now.hour
    minute = now.minute
    return f"{week}-{day}-{hour}{minute:02d}"

def generate_enhanced_dashboard():
    """Generate enhanced dashboard with live pipeline visualization"""
    
    session_timestamp = get_session_timestamp()
    
    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🦚 Peacock Live Pipeline Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'SF Mono', monospace; background: #0d1117; color: #e6edf3; overflow-x: hidden; }}
        
        .header {{ background: #161b22; border-bottom: 1px solid #30363d; padding: 16px 24px; position: sticky; top: 0; z-index: 100; }}
        .header-content {{ max-width: 1400px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; }}
        .logo {{ font-size: 20px; font-weight: bold; color: #ff6b35; }}
        .session-info {{ background: rgba(0, 255, 136, 0.1); border: 1px solid #00ff88; border-radius: 6px; padding: 6px 12px; font-size: 12px; color: #00ff88; }}
        
        .main-container {{ max-width: 1400px; margin: 0 auto; padding: 24px; }}
        
        .input-section {{ background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 24px; margin-bottom: 24px; }}
        .input-title {{ color: #ff6b35; font-size: 18px; font-weight: 600; margin-bottom: 16px; }}
        .prompt-container {{ display: flex; gap: 12px; margin-bottom: 16px; }}
        .prompt-input {{ flex: 1; padding: 12px 16px; background: #0d1117; border: 2px solid #30363d; border-radius: 8px; color: #e6edf3; font-size: 16px; font-family: inherit; }}
        .prompt-input:focus {{ outline: none; border-color: #ff6b35; }}
        .send-btn {{ padding: 12px 24px; background: linear-gradient(45deg, #ff6b35, #ff8c5a); border: none; border-radius: 8px; color: white; font-weight: 600; cursor: pointer; transition: all 0.2s; }}
        .send-btn:hover {{ transform: translateY(-2px); box-shadow: 0 4px 12px rgba(255, 107, 53, 0.3); }}
        .send-btn:disabled {{ background: #30363d; color: #8b949e; cursor: not-allowed; transform: none; }}
        
        .pipeline-container {{ background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 24px; margin-bottom: 24px; }}
        .pipeline-title {{ color: #ff6b35; font-size: 18px; font-weight: 600; margin-bottom: 20px; text-align: center; }}
        
        .stage-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; margin-bottom: 24px; }}
        .stage-card {{ background: #0d1117; border: 2px solid #30363d; border-radius: 8px; padding: 20px; transition: all 0.3s; }}
        .stage-card.active {{ border-color: #ff6b35; box-shadow: 0 0 20px rgba(255, 107, 53, 0.2); }}
        .stage-card.completed {{ border-color: #238636; background: rgba(35, 134, 54, 0.1); }}
        .stage-card.failed {{ border-color: #da3633; background: rgba(218, 54, 51, 0.1); }}
        
        .stage-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }}
        .stage-name {{ font-size: 16px; font-weight: 600; color: #e6edf3; }}
        .stage-icon {{ font-size: 24px; }}
        .stage-model {{ color: #8b949e; font-size: 12px; margin-bottom: 8px; }}
        .stage-status {{ font-size: 14px; }}
        .stage-details {{ margin-top: 12px; font-size: 12px; color: #8b949e; }}
        
        .status-waiting {{ color: #8b949e; }}
        .status-starting {{ color: #ff6b35; }}
        .status-processing {{ color: #ffc107; }}
        .status-completed {{ color: #238636; }}
        .status-failed {{ color: #da3633; }}
        
        .progress-bar {{ width: 100%; height: 4px; background: #30363d; border-radius: 2px; margin-top: 8px; overflow: hidden; }}
        .progress-fill {{ height: 100%; background: linear-gradient(90deg, #ff6b35, #238636); width: 0%; transition: width 0.5s ease; }}
        
        .results-section {{ background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 24px; margin-bottom: 24px; display: none; }}
        .results-section.show {{ display: block; }}
        .results-title {{ color: #238636; font-size: 18px; font-weight: 600; margin-bottom: 16px; }}
        
        .completion-status {{ display: flex; align-items: center; gap: 12px; margin-bottom: 20px; padding: 16px; background: rgba(35, 134, 54, 0.1); border: 1px solid #238636; border-radius: 8px; }}
        .completion-icon {{ font-size: 24px; color: #238636; }}
        .completion-text {{ color: #238636; font-weight: 600; }}
        
        .log-links {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 20px; }}
        .log-link {{ background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 12px; text-align: center; cursor: pointer; transition: all 0.2s; text-decoration: none; color: #e6edf3; }}
        .log-link:hover {{ border-color: #ff6b35; transform: translateY(-2px); }}
        .log-link-title {{ font-size: 12px; color: #8b949e; }}
        .log-link-name {{ font-size: 14px; font-weight: 600; }}
        
        .action-buttons {{ display: flex; gap: 12px; justify-content: center; }}
        .action-btn {{ padding: 14px 28px; border: none; border-radius: 8px; font-weight: 600; cursor: pointer; transition: all 0.2s; }}
        .xedit-btn {{ background: linear-gradient(45deg, #238636, #2ea043); color: white; }}
        .xedit-btn:hover {{ transform: translateY(-2px); box-shadow: 0 4px 12px rgba(35, 134, 54, 0.3); }}
        .download-btn {{ background: linear-gradient(45deg, #0969da, #1f6feb); color: white; }}
        .download-btn:hover {{ transform: translateY(-2px); box-shadow: 0 4px 12px rgba(9, 105, 218, 0.3); }}
        
        @keyframes pulse {{
            0% {{ transform: scale(1); }}
            50% {{ transform: scale(1.05); }}
            100% {{ transform: scale(1); }}
        }}
        
        .processing {{ animation: pulse 2s infinite; }}
        
        .error-message {{ background: rgba(218, 54, 51, 0.1); border: 1px solid #da3633; border-radius: 8px; padding: 16px; color: #da3633; margin-top: 12px; }}
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
            <div class="input-title">💬 One-Prompt Builder</div>
            <div class="prompt-container">
                <input type="text" class="prompt-input" id="promptInput" placeholder="Build a snake game..." />
                <button class="send-btn" id="sendBtn" onclick="startPipeline()">🚀 Build Project</button>
            </div>
        </div>

        <div class="pipeline-container">
            <div class="pipeline-title">🦚 Live Pipeline Progress</div>
            
            <div class="stage-grid">
                <div class="stage-card" id="sparkStage">
                    <div class="stage-header">
                        <div class="stage-name">SPARK</div>
                        <div class="stage-icon">⚡</div>
                    </div>
                    <div class="stage-model">Model: gemma2-9b-it</div>
                    <div class="stage-status status-waiting" id="sparkStatus">Requirements Analysis</div>
                    <div class="progress-bar"><div class="progress-fill" id="sparkProgress"></div></div>
                    <div class="stage-details" id="sparkDetails">Waiting to start...</div>
                </div>

                <div class="stage-card" id="falconStage">
                    <div class="stage-header">
                        <div class="stage-name">FALCON</div>
                        <div class="stage-icon">🦅</div>
                    </div>
                    <div class="stage-model">Model: gemma2-9b-it</div>
                    <div class="stage-status status-waiting" id="falconStatus">Architecture Design</div>
                    <div class="progress-bar"><div class="progress-fill" id="falconProgress"></div></div>
                    <div class="stage-details" id="falconDetails">Waiting to start...</div>
                </div>

                <div class="stage-card" id="eagleStage">
                    <div class="stage-header">
                        <div class="stage-name">EAGLE</div>
                        <div class="stage-icon">🦅</div>
                    </div>
                    <div class="stage-model">Model: llama3-8b-8192</div>
                    <div class="stage-status status-waiting" id="eagleStatus">Code Implementation</div>
                    <div class="progress-bar"><div class="progress-fill" id="eagleProgress"></div></div>
                    <div class="stage-details" id="eagleDetails">Waiting to start...</div>
                </div>

                <div class="stage-card" id="hawkStage">
                    <div class="stage-header">
                        <div class="stage-name">HAWK</div>
                        <div class="stage-icon">🦅</div>
                    </div>
                    <div class="stage-model">Model: gemma2-9b-it</div>
                    <div class="stage-status status-waiting" id="hawkStatus">Quality Assurance</div>
                    <div class="progress-bar"><div class="progress-fill" id="hawkProgress"></div></div>
                    <div class="stage-details" id="hawkDetails">Waiting to start...</div>
                </div>
            </div>
        </div>

        <div class="results-section" id="resultsSection">
            <div class="results-title">🎉 Pipeline Completed Successfully!</div>
            
            <div class="completion-status">
                <div class="completion-icon">✅</div>
                <div class="completion-text">Project generated and ready for review</div>
            </div>

            <div class="log-links">
                <a href="#" class="log-link" id="promptLogLink">
                    <div class="log-link-title">📝 Prompt Log</div>
                    <div class="log-link-name">promptlog-{session_timestamp}.txt</div>
                </a>
                <a href="#" class="log-link" id="responseLogLink">
                    <div class="log-link-title">📋 Response Log</div>
                    <div class="log-link-name">response-{session_timestamp}.txt</div>
                </a>
                <a href="#" class="log-link" id="mcpLogLink">
                    <div class="log-link-title">🔧 MCP Log</div>
                    <div class="log-link-name">mcplog-{session_timestamp}.txt</div>
                </a>
            </div>

            <div class="action-buttons">
                <button class="action-btn xedit-btn" onclick="sendToXEdit()">
                    🎯 Send to XEdit Interface
                </button>
                <button class="action-btn download-btn" onclick="downloadProject()">
                    📦 Download Complete Project
                </button>
            </div>
        </div>
    </div>

    <script>
        const sessionTimestamp = '{session_timestamp}';
        let pipelineResults = null;
        let currentStage = 0;
        const stages = ['spark', 'falcon', 'eagle', 'hawk'];
        
        // Log file paths
        const logPaths = {{
            prompt: `/home/flintx/peacock/logs/promptlog-${{sessionTimestamp}}.txt`,
            response: `/home/flintx/peacock/logs/response-${{sessionTimestamp}}.txt`,
            mcp: `/home/flintx/peacock/logs/mcplog-${{sessionTimestamp}}.txt`
        }};

        function updateStageStatus(stageName, status, details = '', progress = 0) {{
            const stage = document.getElementById(`${{stageName}}Stage`);
            const statusEl = document.getElementById(`${{stageName}}Status`);
            const detailsEl = document.getElementById(`${{stageName}}Details`);
            const progressEl = document.getElementById(`${{stageName}}Progress`);

            // Update stage card appearance
            stage.className = 'stage-card';
            if (status === 'starting' || status === 'processing') {{
                stage.classList.add('active', 'processing');
            }} else if (status === 'completed') {{
                stage.classList.add('completed');
                stage.classList.remove('processing');
            }} else if (status === 'failed') {{
                stage.classList.add('failed');
                stage.classList.remove('processing');
            }}

            // Update status text and class
            statusEl.className = `stage-status status-${{status}}`;
            if (status === 'starting') {{
                statusEl.textContent = 'Starting...';
            }} else if (status === 'processing') {{
                statusEl.textContent = 'Processing...';
            }} else if (status === 'completed') {{
                statusEl.textContent = 'Completed ✓';
            }} else if (status === 'failed') {{
                statusEl.textContent = 'Failed ✗';
            }}

            // Update details
            detailsEl.textContent = details;

            // Update progress bar
            progressEl.style.width = `${{progress}}%`;
        }}

        async function startPipeline() {{
            const promptInput = document.getElementById('promptInput');
            const sendBtn = document.getElementById('sendBtn');
            const prompt = promptInput.value.trim();
            
            if (!prompt) {{
                alert('Please enter a project description');
                return;
            }}

            // Disable input and button
            promptInput.disabled = true;
            sendBtn.disabled = true;
            sendBtn.textContent = '🔄 Building...';

            // Reset all stages
            stages.forEach(stage => {{
                updateStageStatus(stage, 'waiting', 'Waiting to start...', 0);
            }});

            // Hide results section
            document.getElementById('resultsSection').classList.remove('show');

            try {{
                // Simulate pipeline stages with real API call
                updateStageStatus('spark', 'starting', 'Initializing requirements analysis...', 25);
                
                const response = await fetch('http://127.0.0.1:8000/process', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{
                        command: 'peacock_full',
                        text: prompt
                    }})
                }});

                if (!response.ok) {{
                    throw new Error(`HTTP ${{response.status}}: ${{response.statusText}}`);
                }}

                // Start monitoring pipeline progress
                monitorPipelineProgress();

                const result = await response.json();
                
                if (result.success) {{
                    // Mark all stages as completed
                    stages.forEach(stage => {{
                        updateStageStatus(stage, 'completed', 'Stage completed successfully', 100);
                    }});

                    pipelineResults = result;
                    showResults();
                }} else {{
                    throw new Error(result.error || 'Pipeline failed');
                }}

            }} catch (error) {{
                console.error('Pipeline error:', error);
                updateStageStatus(stages[currentStage] || 'spark', 'failed', `Error: ${{error.message}}`, 0);
                
                // Show error in current stage
                const errorDiv = document.createElement('div');
                errorDiv.className = 'error-message';
                errorDiv.textContent = `Pipeline failed: ${{error.message}}`;
                document.getElementById(`${{stages[currentStage] || 'spark'}}Stage`).appendChild(errorDiv);
            }} finally {{
                // Re-enable input
                promptInput.disabled = false;
                sendBtn.disabled = false;
                sendBtn.textContent = '🚀 Build Project';
            }}
        }}

        function monitorPipelineProgress() {{
            // Simulate realistic pipeline timing
            setTimeout(() => updateStageStatus('spark', 'processing', 'Analyzing project requirements...', 50), 500);
            setTimeout(() => updateStageStatus('spark', 'completed', 'Requirements analysis complete', 100), 2000);
            
            setTimeout(() => updateStageStatus('falcon', 'starting', 'Starting architecture design...', 25), 2500);
            setTimeout(() => updateStageStatus('falcon', 'processing', 'Designing system architecture...', 50), 3000);
            setTimeout(() => updateStageStatus('falcon', 'completed', 'Architecture design complete', 100), 5000);
            
            setTimeout(() => updateStageStatus('eagle', 'starting', 'Starting code implementation...', 25), 5500);
            setTimeout(() => updateStageStatus('eagle', 'processing', 'Generating application code...', 50), 6000);
            setTimeout(() => updateStageStatus('eagle', 'completed', 'Code implementation complete', 100), 8000);
            
            setTimeout(() => updateStageStatus('hawk', 'starting', 'Starting quality assurance...', 25), 8500);
            setTimeout(() => updateStageStatus('hawk', 'processing', 'Running quality checks...', 50), 9000);
            setTimeout(() => updateStageStatus('hawk', 'completed', 'Quality assurance complete', 100), 11000);
        }}

        function showResults() {{
            document.getElementById('resultsSection').classList.add('show');
            
            // Set up log file links
            document.getElementById('promptLogLink').href = `file://${{logPaths.prompt}}`;
            document.getElementById('responseLogLink').href = `file://${{logPaths.response}}`;
            document.getElementById('mcpLogLink').href = `file://${{logPaths.mcp}}`;
        }}

        function sendToXEdit() {{
            if (!pipelineResults) {{
                alert('No pipeline results available');
                return;
            }}

            // Extract EAGLE implementation
            const eagleResults = pipelineResults.pipeline_results?.eagle?.text;
            if (!eagleResults) {{
                alert('No implementation code found');
                return;
            }}

            // Generate new XEdit interface with the actual code
            const projectName = document.getElementById('promptInput').value || 'Generated Project';
            
            // Call a backend endpoint to generate XEdit with the actual code
            fetch('http://127.0.0.1:8000/process', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{
                    command: 'generate_xedit',
                    code_content: eagleResults,
                    project_name: projectName,
                    session: sessionTimestamp
                }})
            }})
            .then(response => response.json())
            .then(data => {{
                if (data.success) {{
                    // Open XEdit in new tab
                    const xeditUrl = `file:///home/flintx/peacock/html/xedit-${{sessionTimestamp}}.html`;
                    window.open(xeditUrl, '_blank');
                    alert('✅ XEdit interface updated with generated code!');
                }} else {{
                    alert(`❌ Failed to update XEdit: ${{data.error}}`);
                }}
            }})
            .catch(error => {{
                alert(`❌ Error updating XEdit: ${{error.message}}`);
            }});
        }}

        function downloadProject() {{
            if (!pipelineResults) {{
                alert('No pipeline results available');
                return;
            }}

            const projectData = {{
                timestamp: new Date().toISOString(),
                session: sessionTimestamp,
                prompt: document.getElementById('promptInput').value,
                results: pipelineResults
            }};

            const blob = new Blob([JSON.stringify(projectData, null, 2)], {{
                type: 'application/json'
            }});

            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `peacock_project_${{sessionTimestamp}}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            alert('📦 Project downloaded successfully!');
        }}

        // Enable Enter key to start pipeline
        document.getElementById('promptInput').addEventListener('keypress', function(e) {{
            if (e.key === 'Enter') {{
                startPipeline();
            }}
        }});
    </script>
</body>
</html>'''
    
    return html_content

if __name__ == "__main__":
    html_output = generate_enhanced_dashboard()
    session_timestamp = get_session_timestamp()
    
    # Save to html directory with session timestamp
    html_dir = Path("/home/flintx/peacock/html")
    html_dir.mkdir(exist_ok=True)
    output_path = html_dir / f"enhanced-dashboard-{session_timestamp}.html"
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_output)
    
    print(f"✅ Enhanced Dashboard generated: {output_path}")
    print(f"🔥 Session: {session_timestamp}")
    print(f"🚀 Features: Live pipeline, visual progress, XEdit integration")

import webbrowser
webbrowser.open(f"file://{output_path.absolute()}")
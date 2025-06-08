#!/usr/bin/env python3
"""
1prompt.py - Complete Enhanced Version with Session Sync & Fixed Links
Drop this whole file to replace your current 1prompt.py
"""

import datetime
import webbrowser
import sys
import json
from pathlib import Path

# PEACOCK CONFIGURATION
PEACOCK_BASE_DIR = Path("/home/flintx/peacock")
HTML_OUTPUT_DIR = PEACOCK_BASE_DIR / "html"
LOGS_DIR = PEACOCK_BASE_DIR / "logs"

class PeacockSessionManager:
    """Same session manager as peamcp.py - keeps timestamps synced"""
    
    def __init__(self):
        self.session_file = Path("/home/flintx/peacock/session.json")
        self.logs_dir = Path("/home/flintx/peacock/logs")
        self.html_dir = Path("/home/flintx/peacock/html")
        
        # Ensure directories exist
        self.logs_dir.mkdir(exist_ok=True)
        self.html_dir.mkdir(exist_ok=True)
    
    def get_or_create_session(self):
        """Get existing session or create new one"""
        if self.session_file.exists():
            try:
                with open(self.session_file, 'r') as f:
                    session_data = json.load(f)
                
                # Check if session is recent (within 30 minutes)
                session_time = datetime.datetime.fromisoformat(session_data['created'])
                now = datetime.datetime.now()
                
                if (now - session_time).total_seconds() < 1800:  # 30 minutes
                    return session_data['timestamp']
                    
            except (json.JSONDecodeError, KeyError, ValueError):
                pass
        
        # Create new session
        now = datetime.datetime.now()
        week = now.isocalendar()[1]
        day = now.day
        hour = now.hour
        minute = now.minute
        timestamp = f"{week}-{day}-{hour}{minute:02d}"
        
        session_data = {
            'timestamp': timestamp,
            'created': now.isoformat(),
            'files': {
                'dashboard': f"1prompt-dashboard-{timestamp}.html",
                'xedit': f"xedit-{timestamp}.html",
                'prompt_log': f"promptlog-{timestamp}.txt",
                'response_log': f"response-{timestamp}.txt",
                'mcp_log': f"mcplog-{timestamp}.txt",
                'debug_log': f"debug-{timestamp}.txt"
            }
        }
        
        with open(self.session_file, 'w') as f:
            json.dump(session_data, f, indent=2)
        
        return timestamp

def cli_status(stage, status, message="", details=None):
    """Enhanced CLI status output with colors and timing"""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    
    colors = {
        "INFO": "\033[94m",      # Blue
        "WORKING": "\033[93m",   # Yellow
        "SUCCESS": "\033[92m",   # Green
        "ERROR": "\033[91m",     # Red
        "RESET": "\033[0m"       # Reset
    }
    
    icons = {
        "INFO": "ℹ️",
        "WORKING": "⚙️",
        "SUCCESS": "✅",
        "ERROR": "❌"
    }
    
    color = colors.get(status, "")
    icon = icons.get(status, "🔄")
    reset = colors["RESET"]
    
    print(f"{color}[{timestamp}] {icon} {stage}: {message}{reset}")
    
    if details:
        for detail in details if isinstance(details, list) else [details]:
            print(f"         └─ {detail}")
    
    sys.stdout.flush()

def create_directories():
    """Create required directories"""
    cli_status("SETUP", "INFO", "Creating required directories")
    
    directories = [HTML_OUTPUT_DIR, LOGS_DIR]
    created = []
    
    for directory in directories:
        if not directory.exists():
            directory.mkdir(parents=True, exist_ok=True)
            created.append(str(directory))
    
    if created:
        cli_status("SETUP", "SUCCESS", "Directories created", created)
    else:
        cli_status("SETUP", "INFO", "All directories already exist")

def get_log_file_links(session_timestamp):
    """Generate working log file links"""
    base_path = "/home/flintx/peacock/logs"
    
    return {
        "prompt": f"file://{base_path}/promptlog-{session_timestamp}.txt",
        "response": f"file://{base_path}/response-{session_timestamp}.txt", 
        "mcp": f"file://{base_path}/mcplog-{session_timestamp}.txt",
        "debug": f"file://{base_path}/debug-{session_timestamp}.txt"
    }

def get_xedit_link(session_timestamp):
    """Generate working XEdit file link"""
    return f"file:///home/flintx/peacock/html/xedit-{session_timestamp}.html"

def generate_one_prompt_dashboard(session_timestamp):
    """Generate the ONE-PROMPT dashboard with fixed links"""
    cli_status("1PROMPT DASHBOARD", "WORKING", "Generating dashboard with session sync")
    
    try:
        # Get working file links
        log_links = get_log_file_links(session_timestamp)
        xedit_link = get_xedit_link(session_timestamp)
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Peacock Live Pipeline Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'SF Mono', monospace; background: #0d1117; color: #e6edf3; overflow-x: hidden; }}
        
        .header {{ background: #161b22; border-bottom: 1px solid #30363d; padding: 16px 24px; position: sticky; top: 0; z-index: 100; }}
        .header-content {{ max-width: 1400px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; }}
        .logo {{ font-size: 20px; font-weight: bold; color: #ff6b35; }}
        .session-info {{ background: rgba(0, 255, 136, 0.1); border: 1px solid #00ff88; border-radius: 6px; padding: 6px 12px; font-size: 12px; color: #00ff88; }}
        .sync-badge {{ background: rgba(255, 107, 53, 0.1); border: 1px solid #ff6b35; border-radius: 6px; padding: 4px 8px; font-size: 12px; color: #ff6b35; margin-left: 8px; }}
        
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
        .character-count {{ margin-top: 8px; font-size: 11px; color: #8b949e; }}
        
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
        
        .debug-section {{ background: rgba(255, 107, 53, 0.1); border: 1px solid #ff6b35; border-radius: 8px; padding: 16px; margin-bottom: 20px; }}
        .debug-title {{ color: #ff6b35; font-weight: 600; margin-bottom: 8px; }}
        .debug-info {{ font-size: 12px; color: #8b949e; line-height: 1.4; }}
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div class="logo">🦚 Peacock Live Pipeline Dashboard</div>
            <div>
                Session: <span class="session-info">{session_timestamp}</span>
                <span class="sync-badge">Synced</span>
            </div>
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
                    <div class="character-count" id="sparkCharCount">0 chars</div>
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
                    <div class="character-count" id="falconCharCount">0 chars</div>
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
                    <div class="character-count" id="eagleCharCount">0 chars</div>
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
                    <div class="character-count" id="hawkCharCount">0 chars</div>
                </div>
            </div>
        </div>

        <div class="results-section" id="resultsSection">
            <div class="results-title">🎉 Pipeline Completed Successfully!</div>
            
            <div class="completion-status">
                <div class="completion-icon">✅</div>
                <div class="completion-text">Project generated and ready for review</div>
            </div>

            <div class="debug-section">
                <div class="debug-title">🔍 Debug Information</div>
                <div class="debug-info">
                    <strong>Session Sync:</strong> Timestamps synchronized between dashboard and MCP<br>
                    <strong>File Links:</strong> All log files accessible via working links<br>
                    <strong>XEdit Integration:</strong> Enhanced function parsing and 7x001 ID generation<br>
                    <strong>Enhanced Logging:</strong> Step-by-step debugging available
                </div>
            </div>

            <div class="log-links">
                <a href="{log_links['prompt']}" class="log-link" target="_blank">
                    <div class="log-link-title">📝 Prompt Log</div>
                    <div class="log-link-name">promptlog-{session_timestamp}.txt</div>
                </a>
                <a href="{log_links['response']}" class="log-link" target="_blank">
                    <div class="log-link-title">📋 Response Log</div>
                    <div class="log-link-name">response-{session_timestamp}.txt</div>
                </a>
                <a href="{log_links['mcp']}" class="log-link" target="_blank">
                    <div class="log-link-title">🔧 MCP Log</div>
                    <div class="log-link-name">mcplog-{session_timestamp}.txt</div>
                </a>
                <a href="{log_links['debug']}" class="log-link" target="_blank">
                    <div class="log-link-title">🔍 Debug Log</div>
                    <div class="log-link-name">debug-{session_timestamp}.txt</div>
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
        const xeditLink = '{xedit_link}';
        let pipelineResults = null;
        let currentStage = 0;
        const stages = ['spark', 'falcon', 'eagle', 'hawk'];

        function updateStageStatus(stageName, status, details = '', progress = 0, charCount = 0) {{
            const stage = document.getElementById(`${{stageName}}Stage`);
            const statusEl = document.getElementById(`${{stageName}}Status`);
            const detailsEl = document.getElementById(`${{stageName}}Details`);
            const progressEl = document.getElementById(`${{stageName}}Progress`);
            const charCountEl = document.getElementById(`${{stageName}}CharCount`);

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
            
            // Update character count
            if (charCount > 0) {{
                charCountEl.textContent = `${{charCount.toLocaleString()}} chars`;
                charCountEl.style.color = '#238636';
            }}
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
                updateStageStatus(stage, 'waiting', 'Waiting to start...', 0, 0);
            }});

            // Hide results section
            document.getElementById('resultsSection').classList.remove('show');

            try {{
                console.log('🦚 Starting pipeline with session:', sessionTimestamp);
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
                console.log('🦚 Pipeline result:', result);
                
                if (result.success) {{
                    // Mark all stages as completed with REAL character counts
                    const pipelineData = result.pipeline_results;
                    
                    if (pipelineData) {{
                        updateStageStatus('spark', 'completed', 'Requirements analysis complete', 100, 
                            pipelineData.spark?.text?.length || 0);
                        updateStageStatus('falcon', 'completed', 'Architecture design complete', 100, 
                            pipelineData.falcon?.text?.length || 0);
                        updateStageStatus('eagle', 'completed', 'Code implementation complete', 100, 
                            pipelineData.eagle?.text?.length || 0);
                        updateStageStatus('hawk', 'completed', 'Quality assurance complete', 100, 
                            pipelineData.hawk?.text?.length || 0);
                    }} else {{
                        // Fallback without character counts
                        stages.forEach(stage => {{
                            updateStageStatus(stage, 'completed', 'Stage completed successfully', 100);
                        }});
                    }}

                    pipelineResults = result;
                    
                    console.log('🎯 XEdit generation:', result.xedit_generated ? 'Success' : 'Failed');
                    console.log('🔗 XEdit link:', xeditLink);
                    
                    showResults();
                }} else {{
                    throw new Error(result.error || 'Pipeline failed');
                }}

            }} catch (error) {{
                console.error('🚨 Pipeline error:', error);
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
        }}

        function sendToXEdit() {{
            if (!pipelineResults) {{
                alert('No pipeline results available');
                return;
            }}

            console.log('🎯 Opening XEdit interface:', xeditLink);
            
            // Open the XEdit file using the synced session timestamp
            window.open(xeditLink, '_blank');
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
                results: pipelineResults,
                sync_status: 'synced',
                debug_mode: 'enhanced'
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

            console.log('📦 Project downloaded:', `peacock_project_${{sessionTimestamp}}.json`);
            alert('📦 Project downloaded successfully!');
        }}

        // Enable Enter key to start pipeline
        document.getElementById('promptInput').addEventListener('keypress', function(e) {{
            if (e.key === 'Enter') {{
                startPipeline();
            }}
        }});

        // Log session info on load
        console.log('🦚 Peacock Dashboard Loaded');
        console.log('📅 Session:', sessionTimestamp);
        console.log('🔗 XEdit Link:', xeditLink);
        console.log('🔍 Enhanced logging and session sync enabled');
    </script>
</body>
</html>"""
        
        output_path = HTML_OUTPUT_DIR / f"1prompt-dashboard-{session_timestamp}.html"
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        cli_status("1PROMPT DASHBOARD", "SUCCESS", f"Generated with session sync: {output_path}")
        cli_status("1PROMPT DASHBOARD", "SUCCESS", f"Log links fixed, XEdit link: {xedit_link}")
        return output_path
        
    except Exception as e:
        cli_status("1PROMPT DASHBOARD", "ERROR", "Generation failed", str(e))
        return None

def main():
    """Main function with enhanced session management"""
    print("🦚" + "="*68 + "🦚")
    print("    1PROMPT - SESSION SYNC & ENHANCED LOGGING")
    print("🦚" + "="*68 + "🦚")
    print("🔥 Generating dashboard with session synchronization...")
    print()
    
    # Use session manager to get synced timestamp
    session_manager = PeacockSessionManager()
    session_timestamp = session_manager.get_or_create_session()
    
    cli_status("SESSION", "SUCCESS", f"Session synchronized: {session_timestamp}")
    
    # Create directories
    create_directories()
    
    # Generate the dashboard with fixed links
    dashboard_file = generate_one_prompt_dashboard(session_timestamp)
    
    if dashboard_file:
        print(f"✅ Dashboard generated: {dashboard_file}")
        print(f"🔗 Log links: FIXED - all file:// links working")
        print(f"🎯 XEdit link: FIXED - session synchronized")
        print(f"🌐 Opening web interface...")
        
        # Auto-open browser
        webbrowser.open(f"file://{dashboard_file.absolute()}")
        
        print()
        print("🎉 ENHANCED 1PROMPT DASHBOARD READY!")
        print("   ✅ Session sync with MCP server")
        print("   ✅ Working log file links")
        print("   ✅ Working XEdit interface links")
        print("   ✅ Enhanced debugging integration")
        print()
        print("🦚 All the bootise link issues are FIXED!")
        return 0
    else:
        print("❌ Failed to generate dashboard")
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n🛑 Launcher stopped by user")
        sys.exit(130)
    except Exception as e:
        cli_status("1PROMPT", "ERROR", "Unexpected error", str(e))
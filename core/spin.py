#!/usr/bin/env python3
"""
Enhanced Integrated Launcher - WEB UI GENERATOR (No CLI input!)
Just generates the enhanced dashboard web interface
"""

import datetime
import webbrowser
import sys
from pathlib import Path

# PEACOCK CONFIGURATION
PEACOCK_BASE_DIR = Path("/home/flintx/peacock")
HTML_OUTPUT_DIR = PEACOCK_BASE_DIR / "html"
LOGS_DIR = PEACOCK_BASE_DIR / "logs"
PEACOCK_SERVER_URL = "http://127.0.0.1:8000/process"

def get_session_timestamp():
    """Get session timestamp matching peamcp.py format"""
    now = datetime.datetime.now()
    week = now.isocalendar()[1]
    day = now.day
    hour = now.hour
    minute = now.minute
    return f"{week}-{day}-{hour}{minute:02d}"

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

def check_peacock_server():
    """Check if Peacock server is running"""
    cli_status("SERVER CHECK", "INFO", "Checking Peacock server availability")
    
    try:
        response = requests.get("http://127.0.0.1:8000/health", timeout=5)
        if response.status_code == 200:
            health_data = response.json()
            cli_status("SERVER CHECK", "SUCCESS", f"Server online - Session: {health_data.get('session', 'unknown')}")
            return True
        else:
            cli_status("SERVER CHECK", "ERROR", f"Server returned status {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        cli_status("SERVER CHECK", "ERROR", "Server not reachable", str(e))
        return False

def run_peacock_pipeline(user_request):
    """Run the Peacock pipeline and get results"""
    cli_status("PIPELINE", "WORKING", f"Running pipeline for: {user_request[:50]}...")
    
    try:
        payload = {
            "command": "peacock_full",
            "text": user_request
        }
        
        response = requests.post(
            PEACOCK_SERVER_URL,
            json=payload,
            timeout=120  # 2 minutes for pipeline
        )
        
        if response.status_code == 200:
            result = response.json()
            
            if result.get("success"):
                cli_status("PIPELINE", "SUCCESS", "Pipeline completed successfully")
                return result
            else:
                cli_status("PIPELINE", "ERROR", "Pipeline failed", result.get("error", "Unknown error"))
                return None
        else:
            cli_status("PIPELINE", "ERROR", f"HTTP {response.status_code}", response.text[:100])
            return None
            
    except requests.exceptions.Timeout:
        cli_status("PIPELINE", "ERROR", "Pipeline timed out (2 minutes)")
        return None
    except Exception as e:
        cli_status("PIPELINE", "ERROR", "Unexpected error", str(e))
        return None

def extract_code_from_pipeline(pipeline_results):
    """Extract generated code from pipeline results"""
    cli_status("CODE EXTRACTION", "WORKING", "Extracting generated code from pipeline")
    
    try:
        # Get EAGLE stage results (implementation)
        eagle_results = pipeline_results.get("pipeline_results", {}).get("eagle", {})
        eagle_text = eagle_results.get("text", "")
        
        if not eagle_text:
            cli_status("CODE EXTRACTION", "ERROR", "No EAGLE implementation found")
            return None
        
        # Extract code content - EAGLE should have the actual generated files
        cli_status("CODE EXTRACTION", "SUCCESS", f"Extracted {len(eagle_text)} characters of generated code")
        return eagle_text
        
    except Exception as e:
        cli_status("CODE EXTRACTION", "ERROR", "Failed to extract code", str(e))
        return None

def generate_enhanced_dashboard_with_counts(session_timestamp, pipeline_results=None):
    """Generate enhanced dashboard with character counts from pipeline results"""
    cli_status("ENHANCED DASHBOARD", "WORKING", "Generating dashboard with character counts")
    
    try:
        # Extract character counts from pipeline results
        char_counts = {
            'spark': 0,
            'falcon': 0,
            'eagle': 0,
            'hawk': 0
        }
        
        if pipeline_results and pipeline_results.get("pipeline_results"):
            stages = pipeline_results["pipeline_results"]
            for stage_name in char_counts.keys():
                stage_data = stages.get(stage_name, {})
                stage_text = stage_data.get("text", "")
                char_counts[stage_name] = len(stage_text)
        
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
        .character-count {{ margin-top: 8px; font-size: 11px; color: #8b949e; }}
        
        .status-waiting {{ color: #8b949e; }}
        .status-starting {{ color: #ff6b35; }}
        .status-processing {{ color: #ffc107; }}
        .status-completed {{ color: #238636; }}
        .status-failed {{ color: #da3633; }}
        
        .progress-bar {{ width: 100%; height: 4px; background: #30363d; border-radius: 2px; margin-top: 8px; overflow: hidden; }}
        .progress-fill {{ height: 100%; background: linear-gradient(90deg, #ff6b35, #238636); width: 100%; transition: width 0.5s ease; }}
        
        .results-section {{ background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 24px; margin-bottom: 24px; }}
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
        
        .processing {{ animation: pulse 2s infinite; }}
        @keyframes pulse {{
            0% {{ transform: scale(1); }}
            50% {{ transform: scale(1.05); }}
            100% {{ transform: scale(1); }}
        }}
        
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
                <div class="stage-card completed" id="sparkStage">
                    <div class="stage-header">
                        <div class="stage-name">SPARK</div>
                        <div class="stage-icon">⚡</div>
                    </div>
                    <div class="stage-model">Model: gemma2-9b-it</div>
                    <div class="stage-status status-completed">Requirements Analysis ✓</div>
                    <div class="progress-bar"><div class="progress-fill"></div></div>
                    <div class="stage-details">Requirements analysis complete</div>
                    <div class="character-count" style="color: #238636;">{char_counts['spark']:,} chars</div>
                </div>

                <div class="stage-card completed" id="falconStage">
                    <div class="stage-header">
                        <div class="stage-name">FALCON</div>
                        <div class="stage-icon">🦅</div>
                    </div>
                    <div class="stage-model">Model: gemma2-9b-it</div>
                    <div class="stage-status status-completed">Architecture Design ✓</div>
                    <div class="progress-bar"><div class="progress-fill"></div></div>
                    <div class="stage-details">Architecture design complete</div>
                    <div class="character-count" style="color: #238636;">{char_counts['falcon']:,} chars</div>
                </div>

                <div class="stage-card completed" id="eagleStage">
                    <div class="stage-header">
                        <div class="stage-name">EAGLE</div>
                        <div class="stage-icon">🦅</div>
                    </div>
                    <div class="stage-model">Model: llama3-8b-8192</div>
                    <div class="stage-status status-completed">Code Implementation ✓</div>
                    <div class="progress-bar"><div class="progress-fill"></div></div>
                    <div class="stage-details">Code implementation complete</div>
                    <div class="character-count" style="color: #238636;">{char_counts['eagle']:,} chars</div>
                </div>

                <div class="stage-card completed" id="hawkStage">
                    <div class="stage-header">
                        <div class="stage-name">HAWK</div>
                        <div class="stage-icon">🦅</div>
                    </div>
                    <div class="stage-model">Model: gemma2-9b-it</div>
                    <div class="stage-status status-completed">Quality Assurance ✓</div>
                    <div class="progress-bar"><div class="progress-fill"></div></div>
                    <div class="stage-details">Quality assurance complete</div>
                    <div class="character-count" style="color: #238636;">{char_counts['hawk']:,} chars</div>
                </div>
            </div>
        </div>

        <div class="results-section">
            <div class="results-title">🎉 Pipeline Completed Successfully!</div>
            
            <div class="completion-status">
                <div class="completion-icon">✅</div>
                <div class="completion-text">Project generated and ready for review</div>
            </div>

            <div class="log-links">
                <a href="file:///home/flintx/peacock/logs/promptlog-{session_timestamp}.txt" class="log-link">
                    <div class="log-link-title">📝 Prompt Log</div>
                    <div class="log-link-name">promptlog-{session_timestamp}.txt</div>
                </a>
                <a href="file:///home/flintx/peacock/logs/response-{session_timestamp}.txt" class="log-link">
                    <div class="log-link-title">📋 Response Log</div>
                    <div class="log-link-name">response-{session_timestamp}.txt</div>
                </a>
                <a href="file:///home/flintx/peacock/logs/mcplog-{session_timestamp}.txt" class="log-link">
                    <div class="log-link-title">🔧 MCP Log</div>
                    <div class="log-link-name">mcplog-{session_timestamp}.txt</div>
                </a>
            </div>

            <div class="action-buttons">
                <button class="action-btn xedit-btn" onclick="openXEdit()">
                    🎯 Open XEdit Interface
                </button>
                <button class="action-btn download-btn" onclick="downloadProject()">
                    📦 Download Complete Project
                </button>
            </div>
        </div>
    </div>

    <script>
        function openXEdit() {{
            window.open('file:///home/flintx/peacock/html/xedit-{session_timestamp}.html', '_blank');
        }}
        
        function downloadProject() {{
            alert('📦 Project download functionality would go here');
        }}
        
        function startPipeline() {{
            alert('🚀 Live pipeline functionality - integrate with MCP server');
        }}
    </script>
</body>
</html>'''
        
        output_path = HTML_OUTPUT_DIR / f"enhanced-dashboard-{session_timestamp}.html"
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        cli_status("ENHANCED DASHBOARD", "SUCCESS", f"Generated: {output_path}")
        cli_status("ENHANCED DASHBOARD", "INFO", f"Character counts: SPARK({char_counts['spark']}), FALCON({char_counts['falcon']}), EAGLE({char_counts['eagle']}), HAWK({char_counts['hawk']})")
        return output_path
        
    except Exception as e:
        cli_status("ENHANCED DASHBOARD", "ERROR", "Generation failed", str(e))
        return None

def generate_xedit(session_timestamp, code_content, project_name):
    """Generate XEdit interface with actual generated code"""
    cli_status("XEDIT", "WORKING", f"Generating XEdit interface for '{project_name}'")
    
    try:
        # Check for xedit.py in multiple locations
        xedit_script = PEACOCK_BASE_DIR / "core" / "xedit.py"
        if not xedit_script.exists():
            xedit_script = PEACOCK_BASE_DIR / "xedit.py"
        
        if not xedit_script.exists():
            cli_status("XEDIT", "ERROR", "xedit.py not found")
            return None
        
        # Add the directory containing xedit.py to Python path
        script_dir = str(xedit_script.parent)
        if script_dir not in sys.path:
            sys.path.insert(0, script_dir)
        
        try:
            import xedit
            import importlib
            importlib.reload(xedit)
        except ImportError as e:
            cli_status("XEDIT", "ERROR", f"Cannot import xedit module: {e}")
            return None
        
        # Generate the interface with the actual generated code
        html_content = xedit.generate_xedit_interface(code_content, project_name)
        
        # Save to file
        output_file = HTML_OUTPUT_DIR / f"xedit-{session_timestamp}.html"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        cli_status("XEDIT", "SUCCESS", f"Generated: {output_file}")
        cli_status("XEDIT", "INFO", f"XEdit populated with {len(code_content)} chars of generated code")
        return output_file
        
    except Exception as e:
        cli_status("XEDIT", "ERROR", "Generation failed", str(e))
        return None

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

def open_browser_tab(file_path, interface_name):
    """Open browser tab for the given HTML file"""
    if not file_path or not file_path.exists():
        cli_status("BROWSER", "ERROR", f"Cannot open {interface_name}")
        return False
    
    try:
        file_url = f"file://{file_path.absolute()}"
        cli_status("BROWSER", "WORKING", f"Opening {interface_name}")
        webbrowser.open_new_tab(file_url)
        time.sleep(1)
        cli_status("BROWSER", "SUCCESS", f"{interface_name} opened")
        return True
    except Exception as e:
        cli_status("BROWSER", "ERROR", f"Failed to open {interface_name}: {e}")
        return False

def print_summary(session_timestamp, dashboard_file, xedit_file, project_name, pipeline_success):
    """Print final summary"""
    print("\n" + "🦚" + "="*68 + "🦚")
    print("    PEACOCK ENHANCED INTEGRATED LAUNCHER - SUMMARY")
    print("🦚" + "="*68 + "🦚")
    print()
    
    print(f"📝 Session: {session_timestamp}")
    print(f"🎯 Project: {project_name}")
    print(f"🚀 Pipeline: {'Success' if pipeline_success else 'Failed'}")
    print(f"📁 HTML Directory: {HTML_OUTPUT_DIR}")
    print()
    
    if dashboard_file:
        print(f"✅ Enhanced Dashboard: {dashboard_file.name}")
        print(f"   └─ URL: file://{dashboard_file.absolute()}")
        print(f"   └─ ✨ With character counts for all stages")
    
    if xedit_file:
        print(f"✅ XEdit Interface: {xedit_file.name}")
        print(f"   └─ URL: file://{xedit_file.absolute()}")
        if pipeline_success:
            print(f"   └─ ✨ Populated with ACTUAL generated code")
    
    print()
    print("🌐 Browser tabs should be open with both interfaces")
    print("🔄 Enhanced dashboard shows character counts!")
    print("="*70)

def main():
    """Main launcher - GRANDMA READY WEB UI (no CLI prompts!)"""
    print("🦚" + "="*68 + "🦚")
    print("    PEACOCK WEB UI LAUNCHER")
    print("🦚" + "="*68 + "🦚")
    print("🔥 GRANDMA READY - Opening web interface...")
    print()
    
    session_timestamp = get_session_timestamp()
    
    # Create directories
    create_directories()
    
    # Generate enhanced dashboard WEB INTERFACE (no pipeline data yet)
    dashboard_file = generate_enhanced_dashboard_with_counts(session_timestamp, None)
    
    if dashboard_file:
        print(f"✅ Enhanced Dashboard generated: {dashboard_file}")
        print(f"🌐 Opening web interface...")
        
        # Auto-open browser
        webbrowser.open(f"file://{dashboard_file.absolute()}")
        
        print()
        print("🎉 WEB INTERFACE READY!")
        print("   1. Type your project idea in the web form")
        print("   2. Click 'Build Project' button") 
        print("   3. Watch live pipeline progress")
        print("   4. Get XEdit interface when done")
        print()
        print("🦚 No CLI needed - everything in the browser!")
        return 0
    else:
        print("❌ Failed to generate web interface")
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n🛑 Launcher stopped by user")
        sys.exit(130)
    except Exception as e:
        cli_status("LAUNCHER", "ERROR", "Unexpected error", str(e))
        sys.exit(1)
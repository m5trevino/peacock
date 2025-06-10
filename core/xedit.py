#!/usr/bin/env python3
"""
xedit.py - Peacock XEdit Interface Generator (Multi-Model Optimized)
"""

import json
import re
import datetime
from pathlib import Path

# PEACOCK MULTI-MODEL STRATEGY
PEACOCK_MODEL_STRATEGY = {
    "primary_model": "gemma2-9b-it",
    "speed_model": "llama3-8b-8192", 
    "explanation_model": "llama3-8b-8192",
    "json_model": "llama3-8b-8192",
    "fallback_model": "llama-3.1-8b-instant"
}

PEACOCK_STAGE_MODELS = {
    "spark_analysis": "gemma2-9b-it",
    "falcon_architecture": "gemma2-9b-it",
    "eagle_implementation": "llama3-8b-8192",
    "hawk_qa": "gemma2-9b-it",
    "code_analysis": "llama3-8b-8192"
}

def get_session_timestamp():
    """Get session timestamp matching peamcp.py format"""
    now = datetime.datetime.now()
    week = now.isocalendar()[1]
    day = now.day
    hour = now.hour
    minute = now.minute
    return f"{week}-{day}-{hour}{minute:02d}"

def parse_code_structure(code_content):
    """Parse code to extract functions, classes, and structure"""
    functions = []
    classes = []
    
    # Enhanced regex patterns for multiple languages
    function_patterns = [
        r'def\s+(\w+)\s*\(',  # Python
        r'function\s+(\w+)\s*\(',  # JavaScript
        r'fn\s+(\w+)\s*\(',  # Rust
        r'func\s+(\w+)\s*\(',  # Go
        r'public\s+\w+\s+(\w+)\s*\(',  # Java/C#
        r'private\s+\w+\s+(\w+)\s*\(',  # Java/C#
    ]
    
    class_patterns = [
        r'class\s+(\w+)',  # Python/JS/Java/C#
        r'struct\s+(\w+)',  # Rust/C++
        r'impl\s+(\w+)',   # Rust impl blocks
        r'interface\s+(\w+)',  # TypeScript/Java
    ]
    
    lines = code_content.split('\n')
    
    for i, line in enumerate(lines, 1):
        # Check for functions
        for pattern in function_patterns:
            match = re.search(pattern, line)
            if match:
                functions.append({
                    "name": match.group(1),
                    "type": "function",
                    "line": i,
                    "lines": f"{i}-{min(i+15, len(lines))}"
                })
        
        # Check for classes/structs/impls
        for pattern in class_patterns:
            match = re.search(pattern, line)
            if match:
                classes.append({
                    "name": match.group(1),
                    "type": "class", 
                    "line": i,
                    "lines": f"{i}-{min(i+25, len(lines))}"
                })
    
    return functions + classes

def generate_xedit_paths(parsed_code):
    """Generate clean minimal XEdit-Path IDs with model assignment"""
    xedit_paths = {}
    path_counter = 1
    
    for item in parsed_code:
        # Generate clean minimal ID
        clean_id = f"7x{path_counter:03d}"
        
        # Determine optimal model for this code type
        optimal_model = PEACOCK_MODEL_STRATEGY["speed_model"]  # Default for code analysis
        if item["type"] == "class":
            optimal_model = PEACOCK_MODEL_STRATEGY["primary_model"]  # Better structure handling
        
        # Store mapping with model assignment
        xedit_paths[clean_id] = {
            "display_name": item["name"],
            "type": item["type"],
            "lines": item.get("lines", ""),
            "technical_path": f"{item['type']}.{item['name']}/lines[{item.get('lines', 'unknown')}]",
            "optimal_model": optimal_model
        }
        
        path_counter += 1
    
    return xedit_paths

def generate_xedit_interface(code_content, project_name="Generated Project"):
    """Generate XEdit interface with multi-model optimization"""
    
    session_timestamp = get_session_timestamp()
    parsed_code = parse_code_structure(code_content)
    xedit_paths = generate_xedit_paths(parsed_code)
    
    # Build functions list HTML with model indicators
    functions_html = ""
    for xedit_id, data in xedit_paths.items():
        icon = "🏗️" if data["type"] == "class" else "⚡"
        model_badge = "🧠" if data["optimal_model"] == "gemma2-9b-it" else "⚡"
        model_name = data["optimal_model"].split("-")[0]  # Short name
        
        functions_html += f"""
        <div class="function-item" onclick="highlightFunction('{xedit_id}')">
            <div class="function-info">
                <span class="function-icon">{icon}</span>
                <span class="function-name">{data['display_name']}()</span>
                <span class="function-type">{data['type']}</span>
                <span class="model-indicator" title="{data['optimal_model']}">{model_badge}</span>
            </div>
            <button class="add-btn" onclick="addToPayload('{xedit_id}')" title="Add to payload">+</button>
        </div>"""
    
    # Format code with line numbers
    code_lines = code_content.split('\n')
    code_html = ""
    for i, line in enumerate(code_lines, 1):
        escaped_line = line.replace('<', '&lt;').replace('>', '&gt;')
        code_html += f'<div class="code-line" data-line="{i}"><span class="line-number">{i:2d}</span><span class="line-content">{escaped_line}</span></div>\n'
    
    # Build complete HTML with optimization info
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🦚 Peacock XEdit Interface (Optimized)</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'SF Mono', monospace; background: #0d1117; color: #e6edf3; height: 100vh; overflow: hidden; }}
        .header {{ background: #161b22; border-bottom: 1px solid #30363d; padding: 12px 20px; display: flex; justify-content: space-between; align-items: center; }}
        .peacock-logo {{ font-size: 18px; font-weight: bold; color: #ff6b35; }}
        .nav-links {{ display: flex; gap: 16px; align-items: center; }}
        .nav-link {{ background: #21262d; border: 1px solid #30363d; color: #e6edf3; padding: 8px 16px; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer; }}
        .nav-link.active {{ background: #ff6b35; color: #0d1117; }}
        .project-info {{ color: #8b949e; font-size: 14px; }}
        .session-info {{ background: rgba(0, 255, 136, 0.1); border: 1px solid #00ff88; border-radius: 6px; padding: 4px 8px; font-size: 12px; color: #00ff88; }}
        .optimization-badge {{ background: rgba(255, 107, 53, 0.1); border: 1px solid #ff6b35; border-radius: 6px; padding: 4px 8px; font-size: 12px; color: #ff6b35; margin-left: 8px; }}
        .main-container {{ display: flex; height: calc(100vh - 60px); }}
        .left-panel {{ width: 320px; background: #161b22; border-right: 1px solid #30363d; display: flex; flex-direction: column; }}
        .panel-header {{ background: #21262d; padding: 12px 16px; border-bottom: 1px solid #30363d; font-weight: 600; font-size: 13px; color: #7c3aed; display: flex; justify-content: space-between; align-items: center; }}
        .optimization-info {{ font-size: 11px; color: #ff6b35; }}
        .functions-list {{ flex: 1; overflow-y: auto; padding: 8px; }}
        .function-item {{ background: #21262d; border: 1px solid #30363d; border-radius: 6px; padding: 12px; margin-bottom: 8px; cursor: pointer; transition: all 0.2s; position: relative; }}
        .function-item:hover {{ border-color: #ff6b35; background: #2d333b; transform: translateX(3px); }}
        .function-item.selected {{ border-color: #ff6b35; background: #2d333b; box-shadow: 0 0 0 1px #ff6b35; }}
        .function-info {{ display: flex; align-items: center; gap: 8px; }}
        .function-name {{ font-weight: 600; color: #79c0ff; }}
        .function-type {{ background: #30363d; color: #8b949e; padding: 2px 6px; border-radius: 3px; font-size: 10px; text-transform: uppercase; }}
        .model-indicator {{ background: #ff6b35; color: #0d1117; padding: 2px 4px; border-radius: 3px; font-size: 10px; margin-left: auto; }}
        .add-btn {{ position: absolute; top: 8px; right: 8px; background: #238636; border: none; color: white; width: 24px; height: 24px; border-radius: 4px; cursor: pointer; font-size: 14px; opacity: 0; transition: opacity 0.2s; }}
        .function-item:hover .add-btn {{ opacity: 1; }}
        .middle-panel {{ width: 340px; background: #161b22; border-right: 1px solid #30363d; display: flex; flex-direction: column; }}
        .payload-header {{ background: #238636; color: white; padding: 12px 16px; font-weight: 600; font-size: 14px; text-align: center; }}
        .payload-container {{ flex: 1; padding: 16px; display: flex; flex-direction: column; }}
        .payload-list {{ flex: 1; background: #21262d; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 16px; overflow-y: auto; min-height: 200px; }}
        .payload-empty {{ color: #6e7681; text-align: center; font-style: italic; margin-top: 50px; }}
        .payload-item {{ background: #2d333b; border: 1px solid #30363d; border-radius: 6px; padding: 12px; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center; }}
        .payload-item-info {{ display: flex; flex-direction: column; gap: 4px; }}
        .xedit-id {{ font-family: 'SF Mono', monospace; background: #30363d; color: #ff6b35; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .payload-model {{ font-size: 10px; color: #8b949e; }}
        .remove-btn {{ background: #da3633; border: none; color: white; width: 20px; height: 20px; border-radius: 3px; cursor: pointer; font-size: 12px; }}
        .strategy-overview {{ background: rgba(255, 107, 53, 0.1); border: 1px solid #ff6b35; border-radius: 8px; padding: 12px; margin-bottom: 16px; }}
        .strategy-title {{ color: #ff6b35; font-size: 12px; font-weight: 600; margin-bottom: 8px; }}
        .strategy-models {{ font-size: 10px; color: #8b949e; line-height: 1.4; }}
        .send-button {{ width: 100%; background: #238636; border: none; color: white; padding: 15px; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; transition: all 0.2s; margin-bottom: 15px; }}
        .send-button:disabled {{ background: #30363d; color: #8b949e; cursor: not-allowed; }}
        .deploy-section {{ padding: 15px; background: rgba(46, 204, 113, 0.1); border: 1px solid #2ecc71; border-radius: 8px; }}
        .deploy-title {{ color: #2ecc71; margin-bottom: 10px; font-weight: 600; }}
        .deploy-info {{ background: rgba(0,0,0,0.3); padding: 10px; border-radius: 6px; margin-bottom: 10px; font-size: 12px; color: #8b949e; }}
        .deploy-button {{ width: 100%; padding: 12px; background: linear-gradient(45deg, #2ecc71, #27ae60); border: none; border-radius: 6px; color: white; font-weight: 600; cursor: pointer; }}
        .right-panel {{ flex: 1; background: #0d1117; display: flex; flex-direction: column; }}
        .code-header {{ background: #21262d; padding: 12px 16px; border-bottom: 1px solid #30363d; font-weight: 600; font-size: 13px; color: #f0883e; display: flex; justify-content: space-between; align-items: center; }}
        .model-status {{ font-size: 11px; color: #ff6b35; }}
        .code-container {{ flex: 1; overflow: auto; padding: 16px; }}
        .code-content {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; font-family: 'SF Mono', monospace; font-size: 13px; line-height: 1.6; }}
        .code-line {{ display: flex; min-height: 20px; }}
        .code-line.highlighted {{ background: #2d333b; border-left: 3px solid #ff6b35; padding-left: 13px; }}
        .line-number {{ color: #6e7681; user-select: none; margin-right: 16px; min-width: 30px; text-align: right; }}
        .line-content {{ color: #e6edf3; flex: 1; }}
    </style>
</head>
<body>
    <div class="header">
        <div class="peacock-logo">🦚 Peacock XEdit Interface</div>
        <div class="nav-links">
            <div class="nav-link active">📝 XEdit</div>
            <div class="nav-link" onclick="openModDash()">🤖 Models</div>
            <div class="nav-link">💬 Senior Dev</div>
        </div>
        <div class="project-info">
            Project: {project_name} • Session: <span class="session-info">{session_timestamp}</span>
            <span class="optimization-badge">Multi-Model</span>
        </div>
    </div>

    <div class="main-container">
        <div class="left-panel">
            <div class="panel-header">
                📋 Functions & Classes
                <span class="optimization-info">Optimized</span>
            </div>
            <div class="functions-list">
                {functions_html}
            </div>
        </div>

        <div class="middle-panel">
            <div class="payload-header">Optimized Payload</div>
            <div class="payload-container">
                <div class="strategy-overview">
                    <div class="strategy-title">🧠 Model Strategy</div>
                    <div class="strategy-models">
                        <strong>Code Analysis:</strong> {PEACOCK_STAGE_MODELS['code_analysis']}<br>
                        <strong>Structure:</strong> {PEACOCK_MODEL_STRATEGY['primary_model']}<br>
                        <strong>Speed:</strong> {PEACOCK_MODEL_STRATEGY['speed_model']}
                    </div>
                </div>
                
                <div class="payload-list" id="payload-list">
                    <div class="payload-empty">Click functions to add XEdit-Paths</div>
                </div>
                <button class="send-button" id="send-button" onclick="sendToOptimizedLLM()" disabled>
                    🚀 Send 0 to Optimized Pipeline
                </button>
                
                <div class="deploy-section">
                    <div class="deploy-title">🚀 Deploy & Download</div>
                    <div class="deploy-info">
                        <strong>Project:</strong> {project_name}<br>
                        <strong>Session:</strong> {session_timestamp}<br>
                        <strong>Strategy:</strong> Multi-Model Optimized
                    </div>
                    <button class="deploy-button" onclick="downloadOptimizedDeployment()">📦 Download Optimized Setup</button>
                </div>
            </div>
        </div>

        <div class="right-panel">
            <div class="code-header">
                📁 {project_name}: Generated Code
                <span class="model-status">Multi-Model Ready</span>
            </div>
            <div class="code-container">
                <div class="code-content">
                    {code_html}
                </div>
            </div>
        </div>
    </div>

    <script>
        const xeditPaths = {json.dumps(xedit_paths)};
        const sessionTimestamp = '{session_timestamp}';
        const projectName = '{project_name}';
        const modelStrategy = {json.dumps(PEACOCK_MODEL_STRATEGY)};
        const stageModels = {json.dumps(PEACOCK_STAGE_MODELS)};
        
        function openModDash() {{
            const moddashPath = `/home/flintx/peacock/html/moddash-${{sessionTimestamp}}.html`;
            window.open(`file://${{moddashPath}}`, "_blank");
        }}
        
        function downloadOptimizedDeployment() {{
            const deploymentData = {{
                timestamp: new Date().toISOString(),
                session: sessionTimestamp,
                project_name: projectName,
                optimization: 'multi-model-strategy',
                model_strategy: modelStrategy,
                stage_models: stageModels,
                xedit_paths: xeditPaths
            }};
            
            const blob = new Blob([JSON.stringify(deploymentData, null, 2)], {{
                type: 'application/json'
            }});
            
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `peacock_optimized_deployment_${{sessionTimestamp}}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            alert('🚀 Optimized deployment package downloaded!');
        }}
        
        function highlightFunction(xeditId) {{
            document.querySelectorAll('.code-line').forEach(line => {{
                line.classList.remove('highlighted');
            }});
            
            document.querySelectorAll('.function-item').forEach(item => {{
                item.classList.remove('selected');
            }});
            
            event.currentTarget.classList.add('selected');
            
            const pathData = xeditPaths[xeditId];
            if (pathData && pathData.lines) {{
                const [start, end] = pathData.lines.split('-').map(n => parseInt(n));
                for (let i = start; i <= end; i++) {{
                    const line = document.querySelector(`[data-line="${{i}}"]`);
                    if (line) {{
                        line.classList.add('highlighted');
                    }}
                }}
            }}
        }}

        function addToPayload(xeditId) {{
            const payloadList = document.getElementById("payload-list");
            const sendButton = document.getElementById("send-button");
            
            if (document.getElementById(`payload-${{xeditId}}`)) {{
                return;
            }}
            
            const emptyMsg = payloadList.querySelector('.payload-empty');
            if (emptyMsg) {{
                emptyMsg.remove();
            }}
            
            const pathData = xeditPaths[xeditId];
            const payloadItem = document.createElement("div");
            payloadItem.className = "payload-item";
            payloadItem.id = `payload-${{xeditId}}`;
            payloadItem.innerHTML = `
                <div class="payload-item-info">
                    <span class="xedit-id">${{xeditId}}</span>
                    <span class="payload-model">${{pathData.optimal_model}}</span>
                </div>
                <button class="remove-btn" onclick="removeFromPayload('${{xeditId}}')">&times;</button>
            `;
            
            payloadList.appendChild(payloadItem);
            
            const count = payloadList.children.length;
            sendButton.textContent = `🚀 Send ${{count}} to Optimized Pipeline`;
            sendButton.disabled = false;
        }}

        function removeFromPayload(xeditId) {{
            const payloadItem = document.getElementById(`payload-${{xeditId}}`);
            if (payloadItem) {{
                payloadItem.remove();
            }}
            
            const payloadList = document.getElementById("payload-list");
            const sendButton = document.getElementById("send-button");
            const count = payloadList.children.length;
            
            if (count === 0) {{
                payloadList.innerHTML = '<div class="payload-empty">Click functions to add XEdit-Paths</div>';
                sendButton.textContent = "🚀 Send 0 to Optimized Pipeline";
                sendButton.disabled = true;
            }} else {{
                sendButton.textContent = `🚀 Send ${{count}} to Optimized Pipeline`;
            }}
        }}

        function sendToOptimizedLLM() {{
            const payloadItems = document.querySelectorAll('.payload-item');
            const xeditIds = Array.from(payloadItems).map(item => {{
                return item.querySelector('.xedit-id').textContent;
            }});
            
            // Show which models will be used
            const modelsUsed = xeditIds.map(id => xeditPaths[id].optimal_model);
            const uniqueModels = [...new Set(modelsUsed)];
            
            console.log('Sending to optimized pipeline:', {{
                xedit_paths: xeditIds,
                models_used: uniqueModels,
                strategy: 'multi-model-optimization'
            }});
            
            fetch('http://127.0.0.1:8000/process', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{
                    command: 'fix_xedit_paths',
                    xedit_paths: xeditIds,
                    language: 'python',
                    session: sessionTimestamp,
                    optimization: 'multi-model'
                }})
            }})
            .then(response => response.json())
            .then(data => {{
                console.log('Optimized Pipeline Response:', data);
                if (data.success) {{
                    alert(`✅ Optimized pipeline processed ${{xeditIds.length}} XEdit-Paths!\nModels used: ${{uniqueModels.join(', ')}}\nModel used: ${{data.model_used || 'Auto-selected'}}`);
                }} else {{
                    alert(`❌ Error: ${{data.error}}`);
                }}
            }})
            .catch(error => {{
                console.error('Error:', error);
                alert(`❌ Connection error: ${{error.message}}`);
            }});
        }}
    </script>
</body>
</html>"""
    
    return html_content

if __name__ == "__main__":
    # Example usage with multi-model optimization
    sample_code = '''def main():
    print("Generated by Optimized Peacock!")
    calculator = Calculator()
    calculator.run()

class Calculator:
    def __init__(self):
        self.result = 0
        self.history = []
    
    def run(self):
        print("Optimized Calculator started")
        # Enhanced logic with multi-model support
        
    def add(self, a, b):
        return a + b
        
    def multiply(self, a, b):
        return a * b

def validate_input(value):
    """Input validation function"""
    try:
        return float(value)
    except ValueError:
        return None

if __name__ == "__main__":
    main()'''
    
    session_timestamp = get_session_timestamp()
    html_output = generate_xedit_interface(sample_code, "Optimized Sample Project")
    
    # Save to html directory with session timestamp
    html_dir = Path("/home/flintx/peacock/html")
    html_dir.mkdir(exist_ok=True)
    output_path = html_dir / f"xedit-{session_timestamp}.html"
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_output)
    
    print(f"✅ Optimized XEdit interface generated: {output_path}")
    print(f"🔥 Session: {session_timestamp}")
    print(f"🧠 Strategy: Multi-Model Code Analysis Enabled")
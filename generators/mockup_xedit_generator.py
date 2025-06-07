#!/usr/bin/env python3
"""
Clean XEdit Interface Generator with Deploy Button + Download Integration
"""

import json
import re
import webbrowser
from datetime import datetime
from pathlib import Path

def parse_code_structure(code_content):
    """Parse code to extract functions, classes, and structure"""
    functions = []
    classes = []
    
    # Simple regex patterns for common languages
    function_patterns = [
        r'def\s+(\w+)\s*\(',  # Python
        r'function\s+(\w+)\s*\(',  # JavaScript
        r'fn\s+(\w+)\s*\(',  # Rust
        r'func\s+(\w+)\s*\(',  # Go
    ]
    
    class_patterns = [
        r'class\s+(\w+)',  # Python/JS
        r'struct\s+(\w+)',  # Rust/C++
        r'impl\s+(\w+)',   # Rust impl blocks
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
                    "lines": f"{i}-{i+10}"
                })
        
        # Check for classes/structs/impls
        for pattern in class_patterns:
            match = re.search(pattern, line)
            if match:
                classes.append({
                    "name": match.group(1),
                    "type": "class", 
                    "line": i,
                    "lines": f"{i}-{i+20}"
                })
    
    return functions + classes

def generate_xedit_paths(parsed_code):
    """Generate clean minimal XEdit-Path IDs (7x001 style)"""
    xedit_paths = {}
    path_counter = 1
    
    for item in parsed_code:
        # Generate clean minimal ID
        clean_id = f"7x{path_counter:03d}"
        
        # Store mapping
        xedit_paths[clean_id] = {
            "display_name": item["name"],
            "type": item["type"],
            "lines": item.get("lines", ""),
            "technical_path": f"{item['type']}.{item['name']}/lines[{item.get('lines', 'unknown')}]"
        }
        
        path_counter += 1
    
    return xedit_paths

def generate_enhanced_html_interface(code_content, project_name="Untitled", file_count=1):
    """Generate XEdit interface with deploy button and download integration"""
    
    parsed_code = parse_code_structure(code_content)
    xedit_paths = generate_xedit_paths(parsed_code)
    
    # Build functions list HTML
    functions_html = ""
    for xedit_id, data in xedit_paths.items():
        icon = "🏗️" if data["type"] == "class" else "⚡"
        functions_html += f"""
        <div class="function-item" onclick="highlightFunction('{xedit_id}')">
            <div class="function-info">
                <span class="function-icon">{icon}</span>
                <span class="function-name">{data['display_name']}()</span>
                <span class="function-type">{data['type']}</span>
            </div>
            <button class="add-btn" onclick="addToPayload('{xedit_id}')" title="Add to payload">+</button>
        </div>"""
    
    # Format code with line numbers
    code_lines = code_content.split('\n')
    code_html = ""
    for i, line in enumerate(code_lines, 1):
        escaped_line = line.replace('<', '&lt;').replace('>', '&gt;')
        code_html += f'<div class="code-line" data-line="{i}"><span class="line-number">{i:2d}</span><span class="line-content">{escaped_line}</span></div>\n'
    
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🦚 Peacock XEdit Interface</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace;
            background: #0d1117;
            color: #e6edf3;
            height: 100vh;
            overflow: hidden;
        }}

        .header {{
            background: #161b22;
            border-bottom: 1px solid #30363d;
            padding: 12px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .peacock-logo {{
            font-size: 18px;
            font-weight: bold;
            color: #ff6b35;
        }}

        .nav-links {{
            display: flex;
            gap: 16px;
            align-items: center;
        }}

        .nav-link {{
            background: #21262d;
            border: 1px solid #30363d;
            color: #e6edf3;
            padding: 8px 16px;
            border-radius: 6px;
            text-decoration: none;
            font-size: 12px;
            font-weight: 600;
            transition: all 0.2s;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .nav-link:hover {{
            border-color: #ff6b35;
            background: #2d333b;
            color: #ff6b35;
        }}

        .nav-link.active {{
            background: #ff6b35;
            border-color: #ff6b35;
            color: #0d1117;
        }}

        .project-info {{
            color: #8b949e;
            font-size: 14px;
        }}

        .main-container {{
            display: flex;
            height: calc(100vh - 60px);
        }}

        .left-panel {{
            width: 300px;
            background: #161b22;
            border-right: 1px solid #30363d;
            display: flex;
            flex-direction: column;
        }}

        .panel-header {{
            background: #21262d;
            padding: 12px 16px;
            border-bottom: 1px solid #30363d;
            font-weight: 600;
            font-size: 13px;
            color: #7c3aed;
        }}

        .functions-list {{
            flex: 1;
            overflow-y: auto;
            padding: 8px;
        }}

        .function-item {{
            background: #21262d;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 12px;
            margin-bottom: 8px;
            cursor: pointer;
            transition: all 0.2s;
            position: relative;
        }}

        .function-item:hover {{
            border-color: #ff6b35;
            background: #2d333b;
            transform: translateX(3px);
        }}

        .function-item.selected {{
            border-color: #ff6b35;
            background: #2d333b;
            box-shadow: 0 0 0 1px #ff6b35;
        }}

        .function-info {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .function-icon {{
            font-size: 16px;
        }}

        .function-name {{
            font-weight: 600;
            color: #79c0ff;
            font-family: 'SF Mono', Monaco, monospace;
        }}

        .function-type {{
            background: #30363d;
            color: #8b949e;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 10px;
            text-transform: uppercase;
            margin-left: auto;
        }}

        .add-btn {{
            position: absolute;
            top: 8px;
            right: 8px;
            background: #238636;
            border: none;
            color: white;
            width: 24px;
            height: 24px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            opacity: 0;
            transition: opacity 0.2s;
        }}

        .function-item:hover .add-btn {{
            opacity: 1;
        }}

        .add-btn:hover {{
            background: #2ea043;
        }}

        .middle-panel {{
            width: 320px;
            background: #161b22;
            border-right: 1px solid #30363d;
            display: flex;
            flex-direction: column;
        }}

        .payload-header {{
            background: #238636;
            color: white;
            padding: 12px 16px;
            font-weight: 600;
            font-size: 14px;
            text-align: center;
        }}

        .payload-container {{
            flex: 1;
            padding: 16px;
            display: flex;
            flex-direction: column;
        }}

        .payload-list {{
            flex: 1;
            background: #21262d;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 16px;
            overflow-y: auto;
            min-height: 200px;
        }}

        .payload-empty {{
            color: #6e7681;
            text-align: center;
            font-style: italic;
            margin-top: 50px;
        }}

        .payload-item {{
            background: #2d333b;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 12px;
            margin-bottom: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .xedit-id {{
            font-family: 'SF Mono', monospace;
            background: #30363d;
            color: #ff6b35;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }}

        .remove-btn {{
            background: #da3633;
            border: none;
            color: white;
            width: 20px;
            height: 20px;
            border-radius: 3px;
            cursor: pointer;
            font-size: 12px;
        }}

        .remove-btn:hover {{
            background: #f85149;
        }}

        .send-button {{
            width: 100%;
            background: #238636;
            border: none;
            color: white;
            padding: 15px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            margin-bottom: 15px;
        }}

        .send-button:hover:not(:disabled) {{
            background: #2ea043;
            transform: translateY(-2px);
        }}

        .send-button:disabled {{
            background: #30363d;
            color: #8b949e;
            cursor: not-allowed;
            transform: none;
        }}

        .deploy-section {{
            padding: 15px;
            background: rgba(46, 204, 113, 0.1);
            border: 1px solid #2ecc71;
            border-radius: 8px;
            margin-bottom: 15px;
        }}

        .deploy-title {{
            color: #2ecc71;
            margin-bottom: 10px;
            font-weight: 600;
        }}

        .deploy-info {{
            background: rgba(0,0,0,0.3);
            padding: 10px;
            border-radius: 6px;
            margin-bottom: 10px;
            font-family: monospace;
            font-size: 12px;
            color: #8b949e;
        }}

        .deploy-button {{
            width: 100%;
            padding: 12px;
            background: linear-gradient(45deg, #2ecc71, #27ae60);
            border: none;
            border-radius: 6px;
            color: white;
            font-weight: 600;
            cursor: pointer;
            margin-bottom: 8px;
        }}

        .deploy-button:hover {{
            background: linear-gradient(45deg, #27ae60, #219a52);
        }}

        .download-section {{
            padding: 15px;
            background: rgba(102, 126, 234, 0.1);
            border: 1px solid #667eea;
            border-radius: 8px;
        }}

        .download-title {{
            color: #667eea;
            margin-bottom: 10px;
            font-weight: 600;
        }}

        .download-button {{
            width: 100%;
            padding: 12px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            border: none;
            border-radius: 6px;
            color: white;
            font-weight: 600;
            cursor: pointer;
        }}

        .download-button:hover {{
            background: linear-gradient(45deg, #5a67d8, #6b46c1);
        }}

        .right-panel {{
            flex: 1;
            background: #0d1117;
            display: flex;
            flex-direction: column;
        }}

        .code-header {{
            background: #21262d;
            padding: 12px 16px;
            border-bottom: 1px solid #30363d;
            font-weight: 600;
            font-size: 13px;
            color: #f0883e;
        }}

        .code-container {{
            flex: 1;
            overflow: auto;
            padding: 16px;
        }}

        .code-content {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 16px;
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', monospace;
            font-size: 13px;
            line-height: 1.6;
        }}

        .code-line {{
            display: flex;
            min-height: 20px;
            transition: background-color 0.2s;
        }}

        .code-line:hover {{
            background: #21262d;
        }}

        .code-line.highlighted {{
            background: #2d333b;
            border-left: 3px solid #ff6b35;
            padding-left: 13px;
        }}

        .line-number {{
            color: #6e7681;
            user-select: none;
            margin-right: 16px;
            min-width: 30px;
            text-align: right;
        }}

        .line-content {{
            color: #e6edf3;
            flex: 1;
        }}

        ::-webkit-scrollbar {{
            width: 8px;
            height: 8px;
        }}

        ::-webkit-scrollbar-track {{
            background: #161b22;
        }}

        ::-webkit-scrollbar-thumb {{
            background: #30363d;
            border-radius: 4px;
        }}

        ::-webkit-scrollbar-thumb:hover {{
            background: #484f58;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="peacock-logo">🦚 Peacock XEdit Interface</div>
        <div class="nav-links">
            <a href="#" class="nav-link active">📝 XEdit</a>
            <a href="peacock_model_dashboard.html" class="nav-link">🤖 Models</a>
            <a href="peacock_download_interface.html" class="nav-link">📦 Download</a>
        </div>
        <div class="project-info">Project: {project_name} • {file_count} files</div>
    </div>

    <div class="main-container">
        <div class="left-panel">
            <div class="panel-header">📋 Functions & Classes</div>
            <div class="functions-list">
                {functions_html}
            </div>
        </div>

        <div class="middle-panel">
            <div class="payload-header">Payload</div>
            <div class="payload-container">
                <div class="payload-list" id="payload-list">
                    <div class="payload-empty">
                        Click functions to add XEdit-Paths
                    </div>
                </div>
                <button class="send-button" id="send-button" onclick="sendToLLM2()" disabled>
                    🚀 Send 0 to LLM2
                </button>
                
                <div class="deploy-section">
                    <div class="deploy-title">🚀 Deploy & Run</div>
                    <div class="deploy-info">
                        <strong>Generated:</strong> {project_name}<br>
                        <strong>Run command:</strong> python main.py
                    </div>
                    <button class="deploy-button" onclick="deployCode()">🔥 Deploy Code</button>
                </div>

                <div class="download-section">
                    <div class="download-title">📦 Download Package</div>
                    <button class="download-button" onclick="openDownloadInterface()">📥 Download ZIP</button>
                </div>
            </div>
        </div>

        <div class="right-panel">
            <div class="code-header">📁 {project_name}: main file</div>
            <div class="code-container">
                <div class="code-content">
                    {code_html}
                </div>
            </div>
        </div>
    </div>

    <script>
        const xeditPaths = {json.dumps(xedit_paths)};
        
        function deployCode() {{
            alert("🚀 Code ready to deploy!\\n\\nTo run your app:\\n1. Save the code to main.py\\n2. Run: python main.py\\n\\nFull deployment coming soon!");
        }}
        
        function openDownloadInterface() {{
            window.open("peacock_download_interface.html", "_blank");
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
                
                const firstHighlighted = document.querySelector('.code-line.highlighted');
                if (firstHighlighted) {{
                    firstHighlighted.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
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
            
            const payloadItem = document.createElement("div");
            payloadItem.className = "payload-item";
            payloadItem.id = `payload-${{xeditId}}`;
            payloadItem.innerHTML = `
                <span class="xedit-id">${{xeditId}}</span>
                <button class="remove-btn" onclick="removeFromPayload('${{xeditId}}')">&times;</button>
            `;
            
            payloadList.appendChild(payloadItem);
            
            const count = payloadList.children.length;
            sendButton.textContent = `🚀 Send ${{count}} to LLM2`;
            sendButton.disabled = false;
            
            const addBtn = event.target;
            const originalBg = addBtn.style.backgroundColor;
            const originalText = addBtn.innerHTML;
            addBtn.style.backgroundColor = '#2ea043';
            addBtn.innerHTML = '✓';
            setTimeout(() => {{
                addBtn.style.backgroundColor = originalBg;
                addBtn.innerHTML = originalText;
            }}, 1000);
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
                sendButton.textContent = "🚀 Send 0 to LLM2";
                sendButton.disabled = true;
            }} else {{
                sendButton.textContent = `🚀 Send ${{count}} to LLM2`;
            }}
        }}

        function sendToLLM2() {{
            const payloadItems = document.querySelectorAll('.payload-item');
            const xeditIds = Array.from(payloadItems).map(item => {{
                return item.querySelector('.xedit-id').textContent;
            }});
            
            console.log('Sending to LLM2:', xeditIds);
            alert(`🚀 Sending ${{xeditIds.length}} XEdit-Paths to LLM2: ${{xeditIds.join(', ')}}`);
            
            fetch('http://127.0.0.1:8000/process', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{
                    command: 'fix_xedit_paths',
                    xedit_paths: xeditIds,
                    language: 'python'
                }})
            }})
            .then(response => response.json())
            .then(data => console.log('MCP Response:', data))
            .catch(error => console.error('Error:', error));
        }}
    </script>
</body>
</html>
"""
    
    # Save to file and auto-open
    output_path = Path("peacock_xedit_interface.html")
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"✅ XEdit interface generated: {output_path}")
    
    # Auto-open in browser
    try:
        webbrowser.open(f"file://{output_path.absolute()}")
        print("🌐 Opened XEdit interface in browser")
    except Exception as e:
        print(f"⚠️  Could not auto-open browser: {e}")
    
    return str(output_path.absolute())

if __name__ == "__main__":
    sample_code = '''def main():
    print("Calculator started")'''
    
    html_output = generate_enhanced_html_interface(sample_code, "Calculator App", 1)
    print("🔥 XEdit interface with deploy button and download integration ready!")
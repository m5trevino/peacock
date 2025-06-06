#!/usr/bin/env python3
"""
Peacock Model Dashboard Generator with Chat Interface
"""

import json
import subprocess
import requests
import webbrowser
from datetime import datetime
from pathlib import Path

def check_ollama_status():
    """Check if Ollama is running and get models"""
    try:
        result = subprocess.run(["ollama", "list"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            models = []
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[0]
                        size = parts[1] if len(parts) > 1 else "Unknown"
                        models.append({"name": name, "size": size})
            return {"status": "online", "models": models}
    except Exception:
        pass
    return {"status": "offline", "models": []}

def check_lmstudio_status():
    """Check if LM Studio is running and get models"""
    try:
        response = requests.get("http://localhost:1234/v1/models", timeout=5)
        if response.status_code == 200:
            data = response.json()
            models = [{"name": model["id"], "size": "Unknown"} for model in data.get("data", [])]
            return {"status": "online", "models": models}
    except Exception:
        pass
    return {"status": "offline", "models": []}

def get_api_status():
    """Get API key status for online providers"""
    api_keys = {
        "groq": "gsk_**********435",  # Masked example
        "google": "",  # Empty means not set
        "deepseek": "sk_**********789"  # Masked example
    }
    
    return {
        "groq": {"status": "online" if api_keys["groq"] else "offline", "key": api_keys["groq"]},
        "google": {"status": "offline" if not api_keys["google"] else "online", "key": api_keys["google"]},
        "deepseek": {"status": "online" if api_keys["deepseek"] else "offline", "key": api_keys["deepseek"]}
    }

def generate_model_dashboard():
    """Generate the model dashboard with chat interface"""
    
    # Get current status
    ollama_data = check_ollama_status()
    lmstudio_data = check_lmstudio_status()
    api_data = get_api_status()
    
    # Generate Ollama models HTML
    ollama_models_html = ""
    for model in ollama_data["models"]:
        size_class = "small" if "small" in model["name"] else "medium" if any(x in model["name"] for x in ["7b", "8b"]) else "large"
        ollama_models_html += f"""
        <div class="model-item {size_class}" onclick="selectModel('ollama', '{model["name"]}')">
            <div class="model-info">
                <span class="model-name">{model["name"]}</span>
                <span class="model-size">{model["size"]}</span>
            </div>
            <div class="model-status-indicator"></div>
        </div>"""

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🦚 Peacock Model Dashboard</title>
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

        .dashboard-info {{
            color: #8b949e;
            font-size: 14px;
        }}

        .nav-container {{
            background: #161b22;
            border-bottom: 1px solid #30363d;
            padding: 16px 20px;
            display: flex;
            gap: 16px;
            justify-content: center;
        }}

        .nav-btn {{
            background: #21262d;
            border: 2px solid #30363d;
            color: #e6edf3;
            padding: 12px 24px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .nav-btn:hover {{
            border-color: #ff6b35;
            background: #2d333b;
            transform: translateY(-2px);
        }}

        .nav-btn.active {{
            background: #ff6b35;
            border-color: #ff6b35;
            color: #0d1117;
        }}

        .status-bar {{
            background: #161b22;
            border-bottom: 1px solid #30363d;
            padding: 12px 20px;
            display: flex;
            gap: 24px;
            align-items: center;
        }}

        .status-item {{
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 13px;
        }}

        .status-indicator {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }}

        .status-online {{
            background: #238636;
        }}

        .status-offline {{
            background: #da3633;
        }}

        .status-ip {{
            color: #8b949e;
            font-family: 'SF Mono', monospace;
        }}

        .main-container {{
            display: flex;
            height: calc(100vh - 200px);
        }}

        .left-panel {{
            width: 450px;
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
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .models-list {{
            flex: 1;
            overflow-y: auto;
            padding: 8px;
        }}

        .model-item {{
            background: #21262d;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 12px;
            margin-bottom: 8px;
            cursor: pointer;
            transition: all 0.2s;
            position: relative;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .model-item:hover {{
            border-color: #ff6b35;
            background: #2d333b;
            transform: translateX(3px);
        }}

        .model-item.selected {{
            border-color: #ff6b35;
            background: #2d333b;
            box-shadow: 0 0 0 1px #ff6b35;
        }}

        .model-info {{
            display: flex;
            flex-direction: column;
            gap: 4px;
        }}

        .model-name {{
            font-weight: 600;
            color: #79c0ff;
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 13px;
        }}

        .model-size {{
            background: #30363d;
            color: #8b949e;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 10px;
            text-transform: uppercase;
            width: fit-content;
        }}

        .model-status-indicator {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #238636;
        }}

        .model-item.small .model-size {{
            background: #238636;
            color: white;
        }}

        .model-item.medium .model-size {{
            background: #f0883e;
            color: white;
        }}

        .model-item.large .model-size {{
            background: #da3633;
            color: white;
        }}

        .right-panel {{
            flex: 1;
            background: #0d1117;
            display: flex;
            flex-direction: column;
        }}

        .api-header {{
            background: #21262d;
            padding: 12px 16px;
            border-bottom: 1px solid #30363d;
            font-weight: 600;
            font-size: 13px;
            color: #f0883e;
        }}

        .api-container {{
            flex: 1;
            padding: 16px;
            overflow-y: auto;
        }}

        .api-provider {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            margin-bottom: 16px;
            overflow: hidden;
        }}

        .api-provider-header {{
            background: #21262d;
            padding: 12px 16px;
            border-bottom: 1px solid #30363d;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .provider-name {{
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .api-key-status {{
            display: flex;
            align-items: center;
            gap: 8px;
            font-family: 'SF Mono', monospace;
            font-size: 12px;
        }}

        .api-key-value {{
            color: #8b949e;
        }}

        .api-key-status.online .api-key-value {{
            color: #238636;
        }}

        .api-key-status.offline .api-key-value {{
            color: #da3633;
        }}

        .system-resources {{
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: #161b22;
            border-top: 1px solid #30363d;
            padding: 12px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .resource-group {{
            display: flex;
            align-items: center;
            gap: 16px;
        }}

        .resource-item {{
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 12px;
        }}

        .resource-bar {{
            width: 100px;
            height: 6px;
            background: #30363d;
            border-radius: 3px;
            overflow: hidden;
        }}

        .resource-fill {{
            height: 100%;
            background: linear-gradient(90deg, #238636, #2ea043);
            transition: width 0.3s;
        }}

        .resource-fill.high {{
            background: linear-gradient(90deg, #f0883e, #fb8500);
        }}

        .resource-fill.critical {{
            background: linear-gradient(90deg, #da3633, #f85149);
        }}

        .control-panel {{
            background: #21262d;
            border-top: 1px solid #30363d;
            padding: 16px;
            display: flex;
            gap: 12px;
            justify-content: center;
        }}

        .control-btn {{
            background: #238636;
            border: none;
            color: white;
            padding: 12px 24px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }}

        .control-btn:hover {{
            background: #2ea043;
            transform: translateY(-2px);
        }}

        .control-btn:disabled {{
            background: #30363d;
            color: #8b949e;
            cursor: not-allowed;
            transform: none;
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
        <div class="peacock-logo">🦚 Peacock Model Dashboard</div>
        <div class="nav-links">
            <a href="peacock_xedit_interface.html" class="nav-link">📝 XEdit</a>
            <a href="#" class="nav-link active">🤖 Models</a>
            <a href="#" class="nav-link">💬 Senior Dev</a>
        </div>
        <div class="dashboard-info">AI Model Management • System Resources</div>
    </div>

    <div class="nav-container">
        <button class="nav-btn active" onclick="switchProvider('ollama')">OLLAMA</button>
        <button class="nav-btn" onclick="switchProvider('lmstudio')">LM STUDIO</button>
        <button class="nav-btn" onclick="switchProvider('api')">API MODELS</button>
    </div>

    <div class="status-bar">
        <div class="status-item">
            <div class="status-indicator {'status-online' if ollama_data['status'] == 'online' else 'status-offline'}"></div>
            <span>Ollama Server</span>
            <span class="status-ip">127.0.0.1:11434</span>
        </div>
        <div class="status-item">
            <div class="status-indicator {'status-online' if lmstudio_data['status'] == 'online' else 'status-offline'}"></div>
            <span>LM Studio Server</span>
            <span class="status-ip">127.0.0.1:1234</span>
        </div>
    </div>

    <div class="main-container">
        <div class="left-panel">
            <div class="panel-header">
                <span id="panel-title">📦 OLLAMA MODELS</span>
                <span id="model-count">{len(ollama_data['models'])} models</span>
            </div>
            <div class="models-list" id="models-list">
                {ollama_models_html}
            </div>
            <div class="control-panel">
                <button class="control-btn" id="load-btn" onclick="loadSelectedModel()" disabled>🚀 Load Model</button>
                <button class="control-btn" onclick="refreshModels()">🔄 Refresh</button>
            </div>
        </div>

        <div class="right-panel">
            <div class="api-header" id="right-panel-header">💬 ONE-PROMPT BUILD</div>
            <div class="api-container" id="api-container">
                <!-- Chat Interface for One-Prompt Build -->
                <div style="margin-bottom: 30px; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 20px;">
                    <h3 style="color: #00d4ff; margin-bottom: 15px; font-size: 1.2rem;">💬 One-Prompt Build</h3>
                    <div style="display: flex; gap: 10px; margin-bottom: 15px;">
                        <input type="text" id="chat-input" placeholder="Build a snake game..." 
                               style="flex: 1; padding: 12px; background: rgba(0,0,0,0.3); border: 1px solid #00d4ff; border-radius: 8px; color: #e0e6ed; font-size: 16px;" />
                        <button onclick="sendToPeacock()" 
                                style="padding: 12px 24px; background: linear-gradient(45deg, #00d4ff, #0099cc); border: none; border-radius: 8px; color: white; font-weight: 600; cursor: pointer;">Send to LLM2</button>
                    </div>
                    <div id="chat-messages" style="background: rgba(0,0,0,0.2); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; padding: 15px; height: 200px; overflow-y: auto; margin-bottom: 15px; font-family: monospace; font-size: 14px;">
                        <div style="color: #8b949e; font-style: italic;">🦚 Ready to build! Using GROQ qwen-qwq-32b model...</div>
                    </div>
                    <button onclick="openXEditInterface()" 
                            style="width: 100%; padding: 15px; background: linear-gradient(45deg, #2ecc71, #27ae60); border: none; border-radius: 8px; color: white; font-weight: 600; cursor: pointer;">🎯 Open XEdit Interface</button>
                </div>
                
                <!-- API Providers Section -->
                <div class="api-provider">
                    <div class="api-provider-header">
                        <span class="provider-name">Groq</span>
                        <div class="api-key-status online">
                            <span>groq:</span>
                            <span class="api-key-value">{api_data['groq']['key'] if api_data['groq']['key'] else '_______________'}</span>
                        </div>
                    </div>
                </div>
                <div class="api-provider">
                    <div class="api-provider-header">
                        <span class="provider-name">Google</span>
                        <div class="api-key-status offline">
                            <span>google:</span>
                            <span class="api-key-value">_______________</span>
                        </div>
                    </div>
                </div>
                <div class="api-provider">
                    <div class="api-provider-header">
                        <span class="provider-name">DeepSeek</span>
                        <div class="api-key-status online">
                            <span>deepseek:</span>
                            <span class="api-key-value">sk_**********789</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="system-resources">
        <div class="resource-group">
            <div class="resource-item">
                <span>🎮 GPU Memory</span>
                <div class="resource-bar">
                    <div class="resource-fill" style="width: 50%"></div>
                </div>
                <span>6.2GB / 24GB</span>
            </div>
            <div class="resource-item">
                <span>🧠 CPU Usage</span>
                <div class="resource-bar">
                    <div class="resource-fill" style="width: 15%"></div>
                </div>
                <span>15%</span>
            </div>
        </div>
        <div class="resource-group">
            <div class="resource-item">
                <span>💾 RAM Usage</span>
                <div class="resource-bar">
                    <div class="resource-fill high" style="width: 75%"></div>
                </div>
                <span>24GB / 32GB</span>
            </div>
        </div>
    </div>

    <script>
        let selectedModel = null;
        let currentProvider = 'ollama';
        
        const modelData = {{
            'ollama': {json.dumps(ollama_data['models'])},
            'lmstudio': [],
            'api': []
        }};

        // Chat functionality for One-Prompt Build
        async function sendToPeacock() {{
            const input = document.getElementById("chat-input");
            const messages = document.getElementById("chat-messages");
            const prompt = input.value.trim();
            
            if (!prompt) return;
            
            // Add user message
            messages.innerHTML += `<div style="margin-bottom: 10px; padding: 8px; background: rgba(0, 212, 255, 0.1); border-left: 3px solid #00d4ff; border-radius: 6px;">👤 ${{prompt}}</div>`;
            input.value = "";
            
            // Add loading message
            messages.innerHTML += `<div style="margin-bottom: 10px; padding: 8px; background: rgba(255, 107, 107, 0.1); border-left: 3px solid #ff6b6b; border-radius: 6px;">🦚 Generating code with GROQ qwen-qwq-32b...</div>`;
            messages.scrollTop = messages.scrollHeight;
            
            try {{
                // Use the EXACT same payload as your working command line
                const response = await fetch("http://127.0.0.1:8000/process", {{
                    method: "POST",
                    headers: {{"Content-Type": "application/json"}},
                    body: JSON.stringify({{
                        command: "peacock_full",
                        text: prompt,
                        language: "project_analysis",
                        original_request: prompt
                    }})
                }});
                
                const result = await response.json();
                
                if (result.status === "success") {{
                    messages.innerHTML += `<div style="margin-bottom: 10px; padding: 8px; background: rgba(46, 204, 113, 0.1); border-left: 3px solid #2ecc71; border-radius: 6px;">✅ Code generated with GROQ qwen-qwq-32b! <button onclick="openXEditInterface()" style="background: #2ecc71; border: none; color: white; padding: 4px 8px; border-radius: 4px; margin-left: 8px; cursor: pointer;">Open XEdit</button></div>`;
                }} else {{
                    messages.innerHTML += `<div style="margin-bottom: 10px; padding: 8px; background: rgba(231, 76, 60, 0.1); border-left: 3px solid #e74c3c; border-radius: 6px;">❌ Error: ${{result.message}}</div>`;
                }}
            }} catch (error) {{
                messages.innerHTML += `<div style="margin-bottom: 10px; padding: 8px; background: rgba(231, 76, 60, 0.1); border-left: 3px solid #e74c3c; border-radius: 6px;">❌ Connection error: ${{error.message}}</div>`;
            }}
            
            messages.scrollTop = messages.scrollHeight;
        }}
        
        // Open XEdit interface
        function openXEditInterface() {{
            window.open("file:///home/flintx/peacock/html/reports/peacock_xedit_interface.html", "_blank");
        }}
        
        // Handle Enter key in chat input
        document.addEventListener("DOMContentLoaded", function() {{
            const chatInput = document.getElementById("chat-input");
            if (chatInput) {{
                chatInput.addEventListener("keypress", function(e) {{
                    if (e.key === "Enter") {{
                        sendToPeacock();
                    }}
                }});
            }}
        }});

        function switchProvider(provider) {{
            currentProvider = provider;
            
            document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            
            const panelTitle = document.getElementById('panel-title');
            const modelCount = document.getElementById('model-count');
            const modelsList = document.getElementById('models-list');
            
            if (provider === 'ollama') {{
                panelTitle.textContent = '📦 OLLAMA MODELS';
                modelCount.textContent = `${{modelData.ollama.length}} models`;
                modelsList.innerHTML = generateModelsHTML('ollama');
            }} else {{
                panelTitle.textContent = `🔧 ${{provider.toUpperCase()}} MODELS`;
                modelCount.textContent = '0 models';
                modelsList.innerHTML = '<div style="padding: 40px; text-align: center; color: #8b949e;">Coming soon...</div>';
            }}
            
            selectedModel = null;
            document.getElementById('load-btn').disabled = true;
        }}

        function generateModelsHTML(provider) {{
            const models = modelData[provider];
            if (!models || models.length === 0) {{
                return '<div style="padding: 40px; text-align: center; color: #8b949e;">No models available</div>';
            }}
            
            return models.map(model => {{
                const sizeClass = model.name.includes('small') ? 'small' : 
                                 (model.name.includes('7b') || model.name.includes('8b')) ? 'medium' : 'large';
                return `
                    <div class="model-item ${{sizeClass}}" onclick="selectModel('${{provider}}', '${{model.name}}')">
                        <div class="model-info">
                            <span class="model-name">${{model.name}}</span>
                            <span class="model-size">${{model.size}}</span>
                        </div>
                        <div class="model-status-indicator"></div>
                    </div>`;
            }}).join('');
        }}

        function selectModel(provider, modelName) {{
            selectedModel = {{ provider, name: modelName }};
            
            document.querySelectorAll('.model-item').forEach(item => item.classList.remove('selected'));
            event.currentTarget.classList.add('selected');
            
            document.getElementById('load-btn').disabled = false;
            document.getElementById('load-btn').textContent = `🚀 Load ${{modelName.split(':')[0]}}`;
        }}

        function loadSelectedModel() {{
            if (!selectedModel) return;
            
            console.log('Loading model:', selectedModel);
            alert(`🚀 Loading ${{selectedModel.name}} from ${{selectedModel.provider}}`);
        }}

        function refreshModels() {{
            console.log('Refreshing models for', currentProvider);
            alert(`🔄 Refreshing ${{currentProvider}} models...`);
        }}

        setInterval(updateResourceUsage, 2000);

        function updateResourceUsage() {{
            const fills = document.querySelectorAll('.resource-fill');
            fills.forEach((fill, index) => {{
                const newWidth = Math.random() * 100;
                fill.style.width = newWidth + '%';
                if (newWidth > 80) {{
                    fill.className = 'resource-fill critical';
                }} else if (newWidth > 60) {{
                    fill.className = 'resource-fill high';
                }} else {{
                    fill.className = 'resource-fill';
                }}
            }});
        }}
    </script>
</body>
</html>
"""
    
    # Save to reports directory (where MCP server expects it)
    reports_dir = Path(__file__).parent.parent / "html" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    output_path = reports_dir / "peacock_model_dashboard.html"
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"✅ Model Dashboard with chat interface generated: {output_path}")
    
    # Auto-open in browser
    try:
        webbrowser.open(f"file://{output_path.absolute()}")
        print("🌐 Opened Model Dashboard in browser")
    except Exception as e:
        print(f"⚠️  Could not auto-open browser: {e}")
    
    return str(output_path.absolute())

if __name__ == "__main__":
    html_output = generate_model_dashboard()
    print("🔥 Model Dashboard with chat interface ready!")

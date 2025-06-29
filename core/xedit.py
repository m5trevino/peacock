
#!/usr/bin/env python3
"""
🦚 XEDIT - ENHANCED PEACOCK CODE INTERFACE GENERATOR 
Enhanced for Qwen+Llama compatibility and .pcock deployment
"""

import json
import re
import datetime
import os
import sys
import argparse
from typing import Dict, List, Any, Optional
from pathlib import Path

class EnhancedXEditGenerator:
    """Enhanced XEdit generator with Qwen/Llama support and PCOCK deployment"""
    
    def __init__(self):
        self.html_dir = "/home/flintx/peacock/core/html"
        self.apps_dir = "/home/flintx/peacock/apps"
        os.makedirs(self.html_dir, exist_ok=True)
        os.makedirs(self.apps_dir, exist_ok=True)

    def generate_enhanced_xedit_html(self, parsed_data: Dict[str, Any], xedit_paths: Dict[str, Dict[str, Any]], session_id: str) -> str:
        """Generate enhanced XEdit HTML with PCOCK deployment"""
        
        project_name = parsed_data.get("project_name", "Generated Project")
        model_used = parsed_data.get("model_used", "unknown")
        model_type = parsed_data.get("model_type", "unknown")
        code_files = parsed_data.get("code_files", [])
        
        # Generate functions list HTML
        functions_html = self._generate_functions_html(xedit_paths)
        
        # Generate combined code HTML
        code_html = self._generate_code_html(code_files)
        
        # Generate main HTML with FIXED JavaScript syntax
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🦚 XEdit - {project_name}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Courier New', monospace;
            background: #0a0a0a;
            color: #00ff00;
            overflow: hidden;
        }}
        
        .xedit-container {{
            display: flex;
            height: 100vh;
            border: 2px solid #00ff00;
        }}
        
        .left-panel {{
            width: 25%;
            background: #1a1a1a;
            border-right: 1px solid #00ff00;
            padding: 10px;
            overflow-y: auto;
        }}
        
        .center-panel {{
            width: 50%;
            background: #0f0f0f;
            padding: 10px;
            overflow-y: auto;
            border-right: 1px solid #00ff00;
        }}
        
        .right-panel {{
            width: 25%;
            background: #1a1a1a;
            padding: 10px;
            overflow-y: auto;
        }}
        
        .panel-header {{
            color: #00ffff;
            font-weight: bold;
            margin-bottom: 10px;
            padding: 5px;
            background: #333;
            border: 1px solid #00ff00;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .model-indicator {{
            font-size: 0.8em;
            color: #ffff00;
            background: #444;
            padding: 2px 8px;
            border-radius: 3px;
        }}
        
        .function-item, .class-item {{
            padding: 8px;
            margin: 3px 0;
            background: #2a2a2a;
            border: 1px solid #444;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
        }}
        
        .function-item:hover, .class-item:hover {{
            background: #00ff00;
            color: #000;
            border-color: #00ff00;
        }}
        
        .function-item:hover .hover-button, .class-item:hover .hover-button {{
            display: inline-block;
        }}
        
        .hover-button {{
            display: none;
            position: absolute;
            right: 5px;
            top: 50%;
            transform: translateY(-50%);
            background: #ff6600;
            color: white;
            border: none;
            padding: 2px 6px;
            font-size: 0.7em;

            cursor: pointer;
            border-radius: 2px;
        }}
        
        .hover-button:hover {{
            background: #ff8800;
        }}
        
        .function-icon {{
            color: #ff6600;
            margin-right: 8px;
        }}
        
        .class-icon {{
            color: #6600ff;
            margin-right: 8px;
        }}
        
        .code-display {{
            background: #000;
            color: #00ff00;
            padding: 15px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            line-height: 1.4;
            white-space: pre-wrap;
            border: 1px solid #333;
            border-radius: 4px;
            max-height: calc(100vh - 200px);
            overflow-y: auto;
        }}
        
        .highlighted {{
            background: #004400 !important;
            border-color: #00ff00 !important;
        }}
        
        .payload-section {{
            background: #2a2a2a;
            border: 1px solid #444;
            padding: 10px;
            margin: 5px 0;
            border-radius: 4px;
        }}
        
        .payload-item {{
            background: #333;
            color: #ffff00;
            padding: 8px;
            margin: 5px 0;
            border-radius: 3px;
            font-size: 0.9em;
        }}
        
        .pcock-deploy-btn {{
            background: linear-gradient(45deg, #00ff00, #00cc00);
            color: #000;
            border: none;
            padding: 12px 20px;
            font-weight: bold;
            font-family: 'Courier New', monospace;
            cursor: pointer;
            border-radius: 5px;
            margin: 10px 0;
            width: 100%;
            transition: all 0.3s ease;
        }}
        
        .pcock-deploy-btn:hover {{
            background: linear-gradient(45deg, #00cc00, #009900);
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 255, 0, 0.3);
        }}
        
        .status-indicator {{
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 0.8em;
            margin-left: 10px;
        }}
        
        .status-success {{
            background: #00ff00;
            color: #000;
        }}
        
        .status-qwen {{
            background: #ff6600;
            color: white;
        }}
        
        .status-llama {{
            background: #0066ff;
            color: white;
        }}
    </style>
</head>
<body>
    <div class="xedit-container">
        <!-- LEFT PANEL: Functions & Classes -->
        <div class="left-panel">
            <div class="panel-header">
                🔧 Functions & Classes
                <span class="model-indicator">{model_type.upper()}</span>
            </div>
            {functions_html}
            
            <div class="panel-header" style="margin-top: 20px;">
                🚀 Deploy
            </div>
            <button class="pcock-deploy-btn" onclick="deployToPcock()">
                🦚 PCOCK Deploy
            </button>
            <div id="deploy-status"></div>
        </div>
        
        <!-- CENTER PANEL: Code Display -->
        <div class="center-panel">
            <div class="panel-header">
                💻 Generated Code
                <span class="status-indicator status-{model_type}">{model_used}</span>
            </div>
            <div class="code-display" id="code-display">
{code_html}
            </div>
        </div>
        
        <!-- RIGHT PANEL: Payload -->
        <div class="right-panel">
            <div class="panel-header">
                🎯 Payload
            </div>
            <div class="payload-section">
                <div class="payload-item">
                    <strong>Project:</strong> {project_name}
                </div>
                <div class="payload-item">
                    <strong>Session:</strong> {session_id}
                </div>
                <div class="payload-item">

                    <strong>Model:</strong> {model_used}
                </div>
                <div class="payload-item">
                    <strong>Files:</strong> {len(code_files)}
                </div>
            </div>
            
            <div class="panel-header" style="margin-top: 10px;">
                ⚠️ Issues
            </div>
            <div id="payload-issues">
                <div style="color: #666; text-align: center; padding: 20px;">
                    No issues detected
                </div>
            </div>
        </div>
    </div>
    
    <script>
        /* XEdit navigation paths */
        const xeditPaths = {json.dumps(xedit_paths, indent=2)};
        
        /* Project data for deployment */
        const projectData = {json.dumps(parsed_data, indent=2)};
        
        function highlightFunction(xeditId) {{
            /* Remove existing highlights */
            document.querySelectorAll('.function-item, .class-item').forEach(item => {{
                item.classList.remove('highlighted');
            }});
            
            /* Highlight selected item */
            event.target.closest('.function-item, .class-item').classList.add('highlighted');
            
            /* Get path data */
            const pathData = xeditPaths[xeditId];
            if (!pathData) return;
            
            /* Scroll to function in code display */
            const codeDisplay = document.getElementById('code-display');
            const lines = codeDisplay.textContent.split('\n');
            const targetLine = pathData.line_start - 1;
            
            if (targetLine >= 0 && targetLine < lines.length) {{
                /* Create temporary element to measure line height */
                const tempDiv = document.createElement('div');
                tempDiv.style.font = window.getComputedStyle(codeDisplay).font;
                tempDiv.style.position = 'absolute';
                tempDiv.style.visibility = 'hidden';
                tempDiv.textContent = 'A';
                document.body.appendChild(tempDiv);
                const lineHeight = tempDiv.offsetHeight;
                document.body.removeChild(tempDiv);
                
                /* Scroll to target line */
                codeDisplay.scrollTop = targetLine * lineHeight;
                
                /* Flash highlight effect */
                codeDisplay.style.transition = 'background-color 0.3s ease';
                codeDisplay.style.backgroundColor = '#004400';
                setTimeout(() => {{
                    codeDisplay.style.backgroundColor = '#000';
                }}, 300);
            }}
        }}
        
        function addToPayload(functionName, issue) {{
            const payloadIssues = document.getElementById('payload-issues');
            
            /* Remove "no issues" message */
            if (payloadIssues.textContent.includes('No issues detected')) {{
                payloadIssues.innerHTML = '';
            }}
            
            /* Add new issue */
            const issueDiv = document.createElement('div');
            issueDiv.className = 'payload-item';
            issueDiv.innerHTML = `
                <strong>${{functionName}}:</strong><br>
                ${{issue}}
                <button style="float: right; background: #ff0000; color: white; border: none; padding: 2px 6px; cursor: pointer;" onclick="this.parentElement.remove()">×</button>
            `;
            payloadIssues.appendChild(issueDiv);
        }}
        
        function deployToPcock() {{
            const deployBtn = document.querySelector('.pcock-deploy-btn');
            const deployStatus = document.getElementById('deploy-status');
            
            /* Show loading state */
            deployBtn.disabled = true;
            deployBtn.textContent = '🔄 Deploying...';
            deployStatus.innerHTML = '<div style="color: #ffff00;">Preparing deployment...</div>';
            
            /* Prepare deployment data */
            const deploymentData = {{
                project_name: projectData.project_name,
                session_id: '{session_id}',
                code_files: projectData.code_files,
                timestamp: new Date().toISOString()
            }};
            
            /* Call deployment API */
            fetch('/api/deploy', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json'
                }},
                body: JSON.stringify(deploymentData)
            }})
            .then(response => response.json())
            .then(data => {{
                if (data.success) {{
                    deployBtn.textContent = '✅ Deployed!';
                    deployBtn.style.background = 'linear-gradient(45deg, #00ff00, #00cc00)';
                    deployStatus.innerHTML = `
                        <div style="color: #00ff00;">
                            ✅ Deployment successful!<br>
                            📦 .pcock file created<br>
                            🌐 <a href="${{data.app_url}}" target="_blank" style="color: #00ffff;">Open App</a>
                        </div>
                    `;
                    
                    /* Auto-open app if requested */
                    if (data.app_url) {{
                        setTimeout(() => {{
                            window.open(data.app_url, '_blank');
                        }}, 1000);
                    }}
                }} else {{
                    throw new Error(data.error || 'Deployment failed');
                }}
            }})
            .catch(error => {{
                deployBtn.textContent = '❌ Deploy Failed';
                deployBtn.style.background = 'linear-gradient(45deg, #ff0000, #cc0000)';
                deployStatus.innerHTML = `
                    <div style="color: #ff0000;">
                        ❌ Deployment failed:<br>

                        ${{error.message}}
                    </div>
                `;
            }})
            .finally(() => {{
                deployBtn.disabled = false;
                setTimeout(() => {{
                    deployBtn.textContent = '🦚 PCOCK Deploy';
                    deployBtn.style.background = 'linear-gradient(45deg, #00ff00, #00cc00)';
                }}, 3000);
            }});
        }}
        
        /* Initialize page */
        document.addEventListener('DOMContentLoaded', function() {{
            console.log('🦚 XEdit Enhanced Interface Loaded');
            console.log('Model Type:', '{model_type}');
            console.log('XEdit Paths:', Object.keys(xeditPaths).length);
        }});
    </script>
</body>
</html>"""
        
        # Save HTML file
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        html_filename = f"xedit-{session_id}-{timestamp}.html"
        html_filepath = os.path.join(self.html_dir, html_filename)
        
        with open(html_filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ Enhanced XEdit HTML generated: {html_filepath}")
        return html_filepath

    def _generate_functions_html(self, xedit_paths: Dict[str, Dict[str, Any]]) -> str:
        """Generate HTML for functions and classes list"""
        
        if not xedit_paths:
            return '<div style="color: #666; text-align: center; padding: 20px;">No functions found</div>'
        
        functions_html = ""
        
        # Group by type
        functions = {k: v for k, v in xedit_paths.items() if v["type"] == "function"}
        classes = {k: v for k, v in xedit_paths.items() if v["type"] == "class"}
        
        # Functions section
        if functions:
            functions_html += '<div style="margin-bottom: 15px;"><strong style="color: #ff6600;">⚡ Functions:</strong></div>'
            for xedit_id, data in functions.items():
                functions_html += f'''
                <div class="function-item" onclick="highlightFunction('{xedit_id}')">
                    <span class="function-icon">⚡</span>
                    <strong>{data["display_name"]}</strong>
                    <div style="font-size: 0.8em; color: #888; margin-top: 3px;">
                        {data["filename"]} • Lines {data["lines_display"]}
                    </div>
                    <button class="hover-button" onclick="event.stopPropagation(); addToPayload('{data['display_name']}', 'Function needs review')">+</button>
                </div>
                '''
        
        # Classes section  
        if classes:
            functions_html += '<div style="margin: 15px 0;"><strong style="color: #6600ff;">🏗️ Classes:</strong></div>'
            for xedit_id, data in classes.items():
                functions_html += f'''
                <div class="class-item" onclick="highlightFunction('{xedit_id}')">
                    <span class="class-icon">🏗️</span>
                    <strong>{data["display_name"]}</strong>
                    <div style="font-size: 0.8em; color: #888; margin-top: 3px;">
                        {data["filename"]} • Lines {data["lines_display"]}
                    </div>
                    <button class="hover-button" onclick="event.stopPropagation(); addToPayload('{data['display_name']}', 'Class needs review')">+</button>
                </div>
                '''
        
        return functions_html

    def _generate_code_html(self, code_files: List[Dict[str, Any]]) -> str:
        """Generate HTML for code display"""
        
        if not code_files:
            return "No code files found"
        
        code_html = ""
        
        for i, file_data in enumerate(code_files):
            # Add file separator
            if i > 0:
                code_html += "\n" + "="*80 + "\n"
            
            # Add file header
            code_html += f"// FILE: {file_data['filename']} ({file_data['language']})\n"
            code_html += "//" + "="*78 + "\n\n"
            
            # Add code content with line numbers
            lines = file_data['code'].split('\n')
            for line_num, line in enumerate(lines, 1):
                code_html += f"{line_num:4d} | {line}\n"
            
            code_html += "\n"
        
        return code_html

def main():
    """Main entry point for enhanced XEdit generation"""
    parser = argparse.ArgumentParser(description='Enhanced XEdit Generator')
    parser.add_argument('--data-file', required=True, help='Path to JSON data file')
    parser.add_argument('--session-id', required=True, help='Session ID')
    
    args = parser.parse_args()
    
    # Load data
    try:
        with open(args.data_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        parsed_data = data['parsed_data']
        xedit_paths = data['xedit_paths']
        
    except Exception as e:
        print(json.dumps({"success": False, "error": f"Failed to load data: {e}"}))
        return
    
    # Generate XEdit interface
    try:
        generator = EnhancedXEditGenerator()
        xedit_file = generator.generate_enhanced_xedit_html(parsed_data, xedit_paths, args.session_id)
        
        print(json.dumps({
            "success": True,
            "xedit_file": xedit_file,
            "message": "Enhanced XEdit interface generated successfully"
        }))
        
    except Exception as e:
        print(json.dumps({"success": False, "error": f"XEdit generation failed: {e}"}))

if __name__ == "__main__":
    main()

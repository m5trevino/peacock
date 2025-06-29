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
        self.html_dir = "/home/flintx/peacock/html"
        self.apps_dir = "/home/flintx/peacock/apps"
        os.makedirs(self.html_dir, exist_ok=True)
        os.makedirs(self.apps_dir, exist_ok=True)

    def generate_enhanced_xedit_html(self, parsed_data: Dict[str, Any], xedit_paths: Dict[str, Dict[str, Any]], session_id: str) -> str:
        """Generate enhanced XEdit HTML with PCOCK deployment"""
        
        project_name = parsed_data.get("project_name", "Generated Project")
        model_used = parsed_data.get("model_used", "unknown")
        model_type = self._get_model_type(model_used)
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
        
        .code-line {{
            display: flex;
        }}
        
        .code-line.highlight {{
            background-color: #004400;
        }}
        
        .line-number {{
            color: #666;
            margin-right: 10px;
            user-select: none;
            min-width: 30px;
            text-align: right;
        }}
        
        .line-content {{
            flex: 1;
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
            
            /* Clear previous highlights */
            document.querySelectorAll('.code-line').forEach(line => {{
                line.classList.remove('highlight');
            }});
            
            /* Highlight the code lines */
            const lineStart = parseInt(pathData.line_start || 1);
            const lineEnd = parseInt(pathData.line_end || lineStart + 10);
            
            for (let i = lineStart; i <= lineEnd; i++) {{
                const lineElement = document.querySelector(`.code-line[data-line="${i}"]`);
                if (lineElement) {{
                    lineElement.classList.add('highlight');
                    
                    /* Scroll to the first highlighted line */
                    if (i === lineStart) {{
                        lineElement.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
                    }}
                }}
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
                project_name: projectData.project_name || "Peacock Project",
                session_id: '{session_id}',
                project_files: projectData.code_files || [],
                timestamp: new Date().toISOString()
            }};
            
            /* Call deployment API */
            fetch('http://127.0.0.1:8000/deploy', {{
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
        html_filename = f"xedit-{session_id}.html"
        html_filepath = os.path.join(self.html_dir, html_filename)
        
        with open(html_filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ Enhanced XEdit HTML generated: {html_filepath}")
        return html_filepath

    def _get_model_type(self, model_name: str) -> str:
        """Determine model type from model name"""
        model_name = model_name.lower()
        if "qwen" in model_name:
            return "qwen"
        elif "llama" in model_name:
            return "llama"
        elif "gemma" in model_name:
            return "gemma"
        else:
            return "unknown"

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
        """Generate HTML for code display with line numbers and data attributes for highlighting"""
        
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
            
            # Add code content with line numbers and data attributes
            lines = file_data['code'].split('\n')
            for line_num, line in enumerate(lines, 1):
                # Escape HTML characters
                escaped_line = line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                code_html += f'<div class="code-line" data-line="{line_num}"><span class="line-number">{line_num}</span><span class="line-content">{escaped_line}</span></div>\n'
            
            code_html += "\n"
        
        return code_html

def get_session_timestamp():
    """Generate session timestamp in week-day-hourminute format"""
    now = datetime.datetime.now()
    week = now.isocalendar()[1]
    day = now.day
    hour_minute = now.strftime("%H%M")
    return f"{week}-{day}-{hour_minute}"

class PeacockResponseParser:
    """Parse LLM responses into structured content for XEdit generation"""
    
    def __init__(self):
        self.session_timestamp = get_session_timestamp()
        
    def parse_llm_response(self, response_text: str, project_name: str = "Generated Project") -> Dict[str, Any]:
        """Main parsing function - converts raw LLM response to structured data"""
        parsed_data = {
            "project_name": project_name,
            "session_timestamp": self.session_timestamp,
            "code_files": self._extract_code_files(response_text),
            "parsing_success": True
        }
        return parsed_data
    
    def _extract_code_files(self, text: str) -> List[Dict[str, Any]]:
        """Extract code files from response"""
        code_files = []
        
        # First try to find filename-based code blocks
        filename_pattern = r'```filename:\s*([^\n]+)\n(.*?)\n```'
        filename_matches = re.findall(filename_pattern, text, re.DOTALL)
        
        if filename_matches:
            for filename, code in filename_matches:
                language = self._detect_language_from_filename(filename.strip())
                code_files.append({
                    "id": f"file{len(code_files)+1:03d}",
                    "filename": filename.strip(),
                    "language": language,
                    "code": code.strip(),
                    "size": len(code.strip()),
                    "type": "code_file"
                })
        else:
            # Fallback to standard code blocks
            pattern = r'```(\w+)?\s*(.*?)```'
            matches = re.findall(pattern, text, re.DOTALL)
            
            for i, (language, code) in enumerate(matches):
                if len(code.strip()) > 50:  # Only substantial code blocks
                    lang = language.strip() if language else "text"
                    filename = self._infer_filename(lang, i)
                    code_files.append({
                        "id": f"file{len(code_files)+1:03d}",
                        "filename": filename,
                        "language": lang,
                        "code": code.strip(),
                        "size": len(code.strip()),
                        "type": "code_file"
                    })
        
        return code_files
    
    def _detect_language_from_filename(self, filename: str) -> str:
        """Detect language from filename extension"""
        ext_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.html': 'html',
            '.css': 'css',
            '.json': 'json',
            '.md': 'markdown',
            '.txt': 'text',
            '.sh': 'bash',
            '.sql': 'sql'
        }
        
        for ext, lang in ext_map.items():
            if filename.lower().endswith(ext):
                return lang
        
        return 'text'
    
    def _infer_filename(self, language: str, index: int) -> str:
        """Infer a filename based on language and index"""
        if language == 'python':
            return f"script{index+1}.py"
        elif language == 'javascript':
            return f"script{index+1}.js"
        elif language == 'html':
            return "index.html"
        elif language == 'css':
            return "style.css"
        else:
            return f"file{index+1}.{language}"

class XEditInterfaceGenerator:
    """Generate HTML XEdit interfaces"""
    
    def generate_xedit_interface_html(self, parsed_data: Dict[str, Any], xedit_paths: List[Dict[str, Any]]) -> str:
        """Generate complete XEdit HTML interface"""
        # Create enhanced generator and use it
        generator = EnhancedXEditGenerator()
        
        # Convert xedit_paths list to dictionary with ID keys
        xedit_paths_dict = {}
        for i, path in enumerate(xedit_paths):
            path_id = path.get("id", f"7x{i+1:03d}")
            xedit_paths_dict[path_id] = path
        
        # Generate the HTML
        return generator.generate_enhanced_xedit_html(parsed_data, xedit_paths_dict, parsed_data.get("session_timestamp", get_session_timestamp()))

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
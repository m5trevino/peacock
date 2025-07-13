#!/usr/bin/env python3
"""
xedit-generator.py - XEdit Interface Generator
Creates interactive 3-panel HTML interfaces from parsed code files
"""

import json
import re
import datetime
import base64
from pathlib import Path
from typing import Dict, List, Any, Optional

from schemas import FinalCodeOutput, CodeFile


class XEditGenerator:
    """XEdit Interface Generator - Creates interactive HTML interfaces"""
    
    def __init__(self):
        self.stage_name = "XEDIT-GENERATOR"
        self.icon = "🎨"
        self.specialty = "Interactive HTML Interface Creation"
    
    def generate_xedit_interface(self, parsed_data: FinalCodeOutput, session_id: str, pipeline_metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Generate complete XEdit interface from parsed code data
        
        Args:
            parsed_data: FinalCodeOutput with project files
            session_id: Session identifier
            pipeline_metadata: Additional pipeline information
            
        Returns:
            Dictionary with success status and file path
        """
        print(f"🎨 XEDIT-GENERATOR: Creating interactive interface for session {session_id}")
        
        try:
            # Generate XEdit paths for functions/classes
            xedit_paths = self._generate_xedit_paths(parsed_data.files)
            
            # Create HTML interface
            html_file_path = self._create_xedit_html(parsed_data, xedit_paths, session_id)
            
            print(f"✅ XEDIT-GENERATOR: Interface created successfully at {html_file_path}")
            
            return {
                "success": True,
                "xedit_file_path": str(html_file_path),
                "session_id": session_id,
                "project_files": [{"filename": f.filename, "language": f.language, "code": f.code} for f in parsed_data.files],
                "xedit_paths": xedit_paths,
                "project_name": parsed_data.project_name
            }
            
        except Exception as e:
            print(f"❌ XEDIT-GENERATOR: Failed to create interface - {str(e)}")
            return {
                "success": False,
                "error": f"XEdit generation failed: {str(e)}",
                "session_id": session_id
            }
    
    def _generate_xedit_paths(self, files: List[CodeFile]) -> Dict[str, Dict[str, Any]]:
        """Generate 7x001 style XEdit paths for all code elements"""
        
        xedit_paths = {}
        path_counter = 1
        
        for file in files:
            print(f"🔍 Analyzing {file.filename} ({file.language}) for XEdit paths...")
            
            # Parse code elements in this file
            code_elements = self._parse_code_elements(file.code, file.language, file.filename)
            
            for element in code_elements:
                xedit_id = f"7x{path_counter:03d}"
                
                xedit_paths[xedit_id] = {
                    "display_name": element["name"],
                    "type": element["type"],
                    "filename": file.filename,
                    "language": file.language,
                    "line_start": element["line_start"],
                    "line_end": element["line_end"],
                    "lines_display": f"{element['line_start']}-{element['line_end']}",
                    "technical_path": f"{file.filename}::{element['type']}.{element['name']}/lines[{element['line_start']}-{element['line_end']}]",
                    "optimal_model": self._select_optimal_model(element["type"], file.language)
                }
                
                path_counter += 1
                print(f"  🎯 {xedit_id}: {element['name']} ({element['type']})")
        
        print(f"✅ Generated {len(xedit_paths)} XEdit paths")
        return xedit_paths
    
    def _parse_code_elements(self, code: str, language: str, filename: str) -> List[Dict[str, Any]]:
        """Parse functions, classes, and other code elements"""
        elements = []
        lines = code.split('\n')
        
        if language == 'python':
            elements.extend(self._parse_python_elements(lines))
        elif language in ['javascript', 'js']:
            elements.extend(self._parse_javascript_elements(lines))
        elif language == 'html':
            elements.extend(self._parse_html_elements(lines))
        elif language == 'css':
            elements.extend(self._parse_css_elements(lines))
        else:
            # Generic parsing for other languages
            elements.extend(self._parse_generic_elements(lines))
        
        return elements
    
    def _parse_python_elements(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Parse Python functions and classes"""
        elements = []
        
        for line_num, line in enumerate(lines, 1):
            # Function definitions
            func_match = re.search(r'def\s+(\w+)\s*\(', line)
            if func_match:
                elements.append({
                    "name": func_match.group(1),
                    "type": "function",
                    "line_start": line_num,
                    "line_end": min(line_num + 15, len(lines))
                })
            
            # Class definitions
            class_match = re.search(r'class\s+(\w+)', line)
            if class_match:
                elements.append({
                    "name": class_match.group(1),
                    "type": "class",
                    "line_start": line_num,
                    "line_end": min(line_num + 30, len(lines))
                })
        
        return elements

    def _parse_javascript_elements(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Parse JavaScript functions and classes"""
        elements = []
        
        for line_num, line in enumerate(lines, 1):
            # Function declarations
            func_match = re.search(r'function\s+(\w+)\s*\(', line)
            if func_match:
                elements.append({
                    "name": func_match.group(1),
                    "type": "function",
                    "line_start": line_num,
                    "line_end": min(line_num + 15, len(lines))
                })
            
            # Arrow functions and const assignments
            arrow_match = re.search(r'(?:const|let|var)\s+(\w+)\s*=\s*(?:\([^)]*\)\s*=>|function)', line)
            if arrow_match:
                elements.append({
                    "name": arrow_match.group(1),
                    "type": "function",
                    "line_start": line_num,
                    "line_end": min(line_num + 10, len(lines))
                })
            
            # Class definitions
            class_match = re.search(r'class\s+(\w+)', line)
            if class_match:
                elements.append({
                    "name": class_match.group(1),
                    "type": "class",
                    "line_start": line_num,
                    "line_end": min(line_num + 30, len(lines))
                })
        
        return elements
    
    def _parse_html_elements(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Parse HTML elements and sections"""
        elements = []
        
        for line_num, line in enumerate(lines, 1):
            # HTML tags with IDs or classes
            tag_match = re.search(r'<(\w+)(?:\s+(?:id|class)="([^"]+)")', line)
            if tag_match:
                tag_name, identifier = tag_match.groups()
                elements.append({
                    "name": f"{tag_name}#{identifier}" if 'id=' in line else f"{tag_name}.{identifier}",
                    "type": "element",
                    "line_start": line_num,
                    "line_end": min(line_num + 5, len(lines))
                })
        
        return elements

    def _parse_css_elements(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Parse CSS selectors and rules"""
        elements = []
        
        for line_num, line in enumerate(lines, 1):
            # CSS selectors
            selector_match = re.search(r'^([.#]?[\w-]+)\s*\{', line.strip())
            if selector_match:
                elements.append({
                    "name": selector_match.group(1),
                    "type": "selector",
                    "line_start": line_num,
                    "line_end": min(line_num + 10, len(lines))
                })
        
        return elements

    def _parse_generic_elements(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Generic parsing for unknown file types"""
        elements = []
        
        for line_num, line in enumerate(lines, 1):
            # Look for function-like patterns
            func_pattern = re.search(r'(\w+)\s*\(.*\)\s*[{:]', line)
            if func_pattern:
                elements.append({
                    "name": func_pattern.group(1),
                    "type": "function",
                    "line_start": line_num,
                    "line_end": min(line_num + 10, len(lines))
                })
        
        return elements

    def _select_optimal_model(self, element_type: str, language: str) -> str:
        """Select optimal model for editing this element"""
        if language in ['python', 'javascript']:
            return "llama-3.1-70b-versatile"
        else:
            return "llama-3.1-70b-versatile"

    def _create_xedit_html(self, parsed_data: FinalCodeOutput, xedit_paths: Dict[str, Dict[str, Any]], session_id: str) -> Path:
        """Create the HTML XEdit interface file"""
        
        # Ensure HTML directory exists
        html_dir = Path("/home/flintx/peacock/html")
        html_dir.mkdir(exist_ok=True, parents=True)
        
        output_path = html_dir / f"xedit-{session_id}.html"
        
        print(f"📋 Creating XEdit at: {output_path}")
        
        # Generate enhanced XEdit HTML with 3 sections
        html_content = self._generate_xedit_html_content(parsed_data, xedit_paths, session_id)
        
        # Write the file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        # Verify file was created
        if output_path.exists():
            file_size = output_path.stat().st_size
            print(f"✅ XEdit interface generated: {output_path} ({file_size} bytes)")
            return output_path
        else:
            raise Exception("XEdit file was not created successfully")

    def _generate_xedit_html_content(self, parsed_data: FinalCodeOutput, xedit_paths: Dict[str, Dict[str, Any]], session_id: str) -> str:
        """Generate GitHub-dark themed XEdit HTML interface with 3 sections: Functions, Code Editor, Payload"""
        
        project_name = parsed_data.project_name
        
        # Clean project files to prevent JSON syntax errors
        # Use base64 encoding to completely avoid escaping issues
        cleaned_project_files = []
        for file in parsed_data.files:
            code = file.code
            # Encode code as base64 to avoid all JSON/JavaScript escaping issues
            code_b64 = base64.b64encode(code.encode('utf-8')).decode('ascii')
            
            cleaned_file = {
                "filename": file.filename,
                "language": file.language,
                "code_b64": code_b64,
                "code": ""  # Keep empty for backward compatibility
            }
            cleaned_project_files.append(cleaned_file)
        
        # Generate functions list with + buttons
        functions_html = ""
        for xedit_id, data in xedit_paths.items():
            functions_html += f"""
            <div class="function-item" onclick="highlightFunction('{xedit_id}', '{data['display_name']}', {data['line_start']}, {data['line_end']})" data-id="{xedit_id}">
                <div class="function-info">
                    <span class="function-icon">{"⚡" if data['type'] == 'function' else "🏗️"}</span>
                    <span class="function-name">{data['display_name']}</span>
                    <span class="function-type">{data['type']}</span>
                    <span class="model-indicator">⚡</span>
                </div>
                <button class="add-btn" onclick="event.stopPropagation(); addToPayload('{data['display_name']}', '{data['type']}', '{xedit_id}')" title="Add to payload">+</button>
            </div>
            """
        
        # Generate code display with line numbers (use original files for display)
        code_html = ""
        line_counter = 1
        for file in parsed_data.files:
            lines = file.code.split('\n')
            for line in lines:
                escaped_line = line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                code_html += f'<div class="code-line" data-line="{line_counter}"><span class="line-number">{line_counter:3d}</span><span class="line-content">{escaped_line}</span></div>\n'
                line_counter += 1
        
        return f"""<!DOCTYPE html>
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
            <div class="nav-link">🤖 Models</div>
            <div class="nav-link">💬 Senior Dev</div>
        </div>
        <div class="project-info">
            Project: {project_name} • Session: <span class="session-info">{session_id}</span>
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
                {functions_html if functions_html else '<div class="payload-empty">No functions found</div>'}
            </div>
        </div>

        <div class="middle-panel">
            <div class="payload-header">Optimized Payload</div>
            <div class="payload-container">
                <div class="strategy-overview">
                    <div class="strategy-title">🧠 Model Strategy</div>
                    <div class="strategy-models">
                        <strong>Code Analysis:</strong> llama3-8b-8192<br>
                        <strong>Structure:</strong> gemma2-9b-it<br>
                        <strong>Speed:</strong> llama3-8b-8192
                    </div>
                </div>
                
                <div class="payload-list" id="payload-list">
                    <div class="payload-empty">Click functions to add XEdit-Paths</div>
                </div>
                <button class="send-button" id="send-button" disabled>
                    🚀 Send 0 to Optimized Pipeline
                </button>
                
                <div class="deploy-section">
                    <div class="deploy-title">🚀 Deploy & Download</div>
                    <div class="deploy-info">
                        <strong>Project:</strong> {project_name}<br>
                        <strong>Session:</strong> {session_id}<br>
                        <strong>Strategy:</strong> Multi-Model Optimized
                    </div>
                    <button class="deploy-button" onclick="deployToPcock()">📦 Download Optimized Setup</button>
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
        // XEdit data and state
        const xeditPaths = {json.dumps(xedit_paths, ensure_ascii=True)};
        const projectFiles = {json.dumps(cleaned_project_files, ensure_ascii=True, separators=(',', ':'))};
        const projectName = '{project_name}';
        const sessionId = '{session_id}';
        let payloadItems = [];
        
        function highlightFunction(xeditId, functionName, lineStart, lineEnd) {{
            console.log(`Highlighting function: ${{functionName}} (lines ${{lineStart}}-${{lineEnd}})`);
            
            // Remove previous highlights from function list
            document.querySelectorAll('.function-item').forEach(item => {{
                item.classList.remove('highlighted');
            }});
            
            // Highlight selected function
            const selectedItem = document.querySelector(`[data-id="${{xeditId}}"]`);
            if (selectedItem) {{
                selectedItem.classList.add('highlighted');
            }}
            
            // Clear previous code highlights
            document.querySelectorAll('.code-line').forEach(line => {{
                line.classList.remove('highlight');
            }});
            
            // Highlight code lines
            for (let i = lineStart; i <= lineEnd; i++) {{
                const lineElement = document.querySelector(`.code-line[data-line="${{i}}"]`);
                if (lineElement) {{
                    lineElement.classList.add('highlight');
                    
                    // Scroll to first highlighted line
                    if (i === lineStart) {{
                        lineElement.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
                    }}
                }}
            }}
        }}
        
        function addToPayload(functionName, functionType, xeditId) {{
            console.log(`Adding to payload: ${{functionName}} (${{functionType}})`);
            
            // Check if already in payload
            if (payloadItems.find(item => item.id === xeditId)) {{
                alert('Function already in payload!');
                return;
            }}
            
            // Add to payload
            const payloadItem = {{
                id: xeditId,
                name: functionName,
                type: functionType,
                timestamp: new Date().toLocaleTimeString()
            }};
            
            payloadItems.push(payloadItem);
            updatePayloadDisplay();
        }}
        
        function removeFromPayload(xeditId) {{
            payloadItems = payloadItems.filter(item => item.id !== xeditId);
            updatePayloadDisplay();
        }}
        
        function updatePayloadDisplay() {{
            const payloadList = document.getElementById('payload-list');
            const sendButton = document.getElementById('send-button');
            
            if (payloadItems.length === 0) {{
                payloadList.innerHTML = '<div class="payload-empty">Click functions to add XEdit-Paths</div>';
                sendButton.textContent = '🚀 Send 0 to Optimized Pipeline';
                sendButton.disabled = true;
                return;
            }}
            
            let html = '';
            payloadItems.forEach(item => {{
                html += `
                    <div class="payload-item">
                        <div class="payload-item-info">
                            <div class="xedit-id">${{item.id}}</div>
                            <div class="payload-model">${{item.name}} (${{item.type}})</div>
                        </div>
                        <button class="remove-btn" onclick="removeFromPayload('${{item.id}}')" title="Remove from payload">×</button>
                    </div>
                `;
            }});
            
            payloadList.innerHTML = html;
            sendButton.textContent = `🚀 Send ${{payloadItems.length}} to Optimized Pipeline`;
            sendButton.disabled = false;
        }}
        
        function deployToPcock() {{
            console.log('deployToPcock() called');
            const deployBtn = document.querySelector('.peacock-deploy-btn');
            const deployStatus = document.getElementById('deploy-status');
            const customNameInput = document.getElementById('custom-package-name');
            
            // Get custom name or use default
            const customName = customNameInput.value.trim();
            const finalProjectName = customName || projectName;
            
            // Show loading state
            deployBtn.disabled = true;
            deployBtn.textContent = '🔄 Building...'
            deployStatus.innerHTML = '<div style="color: #ffff00;">🔧 Preparing build...</div>';
            
            // Prepare deployment data
            const deploymentData = {{
                project_name: finalProjectName,
                session_id: sessionId,
                project_files: projectFiles,
                payload_items: payloadItems,
                timestamp: new Date().toISOString()
            }};
            
            // Call deployment API
            fetch('http://127.0.0.1:8000/deploy', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json'
                }},
                body: JSON.stringify(deploymentData)
            }})
            .then(response => {{
                console.log('Response status:', response.status);
                if (!response.ok) {{
                    throw new Error(`HTTP error! status: ${{response.status}}`);
                }}
                return response.json();
            }})
            .then(data => {{
                console.log('Deploy response:', data);
                if (data.success) {{
                    deployBtn.textContent = '✅ Built!';
                    deployBtn.style.background = 'linear-gradient(45deg, #00ff00, #00cc00)';
                    deployStatus.innerHTML = `
                        <div style="color: #00ff00;">
                            ✅ Build successful!<br>
                            📦 Project created<br>
                            🚀 Ready to run
                        </div>
                    `;
                }} else {{
                    throw new Error(data.error || 'Deployment failed');
                }}
            }})
            .catch(error => {{
                console.error('Deploy error:', error);
                deployBtn.textContent = '❌ Build Failed';
                deployBtn.style.background = 'linear-gradient(45deg, #ff0000, #cc0000)';
                deployStatus.innerHTML = `
                    <div style="color: #ff0000;">
                        ❌ Build failed:<br>
                        ${{error.message}}
                    </div>
                `;
            }})
            .finally(() => {{
                deployBtn.disabled = false;
                setTimeout(() => {{
                    deployBtn.textContent = '🦚 Generate Python Project';
                    deployBtn.style.background = 'linear-gradient(45deg, #00ff00, #00cc00)';
                }}, 4000);
            }});
        }}
        
        // Decode base64 project files
        projectFiles.forEach(file => {{
            if (file.code_b64) {{
                file.code = atob(file.code_b64);
                delete file.code_b64;
            }}
        }});
        
        // Initialize page
        document.addEventListener('DOMContentLoaded', function() {{
            console.log('🦚 XEdit Enhanced Interface Loaded');
            console.log('Project:', projectName);
            console.log('Session:', sessionId);
            console.log('Functions found:', Object.keys(xeditPaths).length);
            console.log('Project files:', projectFiles.length);
        }});
    </script>
</body>
</html>"""


def create_xedit_generator() -> XEditGenerator:
    """Factory function to create XEditGenerator instance"""
    return XEditGenerator()


if __name__ == "__main__":
    # Test the XEdit generator
    from schemas import CodeFile, FinalCodeOutput
    
    test_files = [
        CodeFile(filename="app.py", language="python", code="def hello():\n    print('Hello World')\n\nclass App:\n    def run(self):\n        hello()"),
        CodeFile(filename="styles.css", language="css", code=".app {\n    color: blue;\n}\n\n.header {\n    font-size: 24px;\n}")
    ]
    
    test_data = FinalCodeOutput(project_name="Test Project", files=test_files)
    
    generator = create_xedit_generator()
    result = generator.generate_xedit_interface(test_data, "test-session-001")
    
    print(f"✅ Test completed: {result.get('success')}")
    print(f"📄 XEdit file: {result.get('xedit_file_path')}")
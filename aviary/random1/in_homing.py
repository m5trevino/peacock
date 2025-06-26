#!/usr/bin/env python3
"""
in-homing.py - IN-HOMING Response Processing & XEdit Generation Bird
Handles LLM2 responses coming back IN and creates the final XEdit interface
"""

import json
import re
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

class InHomingProcessor:
    """IN-HOMING - The Response Handler & XEdit Generator"""
    
    def __init__(self):
        self.stage_name = "IN-HOMING"
        self.icon = "🔄"
        self.specialty = "LLM2 Response Processing & XEdit Generation"
        self.session_timestamp = self._generate_session_timestamp()
    
    def process_llm2_response(self, llm2_response: str, pipeline_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main IN-HOMING function - process LLM2 response and generate XEdit interface
        """
        print(f"🔄 IN-HOMING: Processing LLM2 response and generating XEdit...")
        
        processing_result = {
            "success": False,
            "llm2_response": llm2_response,
            "pipeline_metadata": pipeline_metadata,
            "parsed_data": {},
            "xedit_interface": None,
            "xedit_paths": {},
            "project_files": [],
            "session_timestamp": self.session_timestamp,
            "processing_timestamp": datetime.datetime.now().isoformat(),
            "error": None
        }
        
        try:
            # Parse the LLM2 response
            processing_result["parsed_data"] = self._parse_llm2_response(llm2_response)
            
            # Extract code files
            processing_result["project_files"] = self._extract_project_files(processing_result["parsed_data"])
            
            # Generate XEdit paths
            processing_result["xedit_paths"] = self._generate_xedit_paths(processing_result["project_files"])
            
            # Generate XEdit interface
            processing_result["xedit_interface"] = self._generate_xedit_interface(
                processing_result["parsed_data"],
                processing_result["xedit_paths"],
                pipeline_metadata
            )
            
            # Save XEdit interface to file
            xedit_file_path = self._save_xedit_interface(
                processing_result["xedit_interface"],
                pipeline_metadata.get("project_name", "project")
            )
            
            processing_result["xedit_file_path"] = str(xedit_file_path)
            processing_result["success"] = True
            
            print(f"✅ IN-HOMING: Processing completed successfully!")
            print(f"📁 Generated: {len(processing_result['project_files'])} files")
            print(f"🎯 XEdit Paths: {len(processing_result['xedit_paths'])}")
            print(f"💾 Saved: {xedit_file_path}")
            
        except Exception as e:
            processing_result["error"] = str(e)
            processing_result["success"] = False
            print(f"❌ IN-HOMING: Processing failed - {e}")
        
        return processing_result
    
    def _parse_llm2_response(self, response_text: str) -> Dict[str, Any]:
        """Parse the LLM2 response into structured data"""
        
        parsed_data = {
            "project_overview": "",
            "code_files": [],
            "implementation_notes": [],
            "testing_checklist": [],
            "raw_response": response_text
        }
        
        # Extract project overview
        overview_match = re.search(r'\*\*PROJECT OVERVIEW:\*\*\s*\n([^\n*]+(?:\n[^\n*]+)*)', response_text)
        if overview_match:
            parsed_data["project_overview"] = overview_match.group(1).strip()
        
        # Extract code files
        code_files = self._extract_code_blocks_with_filenames(response_text)
        parsed_data["code_files"] = code_files
        
        # Extract implementation notes
        notes_match = re.search(r'\*\*IMPLEMENTATION NOTES:\*\*\s*\n((?:- [^\n]+\n?)+)', response_text)
        if notes_match:
            notes = re.findall(r'- ([^\n]+)', notes_match.group(1))
            parsed_data["implementation_notes"] = [note.strip() for note in notes]
        
        # Extract testing checklist
        testing_match = re.search(r'\*\*TESTING CHECKLIST:\*\*\s*\n((?:- [^\n]+\n?)+)', response_text)
        if testing_match:
            tests = re.findall(r'- ([^\n]+)', testing_match.group(1))
            parsed_data["testing_checklist"] = [test.strip() for test in tests]
        
        print(f"📝 Parsed: {len(parsed_data['code_files'])} files, {len(parsed_data['implementation_notes'])} notes")
        return parsed_data
    
    def _extract_code_blocks_with_filenames(self, response_text: str) -> List[Dict[str, Any]]:
        """Extract code blocks with filenames from response"""
        
        code_files = []
        
        # Pattern for filename-based code blocks
        filename_pattern = r'```filename:\s*([^\n]+)\n(.*?)\n```'
        filename_matches = re.findall(filename_pattern, response_text, re.DOTALL)
        
        for filename, code in filename_matches:
            file_data = {
                "filename": filename.strip(),
                "code": code.strip(),
                "language": self._detect_language(filename.strip()),
                "size": len(code.strip()),
                "lines": len(code.strip().split('\n'))
            }
            code_files.append(file_data)
            print(f"📄 Found: {file_data['filename']} ({file_data['language']}, {file_data['lines']} lines)")
        
        return code_files
    
    def _extract_project_files(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert parsed data to project files format"""
        return parsed_data.get("code_files", [])
    
    def _generate_xedit_paths(self, project_files: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Generate 7x001 style XEdit paths for all code elements"""
        
        xedit_paths = {}
        path_counter = 1
        
        for file_data in project_files:
            filename = file_data["filename"]
            language = file_data["language"]
            code = file_data["code"]
            
            print(f"🔍 Analyzing {filename} ({language}) for XEdit paths...")
            
            # Parse code elements in this file
            code_elements = self._parse_code_elements(code, language, filename)
            
            for element in code_elements:
                xedit_id = f"7x{path_counter:03d}"
                
                xedit_paths[xedit_id] = {
                    "display_name": element["name"],
                    "type": element["type"],
                    "filename": filename,
                    "language": language,
                    "line_start": element["line_start"],
                    "line_end": element["line_end"],
                    "lines_display": f"{element['line_start']}-{element['line_end']}",
                    "technical_path": f"{filename}::{element['type']}.{element['name']}/lines[{element['line_start']}-{element['line_end']}]",
                    "optimal_model": self._select_optimal_model(element["type"], language)
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
        
        for i, line in enumerate(lines, 1):
            # Function definitions
            func_match = re.match(r'^(\s*)def\s+(\w+)\s*\(', line)
            if func_match:
                elements.append({
                    "name": func_match.group(2),
                    "type": "function",
                    "line_start": i,
                    "line_end": min(i + 20, len(lines))
                })
            
            # Class definitions
            class_match = re.match(r'^(\s*)class\s+(\w+)', line)
            if class_match:
                elements.append({
                    "name": class_match.group(2),
                    "type": "class",
                    "line_start": i,
                    "line_end": min(i + 50, len(lines))
                })
        
        return elements
    
    def _parse_javascript_elements(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Parse JavaScript functions and classes"""
        elements = []
        
        for i, line in enumerate(lines, 1):
            # Function declarations
            func_match = re.search(r'function\s+(\w+)\s*\(', line)
            if func_match:
                elements.append({
                    "name": func_match.group(1),
                    "type": "function",
                    "line_start": i,
                    "line_end": min(i + 15, len(lines))
                })
            
            # Arrow functions and const assignments
            arrow_match = re.search(r'(?:const|let|var)\s+(\w+)\s*=\s*(?:\([^)]*\)\s*=>|function)', line)
            if arrow_match:
                elements.append({
                    "name": arrow_match.group(1),
                    "type": "function",
                    "line_start": i,
                    "line_end": min(i + 10, len(lines))
                })
            
            # Class definitions
            class_match = re.search(r'class\s+(\w+)', line)
            if class_match:
                elements.append({
                    "name": class_match.group(1),
                    "type": "class",
                    "line_start": i,
                    "line_end": min(i + 30, len(lines))
                })
            
            # Method definitions (inside classes)
            method_match = re.search(r'^\s+(\w+)\s*\([^)]*\)\s*\{', line)
            if method_match and not line.strip().startswith('//'):
                elements.append({
                    "name": method_match.group(1),
                    "type": "method",
                    "line_start": i,
                    "line_end": min(i + 12, len(lines))
                })
        
        return elements
    
    def _parse_html_elements(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Parse HTML elements"""
        elements = []
        
        for i, line in enumerate(lines, 1):
            # Major HTML tags with IDs
            id_match = re.search(r'<(div|section|header|footer|main|nav|article)\s*[^>]*id=["\']([^"\']+)["\']', line)
            if id_match:
                elements.append({
                    "name": id_match.group(2),
                    "type": f"html_{id_match.group(1)}",
                    "line_start": i,
                    "line_end": min(i + 5, len(lines))
                })
            
            # Major HTML tags with classes
            class_match = re.search(r'<(div|section|header|footer|main|nav)\s*[^>]*class=["\']([^"\']+)["\']', line)
            if class_match:
                elements.append({
                    "name": class_match.group(2).split()[0],  # First class name
                    "type": f"html_{class_match.group(1)}",
                    "line_start": i,
                    "line_end": min(i + 5, len(lines))
                })
        
        return elements
    
    def _parse_css_elements(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Parse CSS classes and IDs"""
        elements = []
        
        for i, line in enumerate(lines, 1):
            # CSS classes
            class_match = re.search(r'\.([a-zA-Z][\w-]*)\s*\{', line)
            if class_match:
                elements.append({
                    "name": class_match.group(1),
                    "type": "css_class",
                    "line_start": i,
                    "line_end": min(i + 10, len(lines))
                })
            
            # CSS IDs
            id_match = re.search(r'#([a-zA-Z][\w-]*)\s*\{', line)
            if id_match:
                elements.append({
                    "name": id_match.group(1),
                    "type": "css_id",
                    "line_start": i,
                    "line_end": min(i + 10, len(lines))
                })
        
        return elements
    
    def _parse_generic_elements(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Generic parsing for unknown languages"""
        elements = []
        
        for i, line in enumerate(lines, 1):
            # Generic function-like patterns
            if re.search(r'\w+\s*\([^)]*\)\s*\{', line):
                func_match = re.search(r'(\w+)\s*\(', line)
                if func_match:
                    elements.append({
                        "name": func_match.group(1),
                        "type": "function",
                        "line_start": i,
                        "line_end": min(i + 10, len(lines))
                    })
        
        return elements
    
    def _generate_xedit_interface(self, parsed_data: Dict[str, Any], xedit_paths: Dict[str, Dict[str, Any]], pipeline_metadata: Dict[str, Any]) -> str:
        """Generate complete XEdit HTML interface"""
        
        project_name = pipeline_metadata.get("project_name", "Unknown Project")
        
        # Combine all code for display
        combined_code = self._combine_code_for_display(parsed_data["code_files"])
        
        # Generate functions list HTML
        functions_html = self._generate_functions_html(xedit_paths)
        
        # Generate code display HTML with line numbers
        code_html = self._generate_code_html(combined_code)
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🦚 Peacock XEdit Interface - {project_name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'SF Mono', monospace; background: #0d1117; color: #e6edf3; height: 100vh; overflow: hidden; }}
        
        .header {{ background: #161b22; border-bottom: 1px solid #30363d; padding: 12px 20px; display: flex; justify-content: space-between; align-items: center; }}
        .peacock-logo {{ font-size: 18px; font-weight: bold; color: #ff6b35; }}
        .project-info {{ color: #8b949e; font-size: 14px; }}
        .session-info {{ background: rgba(0, 255, 136, 0.1); border: 1px solid #00ff88; border-radius: 6px; padding: 4px 8px; font-size: 12px; color: #00ff88; }}
        
        .main-container {{ display: flex; height: calc(100vh - 60px); }}
        
        .left-panel {{ width: 320px; background: #161b22; border-right: 1px solid #30363d; display: flex; flex-direction: column; }}
        .panel-header {{ background: #21262d; padding: 12px 16px; border-bottom: 1px solid #30363d; font-weight: 600; font-size: 13px; color: #7c3aed; }}
        
        .functions-list {{ flex: 1; overflow-y: auto; padding: 8px; }}
        .function-item {{ background: #21262d; border: 1px solid #30363d; border-radius: 6px; padding: 12px; margin-bottom: 8px; cursor: pointer; transition: all 0.2s; position: relative; }}
        .function-item:hover {{ border-color: #ff6b35; background: #2d333b; transform: translateX(3px); }}
        .function-item.selected {{ border-color: #ff6b35; background: #2d333b; box-shadow: 0 0 0 1px #ff6b35; }}
        
        .function-info {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
        .function-name {{ font-weight: 600; color: #79c0ff; }}
        .function-type {{ background: #30363d; color: #8b949e; padding: 2px 6px; border-radius: 4px; font-size: 10px; }}
        .xedit-id {{ background: #238636; color: white; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: 600; }}
        .function-lines {{ color: #6e7681; font-size: 10px; }}
        
        .add-btn {{ position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: #238636; color: white; border: none; border-radius: 4px; width: 24px; height: 24px; cursor: pointer; font-weight: bold; }}
        .add-btn:hover {{ background: #2ea043; }}
        
        .middle-panel {{ width: 280px; background: #0d1117; border-right: 1px solid #30363d; display: flex; flex-direction: column; }}
        .payload-header {{ background: #21262d; padding: 12px 16px; border-bottom: 1px solid #30363d; font-weight: 600; font-size: 13px; color: #ff6b35; }}
        
        .payload-list {{ flex: 1; overflow-y: auto; padding: 8px; }}
        .payload-item {{ background: rgba(255, 107, 53, 0.1); border: 1px solid #ff6b35; border-radius: 6px; padding: 8px; margin-bottom: 6px; font-size: 12px; }}
        .payload-item .remove-btn {{ float: right; background: #da3633; color: white; border: none; border-radius: 3px; width: 18px; height: 18px; cursor: pointer; font-size: 10px; }}
        
        .send-btn {{ margin: 8px; padding: 12px; background: linear-gradient(45deg, #238636, #2ea043); color: white; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; }}
        .send-btn:hover {{ background: linear-gradient(45deg, #2ea043, #238636); }}
        
        .right-panel {{ flex: 1; background: #0d1117; display: flex; flex-direction: column; }}
        .code-header {{ background: #21262d; padding: 12px 16px; border-bottom: 1px solid #30363d; font-weight: 600; font-size: 13px; color: #79c0ff; }}
        
        .code-container {{ flex: 1; overflow: auto; }}
        .code-line {{ display: flex; font-family: 'SF Mono', monospace; font-size: 13px; line-height: 1.4; }}
        .code-line:hover {{ background: rgba(255, 255, 255, 0.05); }}
        .line-number {{ width: 60px; padding: 4px 8px; background: #161b22; border-right: 1px solid #30363d; color: #6e7681; text-align: right; flex-shrink: 0; }}
        .line-content {{ padding: 4px 12px; flex: 1; white-space: pre; }}
        
        .highlighted {{ background: rgba(255, 107, 53, 0.2) !important; }}
    </style>
</head>
<body>
    <div class="header">
        <div class="peacock-logo">🦚 Peacock XEdit Interface</div>
        <div class="project-info">{project_name}</div>
        <div class="session-info">Session: {self.session_timestamp}</div>
    </div>
    
    <div class="main-container">
        <!-- Left Panel: Functions List -->
        <div class="left-panel">
            <div class="panel-header">📋 Functions & Classes ({len(xedit_paths)})</div>
            <div class="functions-list">
                {functions_html}
            </div>
        </div>
        
        <!-- Middle Panel: Payload -->
        <div class="middle-panel">
            <div class="payload-header">🎯 Payload</div>
            <div class="payload-list" id="payloadList">
                <div style="color: #6e7681; text-align: center; padding: 20px; font-size: 12px;">
                    Click functions to add XEdit-Paths
                </div>
            </div>
            <button class="send-btn" onclick="sendToLLM2()">🚀 Send to LLM2</button>
            <button class="deploy-btn" onclick="deployProject()" style="margin: 8px; padding: 12px; background: linear-gradient(45deg, #0969da, #1f6feb); color: white; border: none; border-radius: 6px; font-weight: 600; cursor: pointer;">🦚 PCOCK Deploy</button>
        </div>
        
        <!-- Right Panel: Code Display -->
        <div class="right-panel">
            <div class="code-header">💻 Generated Code ({len(parsed_data["code_files"])} files)</div>
            <div class="code-container">
                {code_html}
            </div>
        </div>
    </div>
    
    <script>
        let payloadItems = [];
        const xeditPaths = {json.dumps(xedit_paths)};
        
        function highlightFunction(xeditId) {{
            // Remove previous highlights
            document.querySelectorAll('.highlighted').forEach(el => {{
                el.classList.remove('highlighted');
            }});
            
            // Remove previous selection
            document.querySelectorAll('.function-item.selected').forEach(el => {{
                el.classList.remove('selected');
            }});
            
            // Add selection to clicked item
            event.currentTarget.classList.add('selected');
            
            // Highlight lines based on XEdit path data
            const pathData = xeditPaths[xeditId];
            if (pathData) {{
                for (let lineNum = pathData.line_start; lineNum <= pathData.line_end; lineNum++) {{
                    const lineElement = document.querySelector(`[data-line="${{lineNum}}"]`);
                    if (lineElement) {{
                        lineElement.classList.add('highlighted');
                    }}
                }}
                
                // Scroll to the highlighted section
                const firstHighlighted = document.querySelector('.highlighted');
                if (firstHighlighted) {{
                    firstHighlighted.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
                }}
            }}
            
            console.log('Highlighted function:', xeditId, pathData);
        }}
        
        function addToPayload(xeditId) {{
            event.stopPropagation(); // Prevent highlighting when clicking add button
            
            if (payloadItems.includes(xeditId)) return;
            
            payloadItems.push(xeditId);
            updatePayloadDisplay();
            console.log('Added to payload:', xeditId);
        }}
        
        function removeFromPayload(xeditId) {{
            payloadItems = payloadItems.filter(item => item !== xeditId);
            updatePayloadDisplay();
            console.log('Removed from payload:', xeditId);
        }}
        
        function updatePayloadDisplay() {{
            const payloadList = document.getElementById('payloadList');
            
            if (payloadItems.length === 0) {{
                payloadList.innerHTML = '<div style="color: #6e7681; text-align: center; padding: 20px; font-size: 12px;">Click functions to add XEdit-Paths</div>';
                return;
            }}
            
            payloadList.innerHTML = payloadItems.map(xeditId => {{
                const pathData = xeditPaths[xeditId];
                const displayName = pathData ? pathData.display_name : xeditId;
                return `<div class="payload-item">
                    <strong>${{xeditId}}</strong><br>
                    ${{displayName}} (${{pathData ? pathData.type : 'unknown'}})
                    <button class="remove-btn" onclick="removeFromPayload('${{xeditId}}')">&times;</button>
                </div>`;
            }}).join('');
        }}
        
        function deployProject() {{
            console.log('🦚 PCOCK DEPLOY: Starting deployment...');
            
            // Send deploy request to MCP
            fetch('http://127.0.0.1:8000/deploy', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json',
                }},
                body: JSON.stringify({{
                    project_name: '{project_name}',
                    action: 'deploy_and_run'
                }})
            }})
            .then(response => response.json())
            .then(data => {{
                if (data.success) {{
                    alert(`🦚 PCOCK DEPLOY SUCCESS!\\n\\n` +
                          `📁 Project: ${{data.project_name}}\\n` +
                          `📄 Files: ${{data.files_deployed}}\\n` +
                          `🌐 Running: ${{data.server_url}}\\n\\n` +
                          `Browser should open automatically!`);
                }} else {{
                    alert(`❌ PCOCK DEPLOY FAILED:\\n${{data.error}}`);
                }}
            }})
            .catch(error => {{
                console.error('Deploy error:', error);
                alert(`❌ Deploy request failed: ${{error.message}}`);
            }});
        }}
        
        function sendToLLM2() {{
            if (payloadItems.length === 0) {{
                alert('Please add some XEdit-Paths to the payload first');
                return;
            }}
            
            const payloadData = payloadItems.map(xeditId => xeditPaths[xeditId]);
            console.log('Sending to LLM2:', payloadData);
            
            alert(`Sending ${{payloadItems.length}} XEdit-Paths to LLM2 for optimization:\n\n${{payloadItems.join(', ')}}`);
            
            // In real implementation, would send to MCP server for LLM2 processing
        }}
        
        console.log('🦚 Peacock XEdit Interface Loaded');
        console.log('📁 Project:', '{project_name}');
        console.log('🔢 XEdit Paths:', {len(xedit_paths)});
        console.log('📄 Code Files:', {len(parsed_data["code_files"])});
        console.log('🎯 XEdit Paths Data:', xeditPaths);
    </script>
</body>
</html>"""
        
        return html_content
    
    def _combine_code_for_display(self, code_files: List[Dict[str, Any]]) -> str:
        """Combine all code files for display in interface"""
        combined = []
        
        for file_data in code_files:
            combined.append(f"// File: {file_data['filename']}")
            combined.append(f"// Language: {file_data['language']}")
            combined.append(f"// Size: {file_data['size']} characters")
            combined.append("")
            combined.append(file_data['code'])
            combined.append("")
            combined.append("// " + "="*60)
            combined.append("")
        
        return "\n".join(combined)
    
    def _generate_functions_html(self, xedit_paths: Dict[str, Dict[str, Any]]) -> str:
        """Generate HTML for functions list"""
        functions_html = ""
        
        for xedit_id, path_data in xedit_paths.items():
            icon = "🏗️" if path_data["type"] == "class" else "⚡"
            if "method" in path_data["type"]:
                icon = "🔧"
            elif "html" in path_data["type"]:
                icon = "🌐"
            elif "css" in path_data["type"]:
                icon = "🎨"
            
            functions_html += f"""
            <div class="function-item" onclick="highlightFunction('{xedit_id}')">
                <div class="function-info">
                    <span>{icon}</span>
                    <span class="function-name">{path_data['display_name']}</span>
                    <span class="function-type">{path_data['type']}</span>
                    <span class="xedit-id">{xedit_id}</span>
                    <div class="function-lines">Lines {path_data['lines_display']}</div>
                </div>
                <button class="add-btn" onclick="addToPayload('{xedit_id}')" title="Add to payload">+</button>
            </div>"""
        
        if not xedit_paths:
            functions_html = '<div style="color: #6e7681; text-align: center; padding: 20px;">No functions or classes found</div>'
        
        return functions_html
    
    def _generate_code_html(self, combined_code: str) -> str:
        """Generate HTML for code display with line numbers"""
        lines = combined_code.split('\n')
        code_html = ""
        
        for i, line in enumerate(lines, 1):
            escaped_line = line.replace('<', '&lt;').replace('>', '&gt;')
            code_html += f'<div class="code-line" data-line="{i}"><span class="line-number">{i:3d}</span><span class="line-content">{escaped_line}</span></div>\n'
        
        return code_html
    
    def _save_xedit_interface(self, html_content: str, project_name: str) -> Path:
        """Save XEdit interface to file"""
        output_dir = Path("/home/flintx/peacock/html")
        output_dir.mkdir(exist_ok=True)
        
        file_path = output_dir / f"xedit-{self.session_timestamp}.html"
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        print(f"💾 XEdit interface saved: {file_path}")
        return file_path
    
    def _detect_language(self, filename: str) -> str:
        """Detect programming language from filename"""
        ext_map = {
            '.html': 'html',
            '.css': 'css', 
            '.js': 'javascript',
            '.py': 'python',
            '.java': 'java',
            '.cpp': 'cpp',
            '.c': 'c',
            '.php': 'php',
            '.rb': 'ruby',
            '.go': 'go',
            '.rs': 'rust',
            '.ts': 'typescript',
            '.jsx': 'jsx',
            '.tsx': 'tsx'
        }
        
        for ext, lang in ext_map.items():
            if filename.lower().endswith(ext):
                return lang
        
        return 'text'
    
    def _select_optimal_model(self, element_type: str, language: str) -> str:
        """Select optimal model based on element type and language"""
        # Based on testing results
        if element_type == "class" or language in ["html", "css"]:
            return "gemma2-9b-it"  # Better structure handling
        else:
            return "llama-3.1-8b-instant"  # Better code analysis
    
    def _generate_session_timestamp(self) -> str:
        """Generate session timestamp matching MCP format - MILITARY TIME"""
        now = datetime.datetime.now()
        week = now.isocalendar()[1]
        day = now.day
        hour = now.hour  # Already 24-hour format
        minute = now.minute
        return f"{week:02d}-{day:02d}-{hour:02d}{minute:02d}"
    
    def generate_project_summary(self, processing_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate complete project summary"""
        
        summary = {
            "project_overview": processing_result["parsed_data"].get("project_overview", ""),
            "files_generated": len(processing_result["project_files"]),
            "xedit_paths_created": len(processing_result["xedit_paths"]),
            "total_lines_of_code": sum(file_data["lines"] for file_data in processing_result["project_files"]),
            "languages_used": list(set(file_data["language"] for file_data in processing_result["project_files"])),
            "implementation_notes": processing_result["parsed_data"].get("implementation_notes", []),
            "testing_checklist": processing_result["parsed_data"].get("testing_checklist", []),
            "xedit_interface_path": processing_result.get("xedit_file_path", ""),
            "session_info": {
                "timestamp": self.session_timestamp,
                "processing_time": processing_result["processing_timestamp"]
            }
        }
        
        return summary
    
    def deploy_project_files(self, project_files: List[Dict[str, Any]], project_name: str) -> Dict[str, Any]:
        """Deploy project files to local apps directory and start server"""
        print(f"🚀 IN-HOMING: Deploying {project_name}...")
        
        deploy_result = {
            "success": False,
            "project_path": "",
            "server_url": "",
            "files_deployed": 0,
            "error": None
        }
        
        try:
            # Create apps directory structure
            apps_dir = Path("/home/flintx/peacock/apps")
            apps_dir.mkdir(exist_ok=True)
            
            project_dir = apps_dir / project_name
            project_dir.mkdir(exist_ok=True)
            
            # Deploy all project files
            for file_data in project_files:
                file_path = project_dir / file_data["filename"]
                
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(file_data["code"])
                
                print(f"📄 Deployed: {file_data['filename']} ({file_data['size']} chars)")
                deploy_result["files_deployed"] += 1
            
            # Create project manifest
            manifest = {
                "name": project_name,
                "created": datetime.datetime.now().isoformat(),
                "files": [f["filename"] for f in project_files],
                "languages": list(set(f["language"] for f in project_files)),
                "total_lines": sum(f["lines"] for f in project_files),
                "session": self.session_timestamp
            }
            
            manifest_path = project_dir / "peacock.json"
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)
            
            deploy_result["project_path"] = str(project_dir)
            deploy_result["server_url"] = f"http://localhost:8080"
            deploy_result["success"] = True
            
            print(f"✅ Deployed {deploy_result['files_deployed']} files to: {project_dir}")
            print(f"🌐 Ready to serve at: {deploy_result['server_url']}")
            
        except Exception as e:
            deploy_result["error"] = str(e)
            print(f"❌ Deploy failed: {e}")
        
        return deploy_result
    
    def start_local_server(self, project_name: str, port: int = 8080) -> Dict[str, Any]:
        """Start local HTTP server for deployed project"""
        import subprocess
        import webbrowser
        import time
        
        server_result = {
            "success": False,
            "server_url": "",
            "process_id": None,
            "error": None
        }
        
        try:
            project_dir = Path(f"/home/flintx/peacock/apps/{project_name}")
            
            if not project_dir.exists():
                server_result["error"] = f"Project {project_name} not found"
                return server_result
            
            # Start HTTP server in project directory
            server_cmd = [
                "python", "-m", "http.server", str(port), 
                "--directory", str(project_dir)
            ]
            
            print(f"🌐 Starting server: {' '.join(server_cmd)}")
            
            # Start server process (non-blocking)
            process = subprocess.Popen(
                server_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(project_dir)
            )
            
            # Give server a moment to start
            time.sleep(1)
            
            server_url = f"http://localhost:{port}"
            
            # Open in browser
            print(f"🚀 Opening browser: {server_url}")
            webbrowser.open(server_url)
            
            server_result["success"] = True
            server_result["server_url"] = server_url
            server_result["process_id"] = process.pid
            
            print(f"✅ Server started successfully!")
            print(f"   🌐 URL: {server_url}")
            print(f"   🔢 PID: {process.pid}")
            print(f"   📁 Directory: {project_dir}")
            
        except Exception as e:
            server_result["error"] = str(e)
            print(f"❌ Server start failed: {e}")
        
        return server_result
    
    def deploy_and_run(self, project_files: List[Dict[str, Any]], project_name: str) -> Dict[str, Any]:
        """Complete deploy and run workflow"""
        print(f"🦚 PCOCK DEPLOY: {project_name}")
        
        # Deploy files
        deploy_result = self.deploy_project_files(project_files, project_name)
        
        if not deploy_result["success"]:
            return {
                "success": False,
                "error": f"Deploy failed: {deploy_result['error']}",
                "deploy_result": deploy_result
            }
        
        # Start server and open browser
        server_result = self.start_local_server(project_name)
        
        complete_result = {
            "success": server_result["success"],
            "project_name": project_name,
            "project_path": deploy_result["project_path"],
            "files_deployed": deploy_result["files_deployed"],
            "server_url": server_result["server_url"],
            "process_id": server_result.get("process_id"),
            "deploy_result": deploy_result,
            "server_result": server_result
        }
        
        if complete_result["success"]:
            print(f"🎉 PCOCK DEPLOY COMPLETE!")
            print(f"   📁 Project: {project_name}")
            print(f"   📄 Files: {deploy_result['files_deployed']}")
            print(f"   🌐 Running: {server_result['server_url']}")
        else:
            complete_result["error"] = server_result.get("error", "Unknown server error")
        
        return complete_result
    
    def validate_processing_quality(self, processing_result: Dict[str, Any]) -> Dict[str, Any]:
        """Validate the quality of processing results"""
        
        validation = {
            "overall_quality": "unknown",
            "code_files_valid": False,
            "xedit_paths_valid": False,
            "interface_generated": False,
            "recommendations": []
        }
        
        # Check code files
        if processing_result["project_files"] and len(processing_result["project_files"]) > 0:
            validation["code_files_valid"] = True
            
            # Check if files have content
            total_lines = sum(file_data["lines"] for file_data in processing_result["project_files"])
            if total_lines < 50:
                validation["recommendations"].append("Generated code seems very short - may need more implementation")
        
        # Check XEdit paths
        if processing_result["xedit_paths"] and len(processing_result["xedit_paths"]) > 0:
            validation["xedit_paths_valid"] = True
        else:
            validation["recommendations"].append("No XEdit paths generated - code may lack functions/classes")
        
        # Check interface generation
        if processing_result["xedit_interface"] and len(processing_result["xedit_interface"]) > 1000:
            validation["interface_generated"] = True
        else:
            validation["recommendations"].append("XEdit interface generation may have failed")
        
        # Overall quality assessment
        quality_score = 0
        if validation["code_files_valid"]:
            quality_score += 3
        if validation["xedit_paths_valid"]:
            quality_score += 2
        if validation["interface_generated"]:
            quality_score += 3
        
        if quality_score >= 7:
            validation["overall_quality"] = "excellent"
        elif quality_score >= 5:
            validation["overall_quality"] = "good"
        elif quality_score >= 3:
            validation["overall_quality"] = "fair"
        else:
            validation["overall_quality"] = "poor"
        
        return validation

# Factory function for IN-HOMING processor
def create_return_homing_processor() -> InHomingProcessor:
    """Factory function to create IN-HOMING processor instance"""
    return InHomingProcessor()

# Test function for IN-HOMING processor
def test_in_homing_processor():
    """Test the IN-HOMING processor with sample LLM2 response"""
    processor = create_return_homing_processor()
    
    # Mock LLM2 response
    sample_llm2_response = """**PROJECT OVERVIEW:**
Complete snake game implementation with HTML5 canvas, CSS styling, and JavaScript game logic.

**CODE FILES:**

```filename: index.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Snake Game</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div id="gameContainer">
        <canvas id="gameCanvas" width="400" height="400"></canvas>
        <div id="score">Score: 0</div>
    </div>
    <script src="script.js"></script>
</body>
</html>
```

```filename: styles.css
body {
    margin: 0;
    padding: 0;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
    background-color: #2c3e50;
    font-family: Arial, sans-serif;
}

#gameContainer {
    text-align: center;
}

#gameCanvas {
    border: 2px solid #fff;
    background-color: #34495e;
}

#score {
    color: white;
    font-size: 24px;
    margin-top: 10px;
}
```

```filename: script.js
const canvas = document.getElementById('gameCanvas');
const ctx = canvas.getContext('2d');
const scoreElement = document.getElementById('score');

class SnakeGame {
    constructor() {
        this.snake = [{x: 200, y: 200}];
        this.food = this.generateFood();
        this.direction = {x: 0, y: 0};
        this.score = 0;
    }
    
    generateFood() {
        return {
            x: Math.floor(Math.random() * (canvas.width / 20)) * 20,
            y: Math.floor(Math.random() * (canvas.height / 20)) * 20
        };
    }
    
    update() {
        const head = {x: this.snake[0].x + this.direction.x, y: this.snake[0].y + this.direction.y};
        this.snake.unshift(head);
        
        if (head.x === this.food.x && head.y === this.food.y) {
            this.score++;
            this.food = this.generateFood();
        } else {
            this.snake.pop();
        }
        
        this.checkCollision();
    }
    
    checkCollision() {
        const head = this.snake[0];
        if (head.x < 0 || head.x >= canvas.width || head.y < 0 || head.y >= canvas.height) {
            this.gameOver();
        }
        
        for (let i = 1; i < this.snake.length; i++) {
            if (head.x === this.snake[i].x && head.y === this.snake[i].y) {
                this.gameOver();
            }
        }
    }
    
    gameOver() {
        alert('Game Over! Score: ' + this.score);
        this.snake = [{x: 200, y: 200}];
        this.direction = {x: 0, y: 0};
        this.score = 0;
        this.food = this.generateFood();
    }
    
    render() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        // Draw snake
        ctx.fillStyle = '#27ae60';
        this.snake.forEach(segment => {
            ctx.fillRect(segment.x, segment.y, 20, 20);
        });
        
        // Draw food
        ctx.fillStyle = '#e74c3c';
        ctx.fillRect(this.food.x, this.food.y, 20, 20);
        
        // Update score
        scoreElement.textContent = 'Score: ' + this.score;
    }
}

const game = new SnakeGame();

function gameLoop() {
    game.update();
    game.render();
}

document.addEventListener('keydown', (e) => {
    switch(e.key) {
        case 'ArrowUp':
            if (game.direction.y === 0) game.direction = {x: 0, y: -20};
            break;
        case 'ArrowDown':
            if (game.direction.y === 0) game.direction = {x: 0, y: 20};
            break;
        case 'ArrowLeft':
            if (game.direction.x === 0) game.direction = {x: -20, y: 0};
            break;
        case 'ArrowRight':
            if (game.direction.x === 0) game.direction = {x: 20, y: 0};
            break;
    }
});

setInterval(gameLoop, 100);
```

**IMPLEMENTATION NOTES:**
- Used HTML5 Canvas for smooth game rendering
- Implemented collision detection for walls and self-collision
- Added keyboard controls for snake movement
- Simple scoring system with food consumption

**TESTING CHECKLIST:**
- Test arrow key controls for snake movement
- Verify collision detection works properly
- Check food generation and scoring
- Test game over and restart functionality"""

    # Mock pipeline metadata
    pipeline_metadata = {
        "project_name": "snake_game",
        "total_stages": 4,
        "pipeline_duration": "15.3 seconds"
    }
    
    print("🧪 TESTING IN-HOMING PROCESSOR")
    print("="*70)
    
    # Process the LLM2 response
    processing_result = processor.process_llm2_response(sample_llm2_response, pipeline_metadata)
    
    print("\n📊 PROCESSING RESULTS:")
    print(f"✅ Success: {processing_result['success']}")
    print(f"📁 Project Files: {len(processing_result['project_files'])}")
    print(f"🎯 XEdit Paths: {len(processing_result['xedit_paths'])}")
    
    if processing_result["xedit_interface"]:
        print(f"🌐 XEdit Interface: Generated ({len(processing_result['xedit_interface'])} characters)")
    
    if processing_result.get("xedit_file_path"):
        print(f"💾 Saved to: {processing_result['xedit_file_path']}")
    
    # Show XEdit paths generated
    if processing_result["xedit_paths"]:
        print(f"\n🎯 XEDIT PATHS GENERATED:")
        for xedit_id, path_data in processing_result["xedit_paths"].items():
            print(f"   {xedit_id}: {path_data['display_name']} ({path_data['type']}) - Lines {path_data['lines_display']}")
    
    # Generate project summary
    summary = processor.generate_project_summary(processing_result)
    print(f"\n📋 PROJECT SUMMARY:")
    print(f"   📄 Files: {summary['files_generated']}")
    print(f"   📊 Lines of Code: {summary['total_lines_of_code']}")
    print(f"   🔤 Languages: {', '.join(summary['languages_used'])}")
    print(f"   🎯 XEdit Paths: {summary['xedit_paths_created']}")
    
    # Validate quality
    validation = processor.validate_processing_quality(processing_result)
    print(f"\n🔍 QUALITY VALIDATION:")
    print(f"   📈 Overall Quality: {validation['overall_quality']}")
    print(f"   📝 Code Files Valid: {validation['code_files_valid']}")
    print(f"   🎯 XEdit Paths Valid: {validation['xedit_paths_valid']}")
    print(f"   🌐 Interface Generated: {validation['interface_generated']}")
    
    if validation["recommendations"]:
        print(f"   💡 Recommendations:")
        for rec in validation["recommendations"]:
            print(f"      • {rec}")
    
    if processing_result["error"]:
        print(f"❌ Error: {processing_result['error']}")
    
    return processing_result

if __name__ == "__main__":
    # Test IN-HOMING processor
    test_in_homing_processor()

class InHomingOrchestrator:
    """IN-HOMING orchestrator for processing MCP responses"""
    
    def __init__(self, mcp_client: Optional[Any] = None):
        self.mcp_client = mcp_client or MCPClient()
        self.logger = logging.getLogger(__name__)
    
    def process_mcp_response(self, response_text: str, project_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process MCP response and update project context
        
        Args:
            response_text: Raw response text from MCP
            project_context: Current project context including previous stages
            
        Returns:
            Updated project context with MCP response integrated
        """
        self.logger.info("Starting IN-HOMING processing of MCP response")
        
        try:
            # Parse the MCP response
            parsed_response = self._parse_mcp_response(response_text)
            
            # Update project context with MCP response
            project_context['mcp_response'] = parsed_response
            
            # Determine which stage to update based on the response
            stage_to_update = self._determine_stage_to_update(parsed_response, project_context)
            
            if stage_to_update:
                self._update_stage_with_mcp_response(stage_to_update, parsed_response, project_context)
                self.logger.info(f"Updated {stage_to_update} with MCP response")
            
            # Generate feedback for the user
            feedback = self._generate_user_feedback(parsed_response, project_context)
            project_context['feedback'] = feedback
            
            # Update project status
            project_context['status'] = self._update_project_status(project_context)
            
            self.logger.info("IN-HOMING processing completed successfully")
            return project_context
            
        except Exception as e:
            self.logger.error(f"Error in IN-HOMING processing: {str(e)}", exc_info=True)
            return {
                'status': 'error',
                'error': str(e),
                'original_response': response_text
            }
    
    def _parse_mcp_response(self, response_text: str) -> Dict[str, Any]:
        """Parse the MCP response into a structured format"""
        try:
            # Try to extract JSON from the response
            json_match = re.search(r'```json\n(.*?)\n```', response_text, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(1))
                
            # If no JSON found, try to parse as plain text
            return {
                'type': 'text_response',
                'content': response_text.strip()
            }
            
        except json.JSONDecodeError:
            # If JSON parsing fails, return as plain text
            return {
                'type': 'text_response',
                'content': response_text.strip()
            }
    
    def _determine_stage_to_update(self, parsed_response: Dict[str, Any], 
                                 project_context: Dict[str, Any]) -> Optional[str]:
        """Determine which project stage to update based on the MCP response"""
        # Check if response contains stage information
        if 'stage' in parsed_response:
            return parsed_response['stage']
            
        # Try to infer stage from response content
        content = parsed_response.get('content', '').lower()
        
        if any(term in content for term in ['requirements', 'analysis', 'spark']):
            return 'requirements_analysis'
            
        if any(term in content for term in ['architecture', 'design', 'falcon']):
            return 'architecture_design'
            
        if any(term in content for term in ['implementation', 'code', 'eagle']):
            return 'implementation'
            
        if any(term in content for term in ['test', 'qa', 'hawk']):
            return 'testing'
            
        return None
    
    def _update_stage_with_mcp_response(self, stage: str, parsed_response: Dict[str, Any], 
                                       project_context: Dict[str, Any]) -> None:
        """Update the specified stage with the MCP response"""
        if stage not in project_context:
            project_context[stage] = {}
            
        # Store the raw response
        project_context[stage]['mcp_response'] = parsed_response
        
        # Update stage status
        project_context[stage]['status'] = 'updated_with_mcp'
        project_context[stage]['last_updated'] = datetime.utcnow().isoformat()
        
        # Extract and store any specific updates
        if 'updates' in parsed_response:
            project_context[stage].update(parsed_response['updates'])
    
    def _generate_user_feedback(self, parsed_response: Dict[str, Any], 
                              project_context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate user-friendly feedback from the MCP response"""
        feedback = {
            'summary': 'MCP response processed',
            'actions': [],
            'next_steps': [],
            'warnings': []
        }
        
        # Extract summary if available
        if 'summary' in parsed_response:
            feedback['summary'] = parsed_response['summary']
        
        # Extract actions
        if 'actions' in parsed_response and isinstance(parsed_response['actions'], list):
            feedback['actions'] = parsed_response['actions']
        
        # Extract next steps
        if 'next_steps' in parsed_response and isinstance(parsed_response['next_steps'], list):
            feedback['next_steps'] = parsed_response['next_steps']
        
        # Extract warnings
        if 'warnings' in parsed_response and isinstance(parsed_response['warnings'], list):
            feedback['warnings'] = parsed_response['warnings']
        
        # Add timestamp
        feedback['timestamp'] = datetime.utcnow().isoformat()
        
        return feedback
    
    def _update_project_status(self, project_context: Dict[str, Any]) -> str:
        """Update the overall project status based on current state"""
        # Check for errors first
        if 'error' in project_context:
            return 'error'
            
        # Check if all stages are complete
        stages = ['requirements_analysis', 'architecture_design', 'implementation', 'testing']
        completed_stages = [
            stage for stage in stages 
            if project_context.get(stage, {}).get('status') in ['completed', 'updated_with_mcp']
        ]
        
        if len(completed_stages) == len(stages):
            return 'completed'
            
        # Default to in-progress
        return 'in_progress'
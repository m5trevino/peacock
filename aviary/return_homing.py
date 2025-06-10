#!/usr/bin/env python3
"""
return_homing.py - RETURN-HOMING Response Processor
Handles LLM responses and generates XEdit interfaces with 7x001 targeting
"""

import json
import re
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

class ReturnHomingProcessor:
    """RETURN-HOMING - The Response Handler & XEdit Generator"""
    
    def __init__(self):
        self.stage_name = "RETURN_HOMING"
        self.icon = "🔄"
        self.specialty = "Response Processing & XEdit Generation"
        self.session_timestamp = self._generate_session_timestamp()
        
    def _generate_session_timestamp(self):
        """Generate session timestamp matching other components"""
        now = datetime.datetime.now()
        week = now.isocalendar()[1]
        day = now.day
        hour = now.hour
        minute = now.minute
        return f"{week}-{day:02d}-{hour:02d}{minute:02d}"
    
    def process_pipeline_completion(self, pipeline_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main processing function - takes complete pipeline results and generates XEdit interface
        """
        
        print(f"🔄 RETURN-HOMING: Processing pipeline completion")
        
        processing_result = {
            "success": False,
            "session_timestamp": self.session_timestamp,
            "xedit_generated": False,
            "xedit_file_path": None,
            "parsed_data": None,
            "xedit_paths": None,
            "error": None
        }
        
        try:
            # Extract EAGLE implementation (main code content)
            eagle_result = pipeline_result.get("stage_results", {}).get("eagle", {})
            eagle_response = eagle_result.get("llm_response", "")
            
            if not eagle_response:
                processing_result["error"] = "No EAGLE implementation found in pipeline results"
                return processing_result
            
            # Parse the EAGLE response
            print("🔄 RETURN-HOMING: Parsing EAGLE implementation...")
            parsed_data = self._parse_llm_response(eagle_response)
            
            if not parsed_data["parsing_success"]:
                processing_result["error"] = f"Failed to parse EAGLE response: {parsed_data.get('error')}"
                return processing_result
            
            processing_result["parsed_data"] = parsed_data
            
            # Generate XEdit paths
            print("🔄 RETURN-HOMING: Generating XEdit paths...")
            xedit_paths = self._generate_xedit_paths(parsed_data["code_files"])
            processing_result["xedit_paths"] = xedit_paths
            
            # Generate XEdit interface
            print("🔄 RETURN-HOMING: Creating XEdit interface...")
            project_name = pipeline_result.get("user_request", "Generated Project")[:50]
            xedit_file_path = self._generate_xedit_interface(parsed_data, xedit_paths, project_name)
            
            processing_result["xedit_file_path"] = xedit_file_path
            processing_result["xedit_generated"] = True
            processing_result["success"] = True
            
            print(f"✅ RETURN-HOMING: XEdit interface generated at {xedit_file_path}")
            
        except Exception as e:
            processing_result["error"] = f"RETURN-HOMING processing failed: {str(e)}"
            print(f"❌ RETURN-HOMING ERROR: {e}")
        
        return processing_result
    
    def _parse_llm_response(self, response_text: str) -> Dict[str, Any]:
        """Parse LLM response into structured data"""
        
        parsed_data = {
            "parsing_success": True,
            "explanations": [],
            "code_files": [],
            "json_data": [],
            "implementation_notes": [],
            "total_sections": 0,
            "error": None
        }
        
        try:
            # Extract code files with enhanced patterns
            parsed_data["code_files"] = self._extract_code_files(response_text)
            
            # Extract explanations
            parsed_data["explanations"] = self._extract_explanations(response_text)
            
            # Extract JSON data
            parsed_data["json_data"] = self._extract_json_data(response_text)
            
            # Extract implementation notes
            parsed_data["implementation_notes"] = self._extract_implementation_notes(response_text)
            
            # Calculate totals
            parsed_data["total_sections"] = (
                len(parsed_data["code_files"]) + 
                len(parsed_data["explanations"]) + 
                len(parsed_data["json_data"]) + 
                len(parsed_data["implementation_notes"])
            )
            
            print(f"🔄 Parsed {len(parsed_data['code_files'])} code files, {parsed_data['total_sections']} total sections")
            
        except Exception as e:
            parsed_data["parsing_success"] = False
            parsed_data["error"] = str(e)
        
        return parsed_data
    
    def _extract_code_files(self, text: str) -> List[Dict[str, Any]]:
        """Extract code files with multiple patterns"""
        code_files = []
        
        # Pattern 1: **filename: path** followed by ```language
        pattern1 = r'\*\*filename:\s*([^*\n]+)\*\*\s*```(\w+)?\s*(.*?)```'
        matches1 = re.findall(pattern1, text, re.DOTALL | re.IGNORECASE)
        
        for filename, language, code in matches1:
            code_files.append({
                "filename": filename.strip(),
                "language": language.lower() if language else self._detect_language(filename),
                "code": code.strip(),
                "size": len(code.strip()),
                "type": "code_file",
                "source_pattern": "filename_header"
            })
        
        # Pattern 2: Simple code blocks if no filename blocks found
        if not code_files:
            pattern2 = r'```(\w+)?\s*(.*?)```'
            matches2 = re.findall(pattern2, text, re.DOTALL)
            
            for i, (language, code) in enumerate(matches2):
                if len(code.strip()) > 50:  # Filter out small snippets
                    ext = self._language_to_extension(language)
                    code_files.append({
                        "filename": f"main{ext}",
                        "language": language.lower() if language else "text",
                        "code": code.strip(),
                        "size": len(code.strip()),
                        "type": "code_file",
                        "source_pattern": "code_block"
                    })
        
        return code_files
    
    def _extract_explanations(self, text: str) -> List[Dict[str, Any]]:
        """Extract explanation paragraphs"""
        explanations = []
        
        # Remove code blocks and JSON for clean extraction
        clean_text = re.sub(r'```.*?```', '[CODE_BLOCK]', text, flags=re.DOTALL)
        clean_text = re.sub(r'\{.*?\}', '[JSON_BLOCK]', clean_text, flags=re.DOTALL)
        
        # Split into paragraphs
        paragraphs = [p.strip() for p in clean_text.split('\n\n') if p.strip()]
        
        for i, paragraph in enumerate(paragraphs):
            if (len(paragraph) > 80 and 
                '[CODE_BLOCK]' not in paragraph and 
                '[JSON_BLOCK]' not in paragraph and
                not paragraph.startswith('```') and
                not paragraph.startswith('**filename:')):
                
                explanations.append({
                    "index": i + 1,
                    "content": paragraph,
                    "length": len(paragraph),
                    "type": "explanation"
                })
        
        return explanations
    
    def _extract_json_data(self, text: str) -> List[Dict[str, Any]]:
        """Extract and validate JSON blocks"""
        json_blocks = []
        
        json_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
        json_matches = re.findall(json_pattern, text, re.DOTALL)
        
        for i, match in enumerate(json_matches):
            json_block = {
                "index": i + 1,
                "raw": match,
                "size": len(match),
                "valid": False,
                "data": None,
                "type": "json_data"
            }
            
            try:
                parsed_json = json.loads(match)
                json_block["valid"] = True
                json_block["data"] = parsed_json
                json_block["keys"] = list(parsed_json.keys()) if isinstance(parsed_json, dict) else []
            except json.JSONDecodeError:
                json_block["error"] = "Invalid JSON syntax"
            
            json_blocks.append(json_block)
        
        return json_blocks
    
    def _extract_implementation_notes(self, text: str) -> List[Dict[str, Any]]:
        """Extract implementation and technical notes"""
        notes = []
        
        note_patterns = [
            r'(?:implementation|technical|performance|optimization).*?(?=\n\n|\n\d+\.|\Z)',
            r'(?:notes?|details?|considerations?).*?(?=\n\n|\n\d+\.|\Z)',
        ]
        
        for pattern in note_patterns:
            matches = re.findall(pattern, text, re.DOTALL | re.IGNORECASE)
            for match in matches:
                if len(match.strip()) > 50:
                    notes.append({
                        "content": match.strip(),
                        "length": len(match.strip()),
                        "type": "implementation_note"
                    })
        
        return notes
    
    def _generate_xedit_paths(self, code_files: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Generate 7x001 style XEdit paths"""
        
        xedit_paths = {}
        path_counter = 1
        
        for file_data in code_files:
            filename = file_data["filename"]
            language = file_data["language"]
            code = file_data["code"]
            
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
        
        print(f"🔄 Generated {len(xedit_paths)} XEdit paths")
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
                    "line_end": min(i + 30, len(lines))
                })
        
        return elements
    
    def _parse_javascript_elements(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Parse JavaScript functions and classes"""
        elements = []
        
        for i, line in enumerate(lines, 1):
            # Function patterns
            func_patterns = [
                r'function\s+(\w+)\s*\(',
                r'(\w+)\s*:\s*function\s*\(',
                r'(\w+)\s*=\s*function\s*\(',
                r'(\w+)\s*=\s*\([^)]*\)\s*=>\s*\{',
            ]
            
            for pattern in func_patterns:
                match = re.search(pattern, line)
                if match:
                    elements.append({
                        "name": match.group(1),
                        "type": "function",
                        "line_start": i,
                        "line_end": min(i + 15, len(lines))
                    })
                    break
            
            # Class definitions
            class_match = re.search(r'class\s+(\w+)', line)
            if class_match:
                elements.append({
                    "name": class_match.group(1),
                    "type": "class",
                    "line_start": i,
                    "line_end": min(i + 25, len(lines))
                })
        
        return elements
    
    def _parse_html_elements(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Parse HTML elements with IDs"""
        elements = []
        
        for i, line in enumerate(lines, 1):
            id_match = re.search(r'<(\w+)[^>]*\sid=["\']([^"\']+)["\']', line)
            if id_match:
                elements.append({
                    "name": id_match.group(2),
                    "type": f"{id_match.group(1)}_element",
                    "line_start": i,
                    "line_end": i
                })
        
        return elements
    
    def _parse_css_elements(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Parse CSS selectors and classes"""
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
    
    def _generate_xedit_interface(self, parsed_data: Dict[str, Any], xedit_paths: Dict[str, Dict[str, Any]], project_name: str) -> str:
        """Generate complete XEdit HTML interface"""
        
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
        
        .function-info {{ display: flex; align-items: center; gap: 8px; }}
        .function-name {{ font-weight: 600; color: #79c0ff; }}
        .function-type {{ background: #30363d; color: #8b949e; padding: 2px 6px; border-radius: 3px; font-size: 10px; text-transform: uppercase; }}
        .xedit-id {{ font-family: 'SF Mono', monospace; background: #ff6b35; color: #0d1117; padding: 2px 6px; border-radius: 3px; font-size: 11px; font-weight: bold; }}
        
        .add-btn {{ position: absolute; top: 8px; right: 8px; background: #238636; border: none; color: white; width: 24px; height: 24px; border-radius: 4px; cursor: pointer; font-size: 14px; opacity: 0; transition: opacity 0.2s; }}
        .function-item:hover .add-btn {{ opacity: 1; }}
        
        .middle-panel {{ width: 340px; background: #161b22; border-right: 1px solid #30363d; display: flex; flex-direction: column; }}
        .payload-header {{ background: #238636; color: white; padding: 12px 16px; font-weight: 600; font-size: 14px; text-align: center; }}
        .payload-container {{ flex: 1; padding: 16px; display: flex; flex-direction: column; }}
        .payload-list {{ flex: 1; background: #21262d; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 16px; overflow-y: auto; min-height: 200px; }}
        .payload-empty {{ color: #6e7681; text-align: center; font-style: italic; margin-top: 50px; }}
        
        .payload-item {{ background: #2d333b; border: 1px solid #30363d; border-radius: 6px; padding: 12px; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center; }}
        .remove-btn {{ background: #da3633; border: none; color: white; width: 20px; height: 20px; border-radius: 3px; cursor: pointer; font-size: 12px; }}
        
        .send-button {{ width: 100%; background: #238636; border: none; color: white; padding: 15px; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; transition: all 0.2s; }}
        .send-button:disabled {{ background: #30363d; color: #8b949e; cursor: not-allowed; }}
        
        .right-panel {{ flex: 1; background: #0d1117; display: flex; flex-direction: column; }}
        .code-header {{ background: #21262d; padding: 12px 16px; border-bottom: 1px solid #30363d; font-weight: 600; font-size: 13px; color: #f0883e; }}
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
        <div class="project-info">
            Project: {project_name} • Session: <span class="session-info">{self.session_timestamp}</span>
        </div>
    </div>

    <div class="main-container">
        <div class="left-panel">
            <div class="panel-header">🎯 Functions & Classes ({len(xedit_paths)} items)</div>
            <div class="functions-list">
                {functions_html}
            </div>
        </div>

        <div class="middle-panel">
            <div class="payload-header">XEdit Payload</div>
            <div class="payload-container">
                <div class="payload-list" id="payload-list">
                    <div class="payload-empty">Click functions to add XEdit-Paths</div>
                </div>
                <button class="send-button" id="send-button" onclick="sendToMCP()" disabled>
                    🚀 Send 0 to MCP for Fixes
                </button>
            </div>
        </div>

        <div class="right-panel">
            <div class="code-header">📝 {project_name}: Generated Code</div>
            <div class="code-container">
                <div class="code-content">
                    {code_html}
                </div>
            </div>
        </div>
    </div>

    <script>
        const xeditPaths = {json.dumps(xedit_paths)};
        const sessionTimestamp = '{self.session_timestamp}';
        const projectName = '{project_name}';
        
        function highlightFunction(xeditId) {{
            // Clear previous highlights
            document.querySelectorAll('.code-line').forEach(line => {{
                line.classList.remove('highlighted');
            }});
            
            document.querySelectorAll('.function-item').forEach(item => {{
                item.classList.remove('selected');
            }});
            
            // Highlight selected function
            event.currentTarget.classList.add('selected');
            
            // Highlight code lines
            const pathData = xeditPaths[xeditId];
            if (pathData) {{
                const startLine = pathData.line_start;
                const endLine = pathData.line_end;
                
                for (let i = startLine; i <= endLine; i++) {{
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
            
            // Check if already added
            if (document.getElementById(`payload-${{xeditId}}`)) {{
                return;
            }}
            
            // Remove empty message
            const emptyMsg = payloadList.querySelector('.payload-empty');
            if (emptyMsg) {{
                emptyMsg.remove();
            }}
            
            // Add payload item
            const pathData = xeditPaths[xeditId];
            const payloadItem = document.createElement("div");
            payloadItem.className = "payload-item";
            payloadItem.id = `payload-${{xeditId}}`;
            payloadItem.innerHTML = `
                <div>
                    <span class="xedit-id">${{xeditId}}</span>
                    <div style="font-size: 12px; color: #8b949e; margin-top: 4px;">
                        ${{pathData.display_name}} (${{pathData.type}})
                    </div>
                </div>
                <button class="remove-btn" onclick="removeFromPayload('${{xeditId}}')">&times;</button>
            `;
            
            payloadList.appendChild(payloadItem);
            
            // Update send button
            const count = payloadList.children.length;
            sendButton.textContent = `🚀 Send ${{count}} to MCP for Fixes`;
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
                sendButton.textContent = "🚀 Send 0 to MCP for Fixes";
                sendButton.disabled = true;
            }} else {{
                sendButton.textContent = `🚀 Send ${{count}} to MCP for Fixes`;
            }}
        }}

        function sendToMCP() {{
            const payloadItems = document.querySelectorAll('.payload-item');
            const xeditIds = Array.from(payloadItems).map(item => {{
                return item.querySelector('.xedit-id').textContent;
            }});
            
            console.log('🎯 Sending XEdit-Paths to MCP:', xeditIds);
            
            // Send to MCP server
            fetch('http://127.0.0.1:8000/process', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{
                    command: 'fix_xedit_paths',
                    xedit_paths: xeditIds,
                    session: sessionTimestamp,
                    project: projectName
                }})
            }})
            .then(response => response.json())
            .then(data => {{
                console.log('✅ MCP Response:', data);
                if (data.success) {{
                    alert(`🎉 MCP processed ${{xeditIds.length}} XEdit-Paths successfully!`);
                }} else {{
                    alert(`❌ Error: ${{data.error}}`);
                }}
            }})
            .catch(error => {{
                console.error('❌ Error:', error);
                alert(`🚨 Connection error: ${{error.message}}`);
            }});
        }}
        
        console.log('🦚 Peacock XEdit Interface loaded');
        console.log('🎯 XEdit Paths:', Object.keys(xeditPaths).length);
    </script>
</body>
</html>"""
        
        # Save XEdit interface
        html_dir = Path("/home/flintx/peacock/html")
        html_dir.mkdir(exist_ok=True)
        
        file_path = html_dir / f"xedit-{self.session_timestamp}.html"
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        return str(file_path)
    
    def _combine_code_for_display(self, code_files: List[Dict[str, Any]]) -> str:
        """Combine all code files for display"""
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
            icon = "🏛️" if path_data["type"] == "class" else "⚡"
            
            functions_html += f"""
            <div class="function-item" onclick="highlightFunction('{xedit_id}')">
                <div class="function-info">
                    <span>{icon}</span>
                    <span class="function-name">{path_data['display_name']}</span>
                    <span class="function-type">{path_data['type']}</span>
                    <span class="xedit-id">{xedit_id}</span>
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
    
    def _detect_language(self, filename: str) -> str:
        """Detect programming language from filename"""
        ext_map = {
            '.html': 'html', '.css': 'css', '.js': 'javascript',
            '.py': 'python', '.java': 'java', '.cpp': 'cpp',
            '.c': 'c', '.php': 'php', '.rb': 'ruby',
            '.go': 'go', '.rs': 'rust', '.ts': 'typescript'
        }
        
        for ext, lang in ext_map.items():
            if filename.lower().endswith(ext):
                return lang
        
        return 'text'
    
    def _language_to_extension(self, language: str) -> str:
        """Convert language to file extension"""
        lang_map = {
            'html': '.html', 'css': '.css', 'javascript': '.js',
            'python': '.py', 'java': '.java', 'cpp': '.cpp',
            'c': '.c', 'php': '.php', 'ruby': '.rb'
        }
        
        return lang_map.get(language.lower(), '.txt')
    
    def _select_optimal_model(self, element_type: str, language: str) -> str:
        """Select optimal model based on element type and language"""
        if element_type == "class" or language in ["html", "css"]:
            return "gemma2-9b-it"  # Better structure handling
        else:
            return "llama-3.1-8b-instant"  # Better code analysis

# Factory function
def create_return_homing_processor() -> ReturnHomingProcessor:
    """Factory function to create RETURN-HOMING processor instance"""
    return ReturnHomingProcessor()

# Test function
def test_return_homing_processor():
    """Test the RETURN-HOMING processor with sample data"""
    
    print("🧪 TESTING RETURN-HOMING PROCESSOR")
    print("="*50)
    
    # Create processor
    processor = create_return_homing_processor()
    
    # Mock pipeline result with EAGLE implementation
    sample_eagle_response = '''Here is the complete snake game implementation:

**filename: index.html**
```html
<!DOCTYPE html>
<html>
<head>
    <title>Snake Game</title>
    <style>
        body { margin: 0; padding: 20px; background: #000; }
        canvas { border: 2px solid #fff; }
    </style>
</head>
<body>
    <canvas id="gameCanvas" width="400" height="400"></canvas>
    <script src="game.js"></script>
</body>
</html>
```

**filename: game.js**
```javascript
class SnakeGame {
    constructor() {
        this.canvas = document.getElementById('gameCanvas');
        this.ctx = this.canvas.getContext('2d');
        this.snake = [{x: 200, y: 200}];
        this.direction = {x: 0, y: 0};
        this.food = this.generateFood();
        this.score = 0;
    }
    
    generateFood() {
        return {
            x: Math.floor(Math.random() * 20) * 20,
            y: Math.floor(Math.random() * 20) * 20
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
    }
    
    draw() {
        this.ctx.fillStyle = '#000';
        this.ctx.fillRect(0, 0, 400, 400);
        
        this.ctx.fillStyle = '#0f0';
        this.snake.forEach(segment => {
            this.ctx.fillRect(segment.x, segment.y, 20, 20);
        });
        
        this.ctx.fillStyle = '#f00';
        this.ctx.fillRect(this.food.x, this.food.y, 20, 20);
    }
}

const game = new SnakeGame();

function gameLoop() {
    game.update();
    game.draw();
    setTimeout(gameLoop, 100);
}

gameLoop();
```

This implementation provides a complete working snake game with proper game mechanics.'''
    
    mock_pipeline_result = {
        "success": True,
        "user_request": "Build a snake game with HTML, CSS, and JavaScript",
        "stage_results": {
            "eagle": {
                "llm_response": sample_eagle_response,
                "success": True
            }
        }
    }
    
    # Test processing
    result = processor.process_pipeline_completion(mock_pipeline_result)
    
    print(f"\n📊 PROCESSING RESULTS:")
    print(f"✅ Success: {result.get('success')}")
    print(f"📅 Session: {result.get('session_timestamp')}")
    print(f"🎯 XEdit Generated: {result.get('xedit_generated')}")
    
    if result.get("success"):
        parsed_data = result.get("parsed_data", {})
        xedit_paths = result.get("xedit_paths", {})
        
        print(f"\n🔍 PARSING RESULTS:")
        print(f"   Code Files: {len(parsed_data.get('code_files', []))}")
        print(f"   Total Sections: {parsed_data.get('total_sections', 0)}")
        print(f"   XEdit Paths: {len(xedit_paths)}")
        
        print(f"\n🎯 XEDIT PATHS GENERATED:")
        for xedit_id, path_data in xedit_paths.items():
            print(f"   {xedit_id}: {path_data['display_name']} ({path_data['type']})")
        
        xedit_file = result.get("xedit_file_path")
        if xedit_file:
            print(f"\n📁 XEdit Interface: {xedit_file}")
        
    else:
        print(f"❌ Error: {result.get('error')}")
    
    return result

if __name__ == "__main__":
    # Test the processor
    test_return_homing_processor()
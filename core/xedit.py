#!/usr/bin/env python3
"""
MCP XEdit Parser - Complete Response to Interface System
Handles the FULL flow: LLM Response → Parsed Content → XEdit Interface with 7x001 paths
"""

import re
import json
import datetime
from pathlib import Path
from typing import Dict, List, Any, Tuple

class PeacockResponseParser:
    """Parse LLM responses into structured data for XEdit generation"""
    
    def __init__(self):
        self.session_timestamp = self._get_session_timestamp()
        
    def _get_session_timestamp(self):
        """Generate session timestamp matching other components"""
        now = datetime.datetime.now()
        week = now.isocalendar()[1]
        day = now.day
        hour = now.hour
        minute = now.minute
        return f"{week}-{day}-{hour}{minute:02d}"
    
    def parse_llm_response(self, response_text: str, project_name: str = "Generated Project") -> Dict[str, Any]:
        """
        Main parsing function - converts raw LLM response to structured data
        Returns everything needed for XEdit interface generation
        """
        
        print(f" PARSING LLM RESPONSE ({len(response_text)} chars)")
        
        parsed_data = {
            "project_name": project_name,
            "session_timestamp": self.session_timestamp,
            "explanations": [],
            "code_files": [],
            "json_data": [],
            "implementation_notes": [],
            "total_sections": 0,
            "parsing_success": True
        }
        
        try:
            # Step 1: Extract explanations
            parsed_data["explanations"] = self._extract_explanations(response_text)
            print(f" Found {len(parsed_data['explanations'])} explanations")
            
            # Step 2: Extract code files with proper structure
            parsed_data["code_files"] = self._extract_code_files(response_text)
            print(f" Found {len(parsed_data['code_files'])} code files")
            
            # Step 3: Extract JSON data
            parsed_data["json_data"] = self._extract_json_data(response_text)
            print(f" Found {len(parsed_data['json_data'])} JSON blocks")
            
            # Step 4: Extract implementation notes
            parsed_data["implementation_notes"] = self._extract_implementation_notes(response_text)
            print(f" Found {len(parsed_data['implementation_notes'])} implementation notes")
            
            # Step 5: Calculate totals
            parsed_data["total_sections"] = (
                len(parsed_data["explanations"]) + 
                len(parsed_data["code_files"]) + 
                len(parsed_data["json_data"]) + 
                len(parsed_data["implementation_notes"])
            )
            
            print(f" PARSING COMPLETE: {parsed_data['total_sections']} total sections")
            
        except Exception as e:
            print(f" PARSING ERROR: {e}")
            parsed_data["parsing_success"] = False
            parsed_data["error"] = str(e)
        
        return parsed_data
    
    def _extract_explanations(self, text: str) -> List[Dict[str, Any]]:
        """Extract explanation paragraphs from response"""
        explanations = []
        
        # Remove code blocks and JSON from text for explanation extraction
        clean_text = re.sub(r'```.*?```', '[CODE_BLOCK]', text, flags=re.DOTALL)
        clean_text = re.sub(r'\{.*?\}', '[JSON_BLOCK]', clean_text, flags=re.DOTALL)
        
        # Split into paragraphs
        paragraphs = [p.strip() for p in clean_text.split('\n\n') if p.strip()]
        
        for i, paragraph in enumerate(paragraphs):
            # Filter out placeholder text and short paragraphs
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
    
    def _extract_code_files(self, text: str) -> List[Dict[str, Any]]:
        """Extract code files with enhanced patterns"""
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
        
        # Pattern 2: Simple code blocks without explicit filenames
        if not code_files:  # Only if no filename-based blocks found
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
    
    def _extract_json_data(self, text: str) -> List[Dict[str, Any]]:
        """Extract and validate JSON blocks"""
        json_blocks = []
        
        # Enhanced JSON pattern - handles nested objects
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
        
        # Look for sections that contain implementation details
        note_patterns = [
            r'(?:implementation|technical|performance|optimization|improvement).*?(?=\n\n|\n\d+\.|\nNext|\nFinally|\Z)',
            r'(?:notes?|details?|considerations?).*?(?=\n\n|\n\d+\.|\nNext|\nFinally|\Z)',
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
    
    def _language_to_extension(self, language: str) -> str:
        """Convert language to file extension"""
        lang_map = {
            'html': '.html',
            'css': '.css',
            'javascript': '.js',
            'python': '.py',
            'java': '.java',
            'cpp': '.cpp',
            'c': '.c',
            'php': '.php',
            'ruby': '.rb',
            'go': '.go',
            'rust': '.rs',
            'typescript': '.ts'
        }
        
        return lang_map.get(language.lower(), '.txt')

class XEditPathGenerator:
    """Generate 7x001 style XEdit paths from parsed code"""
    
    def __init__(self):
        self.path_counter = 1
        
    def generate_xedit_paths(self, code_files: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Generate clean 7x001 style paths for all code elements"""
        
        xedit_paths = {}
        
        for file_data in code_files:
            filename = file_data["filename"]
            language = file_data["language"]
            code = file_data["code"]
            
            print(f" Analyzing {filename} ({language})")
            
            # Parse functions/classes in this file
            code_elements = self._parse_code_elements(code, language, filename)
            
            for element in code_elements:
                xedit_id = f"7x{self.path_counter:03d}"
                
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
                
                self.path_counter += 1
        
        print(f" Generated {len(xedit_paths)} XEdit paths")
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
                    "line_end": min(i + 20, len(lines))  # Estimate function length
                })
            
            # Class definitions
            class_match = re.match(r'^(\s*)class\s+(\w+)', line)
            if class_match:
                elements.append({
                    "name": class_match.group(2),
                    "type": "class",
                    "line_start": i,
                    "line_end": min(i + 30, len(lines))  # Estimate class length
                })
        
        return elements
    
    def _parse_javascript_elements(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Parse JavaScript functions and classes"""
        elements = []
        
        for i, line in enumerate(lines, 1):
            # Function declarations
            func_patterns = [
                r'function\s+(\w+)\s*\(',
                r'(\w+)\s*:\s*function\s*\(',
                r'(\w+)\s*=\s*function\s*\(',
                r'(\w+)\s*=\s*\([^)]*\)\s*=>\s*\{',
                r'(\w+)\s*=\s*async\s+\([^)]*\)\s*=>\s*\{'
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
            # Elements with IDs
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
        
        # Look for common patterns
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
    
    def _select_optimal_model(self, element_type: str, language: str) -> str:
        """Select optimal model based on element type and language"""
        # Based on your test results
        if element_type == "class" or language in ["html", "css"]:
            return "gemma2-9b-it"  # Better structure handling
        else:
            return "llama-3.1-8b-instant"  # Better code analysis

class XEditInterfaceGenerator:
    """Generate complete XEdit HTML interface from parsed data"""
    
    def __init__(self):
        pass
    
    def generate_interface(self, parsed_data: Dict[str, Any], xedit_paths: Dict[str, Dict[str, Any]]) -> str:
        """Generate complete XEdit HTML interface"""
        
        project_name = parsed_data["project_name"]
        session_timestamp = parsed_data["session_timestamp"]
        
        # Combine all code into display format
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
    <title> Peacock XEdit Interface - {project_name}</title>
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
        <div class="peacock-logo"> Peacock XEdit Interface</div>
        <div class="project-info">
            Project: {project_name} • Session: <span class="session-info">{session_timestamp}</span>
        </div>
    </div>

    <div class="main-container">
        <div class="left-panel">
            <div class="panel-header"> Functions & Classes ({len(xedit_paths)} items)</div>
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
                    Send 0 to MCP for Fixes
                </button>
            </div>
        </div>

        <div class="right-panel">
            <div class="code-header"> {project_name}: Generated Code</div>
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
            sendButton.textContent = `Send ${{count}} to MCP for Fixes`;
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
                sendButton.textContent = "Send 0 to MCP for Fixes";
                sendButton.disabled = true;
            }} else {{
                sendButton.textContent = `Send ${{count}} to MCP for Fixes`;
            }}
        }}

        function sendToMCP() {{
            const payloadItems = document.querySelectorAll('.payload-item');
            const xeditIds = Array.from(payloadItems).map(item => {{
                return item.querySelector('.xedit-id').textContent;
            }});
            
            console.log('Sending XEdit-Paths to MCP:', xeditIds);
            
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
                console.log('MCP Response:', data);
                if (data.success) {{
                    alert(` MCP processed ${{xeditIds.length}} XEdit-Paths successfully!`);
                }} else {{
                    alert(` Error: ${{data.error}}`);
                }}
            }})
            .catch(error => {{
                console.error('Error:', error);
                alert(` Connection error: ${{error.message}}`);
            }});
        }}
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
            icon = "" if path_data["type"] == "class" else ""
            
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

class MCPIntegrationHandler:
    """Complete MCP integration for response parsing and XEdit generation"""
    
    def __init__(self):
        self.parser = PeacockResponseParser()
        self.path_generator = XEditPathGenerator()
        self.interface_generator = XEditInterfaceGenerator()
        
    def process_llm_response_to_xedit(self, response_text: str, project_name: str = "Generated Project") -> Dict[str, Any]:
        """
        Complete flow: LLM Response → Parsed Data → XEdit Paths → HTML Interface
        This is the main function MCP should call
        """
        
        print(" " + "="*60 + " ")
        print("    PEACOCK RESPONSE → XEDIT PROCESSING")
        print(" " + "="*60 + " ")
        
        result = {
            "success": False,
            "error": None,
            "parsed_data": None,
            "xedit_paths": None,
            "html_interface": None,
            "file_path": None,
            "session_timestamp": None
        }
        
        try:
            # Step 1: Parse LLM response
            print("  STEP 1: Parsing LLM response...")
            parsed_data = self.parser.parse_llm_response(response_text, project_name)
            
            if not parsed_data["parsing_success"]:
                result["error"] = f"Parsing failed: {parsed_data.get('error', 'Unknown error')}"
                return result
            
            result["parsed_data"] = parsed_data
            result["session_timestamp"] = parsed_data["session_timestamp"]
            
            # Step 2: Generate XEdit paths
            print("  STEP 2: Generating XEdit paths...")
            xedit_paths = self.path_generator.generate_xedit_paths(parsed_data["code_files"])
            result["xedit_paths"] = xedit_paths
            
            # Step 3: Generate HTML interface
            print("  STEP 3: Generating HTML interface...")
            html_interface = self.interface_generator.generate_interface(parsed_data, xedit_paths)
            result["html_interface"] = html_interface
            
            # Step 4: Save to file
            print("  STEP 4: Saving XEdit interface...")
            file_path = self._save_xedit_interface(html_interface, parsed_data["session_timestamp"])
            result["file_path"] = file_path
            
            result["success"] = True
            
            print(" XEDIT GENERATION COMPLETE!")
            print(f"  File: {file_path}")
            print(f"  XEdit Paths: {len(xedit_paths)}")
            print(f"  Total Sections: {parsed_data['total_sections']}")
            
        except Exception as e:
            print(f" XEDIT GENERATION FAILED: {e}")
            result["error"] = str(e)
        
        return result
    
    def _save_xedit_interface(self, html_content: str, session_timestamp: str) -> str:
        """Save XEdit interface to file"""
        output_dir = Path("/home/flintx/peacock/html")
        output_dir.mkdir(exist_ok=True)
        
        file_path = output_dir / f"xedit-{session_timestamp}.html"
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        return str(file_path)

# MAIN FUNCTIONS FOR MCP INTEGRATION

def process_eagle_response_to_xedit(eagle_response_text: str, project_name: str = "Generated Project") -> Dict[str, Any]:
    """
    Main function for MCP to call when EAGLE response comes back
    
    Args:
        eagle_response_text: Raw text response from EAGLE stage
        project_name: Name of the project for the interface
    
    Returns:
        Dict with success, file_path, xedit_paths, and other data
    """
    
    handler = MCPIntegrationHandler()
    return handler.process_llm_response_to_xedit(eagle_response_text, project_name)

def test_parser_with_sample():
    """Test the parser with a sample response"""
    
    sample_response = """I'll create a simple calculator app for you.

First, let me explain my approach. I'll use HTML5 with embedded CSS and JavaScript to create a fully functional calculator that works in any modern browser.

**filename: calculator.html**
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Simple Calculator</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background-color: #f0f0f0;
        }
        
        .calculator {
            background-color: #333;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 10px rgba(0,0,0,0.3);
        }
        
        .display {
            width: 100%;
            height: 60px;
            font-size: 24px;
            text-align: right;
            margin-bottom: 10px;
            padding: 0 10px;
            border: none;
            background-color: #000;
            color: white;
        }
        
        .buttons {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 10px;
        }
        
        button {
            height: 60px;
            font-size: 18px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            transition: background-color 0.2s;
        }
        
        .number, .decimal {
            background-color: #666;
            color: white;
        }
        
        .operator {
            background-color: #ff9500;
            color: white;
        }
        
        .clear, .equals {
            background-color: #a6a6a6;
            color: black;
        }
        
        button:hover {
            opacity: 0.8;
        }
    </style>
</head>
<body>
    <div class="calculator">
        <input type="text" class="display" id="display" readonly>
        <div class="buttons">
            <button class="clear" onclick="clearDisplay()">C</button>
            <button class="clear" onclick="clearEntry()">CE</button>
            <button class="operator" onclick="appendToDisplay('/')">/</button>
            <button class="operator" onclick="appendToDisplay('*')">×</button>
            
            <button class="number" onclick="appendToDisplay('7')">7</button>
            <button class="number" onclick="appendToDisplay('8')">8</button>
            <button class="number" onclick="appendToDisplay('9')">9</button>
            <button class="operator" onclick="appendToDisplay('-')">-</button>
            
            <button class="number" onclick="appendToDisplay('4')">4</button>
            <button class="number" onclick="appendToDisplay('5')">5</button>
            <button class="number" onclick="appendToDisplay('6')">6</button>
            <button class="operator" onclick="appendToDisplay('+')">+</button>
            
            <button class="number" onclick="appendToDisplay('1')">1</button>
            <button class="number" onclick="appendToDisplay('2')">2</button>
            <button class="number" onclick="appendToDisplay('3')">3</button>
            <button class="equals" onclick="calculateResult()" rowspan="2">=</button>
            
            <button class="number" onclick="appendToDisplay('0')" colspan="2">0</button>
            <button class="decimal" onclick="appendToDisplay('.')">.</button>
        </div>
    </div>

    <script>
        let display = document.getElementById('display');
        let currentInput = '';
        let operator = '';
        let previousInput = '';

        function appendToDisplay(value) {
            if (['+', '-', '*', '/'].includes(value)) {
                if (currentInput !== '') {
                    if (previousInput !== '' && operator !== '') {
                        calculateResult();
                    }
                    previousInput = currentInput;
                    operator = value;
                    currentInput = '';
                }
            } else {
                currentInput += value;
            }
            updateDisplay();
        }

        function updateDisplay() {
            display.value = previousInput + ' ' + operator + ' ' + currentInput;
        }

        function clearDisplay() {
            currentInput = '';
            operator = '';
            previousInput = '';
            display.value = '';
        }

        function clearEntry() {
            currentInput = '';
            updateDisplay();
        }

        function calculateResult() {
            if (previousInput !== '' && currentInput !== '' && operator !== '') {
                let result;
                const prev = parseFloat(previousInput);
                const current = parseFloat(currentInput);
                
                switch (operator) {
                    case '+':
                        result = prev + current;
                        break;
                    case '-':
                        result = prev - current;
                        break;
                    case '*':
                        result = prev * current;
                        break;
                    case '/':
                        result = current !== 0 ? prev / current : 'Error';
                        break;
                    default:
                        return;
                }
                
                display.value = result;
                currentInput = result.toString();
                operator = '';
                previousInput = '';
            }
        }
    </script>
</body>
</html>
```

After creating the code, here's the project analysis:

{
    "project_name": "Simple Calculator",
    "complexity_level": "beginner",
    "technologies_used": ["HTML5", "CSS3", "JavaScript"],
    "estimated_dev_time": "2-3 hours",
    "key_features": ["basic math operations", "clear function", "responsive design", "error handling"],
    "code_lines": 150,
    "browser_compatibility": ["Chrome", "Firefox", "Safari", "Edge"],
    "mobile_friendly": true,
    "performance_notes": "Lightweight and fast"
}

Finally, here are some implementation notes:

The calculator uses a grid layout for the buttons and includes proper error handling for division by zero. The design is responsive and will work well on both desktop and mobile devices. 

For future improvements, you could add:
- Keyboard support
- Memory functions (M+, M-, MR, MC)
- History of calculations
- Scientific calculator functions
- Themes and customization options

The code is well-structured and easy to maintain, with clear separation between HTML structure, CSS styling, and JavaScript functionality."""

    print("  TESTING PARSER WITH SAMPLE RESPONSE...")
    result = process_eagle_response_to_xedit(sample_response, "Sample Calculator Project")
    
    if result["success"]:
        print("  TEST SUCCESSFUL!")
        print(f"  XEdit Interface: {result['file_path']}")
        print(f"  XEdit Paths Generated: {len(result['xedit_paths'])}")
        
        print("\n  GENERATED XEDIT PATHS:")
        for xedit_id, path_data in result["xedit_paths"].items():
            print(f"    {xedit_id}: {path_data['display_name']} ({path_data['type']})")
    else:
        print(f"  TEST FAILED: {result['error']}")

if __name__ == "__main__":
    test_parser_with_sample()
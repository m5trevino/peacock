#!/usr/bin/env python3
"""
in-homing.py - IN-HOMING Response Processing & XEdit Generation Bird
Handles LLM2 responses coming back IN and creates the final XEdit interface
"""

import json
import re
import datetime
from pathlib import Path
import sys
import subprocess

# Add core directory to path for xedit imports
core_path = Path(__file__).parent.parent / "core"
if str(core_path) not in sys.path:
    sys.path.insert(0, str(core_path))
from typing import Dict, List, Any, Optional

from schemas import FinalCodeOutput

class InHomingProcessor:
    """IN-HOMING - The Response Handler & XEdit Generator"""
    
    def __init__(self):
        self.stage_name = "IN-HOMING"
        self.icon = "🔄"
        self.specialty = "LLM2 Response Processing & XEdit Generation"
    
    def _generate_session_timestamp(self):
        """Generate session timestamp in week-day-hourminute format"""
        now = datetime.datetime.now()
        week = now.isocalendar()[1]
        day = now.day
        hour_minute = now.strftime("%H%M")
        return f"{week:02d}-{day:02d}-{hour_minute}"
    
    def process_llm2_response(self, llm2_response: str, pipeline_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main IN-HOMING function - process LLM2 response and generate XEdit interface
        """
        print(f"🔄 IN-HOMING: Processing LLM2 response and generating XEdit...")
        
        session_timestamp = pipeline_metadata.get("session_timestamp", self._generate_session_timestamp())

        processing_result = {
            "success": False,
            "llm2_response": llm2_response,
            "pipeline_metadata": pipeline_metadata,
            "parsed_data": {},
            "xedit_interface": None,
            "xedit_paths": {},
            "project_files": [],
            "session_timestamp": session_timestamp,
            "processing_timestamp": datetime.datetime.now().isoformat(),
            "error": None,
            "xedit_file_path": None
        }
        
        try:
            # Parse the LLM2 response using the Pydantic schema
            parsed_data = self._parse_llm2_response(llm2_response)
            processing_result["parsed_data"] = parsed_data.dict() if parsed_data else {}
            
            # The parsed_data is now a Pydantic model, so we access its attributes
            project_files = [file.dict() for file in parsed_data.files] if parsed_data else []
            processing_result["project_files"] = project_files
            
            # Generate XEdit paths
            processing_result["xedit_paths"] = self._generate_xedit_paths(project_files)
            
            # Call xedit.py to generate the HTML file
            xedit_file_path = self._call_xedit_generator(processing_result, session_timestamp)
            
            processing_result["xedit_file_path"] = str(xedit_file_path)
            processing_result["success"] = True
            
            print(f"✅ IN-HOMING: Processing completed successfully!")
            print(f"📁 Generated: {len(project_files)} files")
            print(f"🎯 XEdit Paths: {len(processing_result['xedit_paths'])}")
            print(f"💾 Saved: {xedit_file_path}")
            
        except Exception as e:
            processing_result["error"] = str(e)
            processing_result["success"] = False
            print(f"❌ IN-HOMING: Processing failed - {e}")
        
        return processing_result
    
    def _parse_llm2_response(self, response_text: str) -> Optional[FinalCodeOutput]:
        """Parse the LLM2 response using our Pydantic schema."""
        print("Parsing LLM response with Pydantic schema...")
        try:
            # First, try to find a JSON code block, which is the most reliable format
            json_match = re.search(r"```json\n(.*?)```", response_text, re.DOTALL)
            if json_match:
                json_text = json_match.group(1)
                return FinalCodeOutput.parse_raw(json_text)
            else:
                # If no JSON block is found, try to parse the whole string
                try:
                    return FinalCodeOutput.parse_raw(response_text)
                except:
                    # Fallback for models that don't follow the JSON schema and just return raw code
                    code_files = self._extract_raw_code_blocks(response_text)
                    if not code_files:
                        raise ValueError("Could not parse LLM response as JSON or extract any code blocks.")
                    
                    return FinalCodeOutput(
                        project_name="Unknown Project (from raw extraction)",
                        files=code_files
                    )
        except (json.JSONDecodeError, ValueError) as e:
            print(f"⚠️ Pydantic parsing failed: {e}. Falling back to raw code block extraction.")
            # Fallback for models that don't follow the JSON schema and just return raw code
            code_files = self._extract_raw_code_blocks(response_text)
            if not code_files:
                raise ValueError("Could not parse LLM response as JSON or extract any code blocks.")
            
            return FinalCodeOutput(
                project_name="Unknown Project (from raw extraction)",
                files=code_files
            )

    def _extract_raw_code_blocks(self, response_text: str) -> List[Dict[str, Any]]:
        """Fallback to extract raw code blocks when JSON parsing fails."""
        print("Extracting raw code blocks...")
        code_files = []
        
        # First try to find filename-based code blocks
        filename_pattern = r'```filename:\s*([^\n]+)\n(.*?)\n```'
        filename_matches = re.findall(filename_pattern, response_text, re.DOTALL)
        
        if filename_matches:
            for filename, code in filename_matches:
                lang = self._detect_language_from_filename(filename.strip())
                file_data = {
                    "filename": filename.strip(),
                    "language": lang,
                    "code": code.strip(),
                }
                code_files.append(file_data)
                print(f"📄 Found file: {file_data['filename']} ({file_data['language']})")
        else:
            # A more generic pattern to find any markdown code block
            pattern = r'```(\w*)\n(.*?)```'
            matches = re.findall(pattern, response_text, re.DOTALL)
            for file_index, (language, code) in enumerate(matches):
                lang = language.lower() or self._detect_language_from_content(code)
                file_data = {
                    "filename": f"file{file_index+1}.{lang}",
                    "language": lang,
                    "code": code.strip(),
                }
                code_files.append(file_data)
                print(f"📄 Found raw block: {file_data['filename']} ({file_data['language']})")
        
        return code_files

    def _detect_language_from_filename(self, filename: str) -> str:
        """Detect programming language from filename"""
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

    def _detect_language_from_content(self, code: str) -> str:
        """A simple heuristic to guess the language from code content."""
        if code.strip().startswith("<!DOCTYPE html>") or "<html" in code:
            return "html"
        if "def " in code and ":" in code:
            return "python"
        if "function " in code and "{" in code:
            return "javascript"
        if "{" in code and ":" in code and "}" in code:
            return "css"
        return "txt"
    
    def _generate_xedit_paths(self, project_files: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Generate 7x001 style XEdit paths for all code elements"""
        
        xedit_paths = {}
        path_counter = 1
        
        for file_data in project_files:
            filename = file_data["filename"]
            language = file_data.get("language", "text")
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
            
            # Method definitions (inside classes)
            method_match = re.search(r'^\s+(\w+)\s*\([^)]*\)\s*\{', line)
            if method_match and not line.strip().startswith('//'):
                elements.append({
                    "name": method_match.group(1),
                    "type": "method",
                    "line_start": line_num,
                    "line_end": min(line_num + 12, len(lines))
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
            return "meta-llama/llama-4-scout-17b-16e-instruct"
        else:
            return "meta-llama/llama-4-maverick-17b-128e-instruct"

    def _call_xedit_generator(self, processing_result: Dict[str, Any], session_timestamp: str) -> str:
        """Call xedit.py to generate the HTML interface - FIXED"""
        try:
            # Create a simple XEdit HTML file directly
            html_dir = Path("/home/flintx/peacock/html")
            html_dir.mkdir(exist_ok=True)
            
            output_path = html_dir / f"xedit-{session_timestamp}.html"
            
            # Get data
            parsed_data = processing_result["parsed_data"]
            xedit_paths = processing_result["xedit_paths"]
            project_files = processing_result["project_files"]
            
            # Generate simple XEdit HTML
            html_content = self._generate_simple_xedit_html(parsed_data, xedit_paths, project_files, session_timestamp)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"✅ XEdit interface generated: {output_path}")
            return str(output_path)
            
        except Exception as e:
            print(f"❌ XEdit generation failed: {e}")
            print(f"❌ Error details: {str(e)}")
            
            # Try to create a simple HTML file as fallback
            fallback_path = f"/home/flintx/peacock/html/xedit-{session_timestamp}.html"
            try:
                Path("/home/flintx/peacock/html").mkdir(parents=True, exist_ok=True)
                with open(fallback_path, 'w') as f:
                    f.write(f"""<!DOCTYPE html>
<html><head><title>XEdit - {session_timestamp}</title></head>
<body>
<h1>🦚 Peacock XEdit Interface</h1>
<p>Session: {session_timestamp}</p>
<p>XEdit generation encountered an error: {str(e)}</p>
<p>This is a fallback interface.</p>
</body></html>""")
                print(f"✅ Created fallback XEdit file: {fallback_path}")
                return fallback_path
            except Exception as fallback_error:
                print(f"❌ Even fallback failed: {fallback_error}")
                return f"/home/flintx/peacock/html/xedit-{session_timestamp}-error.html"
    
    def _generate_simple_xedit_html(self, parsed_data: Dict[str, Any], xedit_paths: Dict[str, Dict[str, Any]], project_files: List[Dict[str, Any]], session_timestamp: str) -> str:
        """Generate a simple XEdit HTML interface"""
        
        project_name = parsed_data.get("project_name", "Generated Project")
        
        # Generate functions list
        functions_html = ""
        for xedit_id, data in xedit_paths.items():
            functions_html += f"""
            <div class="function-item" onclick="highlightFunction('{xedit_id}')">
                <strong>{data['display_name']}</strong> ({data['type']})
                <br><small>{data['filename']} • Lines {data['lines_display']}</small>
            </div>
            """
        
        # Generate code display
        code_html = ""
        for file_data in project_files:
            code_html += f"// FILE: {file_data['filename']}\n"
            code_html += f"{file_data['code']}\n\n"
        
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>🦚 XEdit - {project_name}</title>
    <style>
        body {{ font-family: monospace; background: #1a1a1a; color: #00ff00; margin: 0; padding: 20px; }}
        .container {{ display: flex; height: 100vh; }}
        .left-panel {{ width: 30%; background: #2a2a2a; padding: 20px; overflow-y: auto; }}
        .right-panel {{ width: 70%; background: #0a0a0a; padding: 20px; overflow-y: auto; }}
        .function-item {{ padding: 10px; margin: 5px 0; background: #333; cursor: pointer; border-radius: 5px; }}
        .function-item:hover {{ background: #555; }}
        .code-display {{ white-space: pre-wrap; font-size: 14px; line-height: 1.4; }}
        h2 {{ color: #00ffff; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="left-panel">
            <h2>🔧 Functions & Elements</h2>
            {functions_html}
        </div>
        <div class="right-panel">
            <h2>💻 Generated Code</h2>
            <div class="code-display">{code_html}</div>
        </div>
    </div>
    
    <script>
        function highlightFunction(xeditId) {{
            console.log('Selected:', xeditId);
            // Remove previous highlights
            document.querySelectorAll('.function-item').forEach(item => {{
                item.style.background = '#333';
            }});
            // Highlight selected
            event.target.style.background = '#00ff00';
            event.target.style.color = '#000';
        }}
        
        console.log('🦚 XEdit Interface Loaded');
        console.log('Session: {session_timestamp}');
        console.log('Project: {project_name}');
    </script>
</body>
</html>"""
    
    def deploy_and_run(self, project_files, project_name):
        """Deploy and run a PCOCK project"""
        try:
            # Create a directory for the project
            project_dir = Path(f"/home/flintx/peacock/apps/{project_name}")
            project_dir.mkdir(parents=True, exist_ok=True)
            
            # Write all files to the project directory
            for file_data in project_files:
                filename = file_data.get("filename")
                code = file_data.get("code", "")
                
                if filename and code:
                    file_path = project_dir / filename
                    with open(file_path, 'w') as f:
                        f.write(code)
                    print(f"✅ Created file: {file_path}")
            
            # Create a simple HTML wrapper to view the project
            wrapper_path = project_dir / "index.html"
            if not wrapper_path.exists():
                with open(wrapper_path, 'w') as f:
                    f.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>{project_name}</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <h1>{project_name}</h1>
    <div id="app-container">
        <iframe src="{project_files[0]['filename']}" style="width: 100%; height: 80vh; border: 1px solid #ccc;"></iframe>
    </div>
</body>
</html>""")
            
            # Return success with app URL
            app_url = f"file://{project_dir}/index.html"
            return {
                "success": True,
                "message": f"Project {project_name} deployed successfully",
                "app_url": app_url,
                "project_dir": str(project_dir),
                "files_created": len(project_files)
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Deployment failed: {str(e)}"
            }
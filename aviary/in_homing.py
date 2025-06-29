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
import os

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
            "error": None
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
            
            # Create a fallback XEdit file with error information
            try:
                fallback_path = self._create_fallback_xedit(llm2_response, session_timestamp, str(e))
                processing_result["xedit_file_path"] = str(fallback_path)
                print(f"✅ Created fallback XEdit file: {fallback_path}")
            except Exception as fallback_error:
                print(f"❌ Even fallback failed: {fallback_error}")
        
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
                return FinalCodeOutput.parse_raw(response_text)
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
        
        # First try to find filename-based code blocks (most common format)
        filename_pattern = r'```filename:\s*([^\n]+)\n(.*?)```'
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
                print(f"📄 Found filename block: {file_data['filename']} ({file_data['language']})")
        else:
            # If no filename blocks found, try generic code blocks
            pattern = r'```(\w*)\n(.*?)```'
            matches = re.findall(pattern, response_text, re.DOTALL)
            for i, (language, code) in enumerate(matches):
                lang = language.lower() or self._detect_language_from_content(code)
                
                # Try to infer filename from content
                filename = self._infer_filename_from_content(code, lang, i)
                
                file_data = {
                    "filename": filename,
                    "language": lang,
                    "code": code.strip(),
                }
                code_files.append(file_data)
                print(f"📄 Found raw block: {file_data['filename']} ({file_data['language']})")
        
        return code_files

    def _detect_language_from_filename(self, filename: str) -> str:
        """Detect language from filename extension."""
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
            '.ts': 'typescript',
            '.jsx': 'jsx',
            '.tsx': 'tsx',
            '.json': 'json',
            '.md': 'markdown',
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
        if "{" in code and ":" in code and "}" in code and not "function" in code:
            return "css"
        return "text"
    
    def _infer_filename_from_content(self, code: str, language: str, index: int) -> str:
        """Infer a reasonable filename based on code content and language."""
        # Default filenames by language
        defaults = {
            'html': 'index.html',
            'css': 'style.css',
            'javascript': 'script.js',
            'python': 'main.py',
            'java': 'Main.java',
            'typescript': 'index.ts',
            'jsx': 'App.jsx',
            'tsx': 'App.tsx',
        }
        
        # Try to find clues in the content
        if language == 'html':
            title_match = re.search(r'<title>(.*?)</title>', code)
            if title_match:
                title = title_match.group(1).lower().replace(' ', '_')
                return f"{title}.html"
        
        elif language == 'javascript':
            # Look for class or main function name
            class_match = re.search(r'class\s+(\w+)', code)
            if class_match:
                return f"{class_match.group(1).lower()}.js"
            
            # Look for main function or component
            func_match = re.search(r'function\s+(\w+)', code)
            if func_match and func_match.group(1) not in ['render', 'init', 'setup']:
                return f"{func_match.group(1).lower()}.js"
        
        # Use default if we couldn't infer
        if language in defaults:
            return defaults[language]
        
        # Generic fallback
        return f"file{index+1}.{language or 'txt'}"
    
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
        
        for i, line in enumerate(lines, 1):
            # Function definitions
            func_match = re.search(r'def\s+(\w+)\s*\(', line)
            if func_match:
                elements.append({
                    "name": func_match.group(1),
                    "type": "function",
                    "line_start": i,
                    "line_end": min(i + 15, len(lines))
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
        """Parse HTML elements and sections"""
        elements = []
        
        for i, line in enumerate(lines, 1):
            # HTML tags with IDs or classes
            tag_match = re.search(r'<(\w+)(?:\s+(?:id|class)="([^"]+)")', line)
            if tag_match:
                tag_name, identifier = tag_match.groups()
                elements.append({
                    "name": f"{tag_name}#{identifier}" if 'id=' in line else f"{tag_name}.{identifier}",
                    "type": "element",
                    "line_start": i,
                    "line_end": min(i + 5, len(lines))
                })
        
        return elements

    def _parse_css_elements(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Parse CSS selectors and rules"""
        elements = []
        
        for i, line in enumerate(lines, 1):
            # CSS selectors
            selector_match = re.search(r'^([.#]?[\w-]+)\s*\{', line.strip())
            if selector_match:
                elements.append({
                    "name": selector_match.group(1),
                    "type": "selector",
                    "line_start": i,
                    "line_end": min(i + 10, len(lines))
                })
        
        return elements

    def _parse_generic_elements(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Generic parsing for unknown file types"""
        elements = []
        
        for i, line in enumerate(lines, 1):
            # Look for function-like patterns
            func_pattern = re.search(r'(\w+)\s*\(.*\)\s*[{:]', line)
            if func_pattern:
                elements.append({
                    "name": func_pattern.group(1),
                    "type": "function",
                    "line_start": i,
                    "line_end": min(i + 10, len(lines))
                })
        
        return elements

    def _select_optimal_model(self, element_type: str, language: str) -> str:
        """Select optimal model for editing this element"""
        if language in ['python', 'javascript']:
            return "meta-llama/llama-4-scout-17b-16e-instruct"
        else:
            return "meta-llama/llama-4-maverick-17b-128e-instruct"

    def _call_xedit_generator(self, processing_result: Dict[str, Any], session_timestamp: str) -> str:
        """Call xedit.py to generate the HTML interface"""
        try:
            # Import XEdit generator from the actual classes in your xedit.py
            sys.path.insert(0, str(Path(__file__).parent.parent / "core"))
            from xedit import EnhancedXEditGenerator
            
            # Create generator instance
            xedit_generator = EnhancedXEditGenerator()
            
            # Generate the HTML file using the method that actually exists
            xedit_file_path = xedit_generator.generate_enhanced_xedit_html(
                parsed_data=processing_result["parsed_data"],
                xedit_paths=processing_result["xedit_paths"], 
                session_id=session_timestamp
            )
            
            return xedit_file_path
            
        except Exception as e:
            print(f"❌ XEdit generation failed: {e}")
            print(f"❌ Error details: {str(e)}")
            
            # Try to create a simple HTML file as fallback
            fallback_path = self._create_fallback_xedit(
                processing_result["llm2_response"], 
                session_timestamp, 
                str(e)
            )
            return fallback_path
    
    def _create_fallback_xedit(self, response_text: str, session_timestamp: str, error_message: str) -> str:
        """Create a fallback XEdit HTML file when normal generation fails"""
        fallback_path = f"/home/flintx/peacock/html/xedit-{session_timestamp}.html"
        
        try:
            # Ensure directory exists
            Path("/home/flintx/peacock/html").mkdir(parents=True, exist_ok=True)
            
            # Extract any code blocks for display
            code_blocks = re.findall(r'```(?:\w+)?\n(.*?)\n```', response_text, re.DOTALL)
            code_display = "\n\n".join(code_blocks) if code_blocks else response_text
            
            # Create a simple HTML file
            with open(fallback_path, 'w') as f:
                f.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>XEdit - Session {session_timestamp}</title>
    <style>
        body {{ font-family: monospace; background: #1e1e1e; color: #d4d4d4; padding: 20px; }}
        h1 {{ color: #ff6b35; }}
        .error {{ color: #ff0000; background: #2d2d2d; padding: 10px; border-left: 5px solid #ff0000; margin: 20px 0; }}
        pre {{ background: #2d2d2d; padding: 15px; overflow: auto; white-space: pre-wrap; }}
        .info {{ color: #3794ff; background: #2d2d2d; padding: 10px; border-left: 5px solid #3794ff; margin: 20px 0; }}
    </style>
</head>
<body>
    <h1>🦚 Peacock XEdit - Fallback Mode</h1>
    
    <div class="info">
        <strong>Session:</strong> {session_timestamp}<br>
        <strong>Generated:</strong> {datetime.datetime.now().isoformat()}<br>
        <strong>Mode:</strong> Fallback (Error Recovery)
    </div>
    
    <div class="error">
        <strong>XEdit Generation Error:</strong><br>
        {error_message}
    </div>
    
    <h2>Generated Code:</h2>
    <pre>{code_display}</pre>
</body>
</html>""")
            
            print(f"✅ Created fallback XEdit file: {fallback_path}")
            return fallback_path
            
        except Exception as fallback_error:
            print(f"❌ Even fallback failed: {fallback_error}")
            return f"/home/flintx/peacock/html/xedit-{session_timestamp}-error.html"
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
from enhanced_robust_parser import create_enhanced_parser

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
            print(f"🔍 DEBUG: Starting LLM2 response parsing...")
            print(f"🔍 DEBUG: Response length: {len(llm2_response)} characters")
            print(f"🔍 DEBUG: Response preview: {llm2_response[:500]}...")
            
            parsed_data = self._parse_llm2_response(llm2_response)
            
            print(f"🔍 DEBUG: Parsed data result: {parsed_data is not None}")
            if parsed_data:
                print(f"🔍 DEBUG: Files in parsed data: {len(parsed_data.files)}")
            
            processing_result["parsed_data"] = parsed_data.dict() if parsed_data else {}
            
            # The parsed_data is now a Pydantic model, so we access its attributes
            project_files = [file.dict() for file in parsed_data.files] if parsed_data else []
            processing_result["project_files"] = project_files
            
            print(f"🔍 DEBUG: Final project_files count: {len(project_files)}")
            
            # If no files were parsed, this is a critical error
            if not project_files:
                print("❌ CRITICAL: No project files were parsed! XEdit will be empty!")
                print("❌ This means either the LLM response format is wrong or the parser failed")
                # Let's try fallback parsing
                print("🔄 Attempting fallback parsing...")
                fallback_files = self._extract_raw_code_blocks(llm2_response)
                if fallback_files:
                    print(f"✅ Fallback parsing found {len(fallback_files)} files")
                    project_files = fallback_files
                    processing_result["project_files"] = project_files
                else:
                    print("❌ Even fallback parsing failed - no content will be shown in XEdit")
            
            # Generate XEdit paths
            processing_result["xedit_paths"] = self._generate_xedit_paths(project_files)
            
            # Call xedit.py to generate the HTML file
            xedit_file_path = self._call_xedit_generator(processing_result, session_timestamp)
            
            processing_result["xedit_file_path"] = str(xedit_file_path)
            processing_result["success"] = True
            
            print(f"✅ IN-HOMING: Processing completed successfully!")
            print(f"📁 Generated: {len(project_files)} files")
            print(f"🎯 XEdit Paths: {len(processing_result['xedit_paths'])}")
            print(f"💾 XEdit saved: {xedit_file_path}")
            
            # Double-check file exists
            if Path(xedit_file_path).exists():
                print(f"✅ XEdit file verified to exist at: {xedit_file_path}")
            else:
                print(f"⚠️ XEdit file NOT found at: {xedit_file_path}")
            
        except Exception as e:
            processing_result["error"] = str(e)
            processing_result["success"] = False
            print(f"❌ IN-HOMING: Processing failed - {e}")
            
            # Create emergency fallback XEdit
            try:
                fallback_path = f"/home/flintx/peacock/html/xedit-{session_timestamp}-fallback.html"
                Path("/home/flintx/peacock/html").mkdir(parents=True, exist_ok=True)
                with open(fallback_path, 'w') as f:
                    f.write(f"""<!DOCTYPE html>
<html><head><title>XEdit Emergency - {session_timestamp}</title></head>
<body>
<h1>🦚 Peacock XEdit Interface (Emergency Mode)</h1>
<p>Session: {session_timestamp}</p>
<p>Emergency fallback due to error: {str(e)}</p>
<p>Raw LLM Response:</p>
<pre>{llm2_response[:2000]}...</pre>
</body></html>""")
                processing_result["xedit_file_path"] = fallback_path
                print(f"⚠️ Created emergency XEdit: {fallback_path}")
            except Exception as fallback_error:
                print(f"❌ Even emergency XEdit failed: {fallback_error}")
        
        # Final verification
        if processing_result.get("xedit_file_path"):
            final_path = processing_result["xedit_file_path"]
            if Path(final_path).exists():
                print(f"✅ Final XEdit verification: {final_path} exists")
            else:
                print(f"❌ Final XEdit verification: {final_path} MISSING")
        
        return processing_result
    
    def _parse_llm2_response(self, response_text: str) -> Optional[FinalCodeOutput]:
        """Parse the LLM2 response using enhanced robust parser."""
        print("🦚 Parsing LLM response with Enhanced Robust Parser...")
        
        try:
            # Use the enhanced parser with schema standardization
            enhanced_parser = create_enhanced_parser()
            parse_result = enhanced_parser.parse(response_text, "peacock_full")
            
            if parse_result.success and parse_result.qwen_parsed:
                print(f"✅ Enhanced parser succeeded with method: {parse_result.method.value}")
                print(f"📊 Confidence: {parse_result.confidence}")
                print(f"📁 Files parsed: {len(parse_result.qwen_parsed.files)}")
                return parse_result.qwen_parsed
            
            elif parse_result.success and parse_result.data.get("files"):
                # Convert parsed data to FinalCodeOutput
                files_data = parse_result.data["files"]
                project_name = parse_result.data.get("project_name", "Generated Project")
                
                print(f"✅ Enhanced parser succeeded with method: {parse_result.method.value}")
                print(f"📊 Confidence: {parse_result.confidence}")
                print(f"📁 Files parsed: {len(files_data)}")
                
                # Convert to CodeFile objects
                from schemas import CodeFile
                code_files = []
                for file_data in files_data:
                    code_file = CodeFile(
                        filename=file_data.get("filename", "unknown.txt"),
                        language=file_data.get("language", "text"),
                        code=file_data.get("code", "")
                    )
                    code_files.append(code_file)
                
                return FinalCodeOutput(
                    project_name=project_name,
                    files=code_files
                )
            
            else:
                print(f"⚠️ Enhanced parser failed!")
                print(f"🔍 Method attempted: {parse_result.method.value if parse_result.method else 'None'}")
                print(f"🔍 Confidence: {parse_result.confidence}")
                print(f"🔍 Errors: {parse_result.errors}")
                print(f"🔍 Data keys: {list(parse_result.data.keys()) if parse_result.data else 'None'}")
                return None
                
        except Exception as e:
            print(f"❌ Enhanced parser exception: {e}")
            return None

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
                
                # Try to detect filename from code content or context
                detected_filename = self._detect_filename_from_code(code, lang, file_index + 1)
                
                file_data = {
                    "filename": detected_filename,
                    "language": lang,
                    "code": code.strip(),
                }
                code_files.append(file_data)
                print(f"📄 Found raw block: {file_data['filename']} ({file_data['language']})")
        
        return code_files
    
    def _detect_filename_from_code(self, code: str, lang: str, file_index: int) -> str:
        """Try to detect the actual filename from code content and language"""
        
        # Python files - primary focus  
        if lang == 'python':
            if any(keyword in code.lower() for keyword in ['snake', 'game']):
                if 'class' in code and 'Game' in code:
                    return 'snake_game.py'
                elif 'flask' in code.lower() or 'app.run' in code:
                    return 'app.py'
                elif 'django' in code.lower():
                    return 'manage.py'
                else:
                    return 'game.py'
            elif 'flask' in code.lower() or 'app.run' in code:
                return 'app.py'
            elif 'if __name__ == "__main__"' in code:
                return 'main.py'
            else:
                return f'script{file_index}.py'
        
        # HTML files - look for title or common HTML patterns
        elif lang == 'html':
            title_match = re.search(r'<title>(.*?)</title>', code, re.IGNORECASE)
            if title_match and 'snake' in title_match.group(1).lower():
                return 'index.html'
            return 'index.html'  # Default for HTML
        
        # CSS files - look for common CSS patterns
        elif lang == 'css':
            if 'game-container' in code or 'snake' in code.lower():
                return 'styles.css'
            return 'styles.css'  # Default for CSS
        
        # Python files - look for main application patterns  
        elif lang == 'python':
            if 'class Game(' in code:
                return 'models/game.py'
            elif 'Blueprint(' in code or 'api = Blueprint' in code:
                return 'routes/api.py'
            elif 'Flask(__name__)' in code:
                return 'app.py'
            elif 'if __name__' in code:
                return 'main.py'
            else:
                return f'module{file_index}.py'
        
        # Text files - look for requirements or env files
        elif lang == 'text':
            if 'Flask==' in code or 'django==' in code.lower():
                return 'requirements.txt'
            elif 'FLASK_ENV=' in code or 'PORT=' in code:
                return '.env.example'
            return f'file{file_index}.txt'
        
        # JSON files - look for configuration patterns
        elif lang == 'json':
            if any(key in code for key in ['"name"', '"version"', '"description"']):
                return 'config.json'
            return f'data{file_index}.json'
        
        # Markdown files
        elif lang == 'markdown':
            if code.lower().startswith('# ') or 'readme' in code.lower():
                return 'README.md'
            return f'doc{file_index}.md'
        
        # Shell scripts
        elif lang == 'bash':
            if 'pip' in code or 'python' in code:
                return 'setup.sh'
            return f'script{file_index}.sh'
        
        # Default fallback
        else:
            ext = self._get_extension_for_language(lang)
            return f"file{file_index}.{ext}"
    
    def _get_extension_for_language(self, lang: str) -> str:
        """Get file extension for a language"""
        ext_map = {
            'python': 'py',
            'javascript': 'js', 
            'html': 'html',
            'css': 'css',
            'json': 'json',
            'markdown': 'md',
            'bash': 'sh',
            'sql': 'sql',
            'yaml': 'yml',
            'text': 'txt'
        }
        return ext_map.get(lang, 'txt')

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
        """Call xedit.py to generate the HTML interface - ENHANCED WITH FORCED GENERATION"""
        try:
            # Ensure HTML directory exists
            html_dir = Path("/home/flintx/peacock/html")
            html_dir.mkdir(exist_ok=True, parents=True)
            
            output_path = html_dir / f"xedit-{session_timestamp}.html"
            
            print(f"📋 Creating XEdit at: {output_path}")
            
            # Get data with fallbacks
            parsed_data = processing_result.get("parsed_data", {})
            xedit_paths = processing_result.get("xedit_paths", {})
            project_files = processing_result.get("project_files", [])
            
            print(f"📊 XEdit data: {len(project_files)} files, {len(xedit_paths)} paths")
            
            # Generate enhanced XEdit HTML with 3 sections
            html_content = self._generate_simple_xedit_html(parsed_data, xedit_paths, project_files, session_timestamp)
            
            # Force write the file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            # Verify file was created
            if output_path.exists():
                file_size = output_path.stat().st_size
                print(f"✅ XEdit interface generated: {output_path} ({file_size} bytes)")
                return str(output_path)
            else:
                raise Exception("XEdit file was not created successfully")
            
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
        """Generate ENHANCED XEdit HTML interface with 3 sections: Functions, Code Editor, Payload"""
        
        project_name = parsed_data.get("project_name", "Generated Project")
        
        # Clean project files to prevent JSON syntax errors
        # Use base64 encoding to completely avoid escaping issues
        import base64
        cleaned_project_files = []
        for file_data in project_files:
            code = file_data.get("code", "")
            # Encode code as base64 to avoid all JSON/JavaScript escaping issues
            code_b64 = base64.b64encode(code.encode('utf-8')).decode('ascii')
            
            cleaned_file = {
                "filename": file_data.get("filename", "unknown.txt"),
                "language": file_data.get("language", "text"),
                "code_b64": code_b64,
                "code": ""  # Keep empty for backward compatibility
            }
            cleaned_project_files.append(cleaned_file)
        
        # Generate functions list with + buttons
        functions_html = ""
        for xedit_id, data in xedit_paths.items():
            functions_html += f"""
            <div class="function-item" onclick="highlightFunction('{xedit_id}', '{data['display_name']}', {data['line_start']}, {data['line_end']})" data-id="{xedit_id}">
                <div class="function-header">
                    <span class="function-icon">{"⚡" if data['type'] == 'function' else "🏗️"}</span>
                    <strong>{data['display_name']}</strong>
                    <button class="add-payload-btn" onclick="event.stopPropagation(); addToPayload('{data['display_name']}', '{data['type']}', '{xedit_id}')" title="Add to payload">+</button>
                </div>
                <div class="function-details">
                    {data['type']} • {data['filename']} • Lines {data['lines_display']}
                </div>
            </div>
            """
        
        # Generate code display with line numbers (use original files for display)
        code_html = ""
        line_counter = 1
        for file_data in project_files:
            code_html += f"<div class='file-header'>// FILE: {file_data['filename']} ({file_data.get('language', 'text')})</div>\n"
            code_html += "<div class='file-separator'>//" + "="*70 + "</div>\n\n"
            
            lines = file_data['code'].split('\n')
            for line in lines:
                escaped_line = line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                code_html += f"<div class='code-line' data-line='{line_counter}'><span class='line-number'>{line_counter:3d}</span><span class='line-content'>{escaped_line}</span></div>\n"
                line_counter += 1
            
            code_html += "\n"
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🦚 XEdit Enhanced - {project_name}</title>
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
        
        /* LEFT PANEL - Functions & Classes List */
        .left-panel {{
            width: 25%;
            background: #1a1a1a;
            border-right: 1px solid #00ff00;
            padding: 15px;
            overflow-y: auto;
        }}
        
        /* MIDDLE PANEL - Code Editor */
        .middle-panel {{
            width: 50%;
            background: #0f0f0f;
            padding: 15px;
            overflow-y: auto;
            border-right: 1px solid #00ff00;
        }}
        
        /* RIGHT PANEL - Payload */
        .right-panel {{
            width: 25%;
            background: #1a1a1a;
            padding: 15px;
            overflow-y: auto;
        }}
        
        .panel-header {{
            color: #00ffff;
            font-weight: bold;
            margin-bottom: 15px;
            padding: 8px;
            background: #333;
            border: 1px solid #00ff00;
            text-align: center;
            border-radius: 4px;
        }}
        
        /* Function List Styling */
        .function-item {{
            background: #2a2a2a;
            border: 1px solid #444;
            border-radius: 6px;
            margin: 8px 0;
            padding: 10px;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
        }}
        
        .function-item:hover {{
            background: #004400;
            border-color: #00ff00;
            box-shadow: 0 2px 8px rgba(0, 255, 0, 0.3);
        }}
        
        .function-item.highlighted {{
            background: #006600 !important;
            border-color: #00ff00 !important;
            color: #ffffff !important;
        }}
        
        .function-header {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .function-icon {{
            font-size: 16px;
        }}
        
        .function-details {{
            font-size: 11px;
            color: #888;
            margin-top: 6px;
            line-height: 1.3;
        }}
        
        .add-payload-btn {{
            background: #ff6600;
            color: white;
            border: none;
            width: 22px;
            height: 22px;
            border-radius: 50%;
            cursor: pointer;
            font-weight: bold;
            font-size: 14px;
            margin-left: auto;
            transition: all 0.2s ease;
        }}
        
        .add-payload-btn:hover {{
            background: #ff8800;
            transform: scale(1.1);
        }}
        
        /* Code Editor Styling */
        .code-display {{
            background: #000;
            color: #00ff00;
            padding: 15px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            line-height: 1.4;
            border: 1px solid #333;
            border-radius: 4px;
            height: calc(100vh - 120px);
            overflow-y: auto;
        }}
        
        .code-line {{
            display: flex;
            min-height: 18px;
            border-left: 3px solid transparent;
        }}
        
        .code-line.highlight {{
            background-color: #004400;
            border-left-color: #00ff00;
        }}
        
        .line-number {{
            color: #666;
            margin-right: 15px;
            user-select: none;
            min-width: 35px;
            text-align: right;
            font-size: 11px;
        }}
        
        .line-content {{
            flex: 1;
            white-space: pre;
        }}
        
        .file-header {{
            color: #00ffff;
            font-weight: bold;
            margin: 15px 0 5px 0;
            font-size: 14px;
        }}
        
        .file-separator {{
            color: #666;
            margin-bottom: 10px;
        }}
        
        /* Payload Section Styling */
        .payload-item {{
            background: #333;
            border: 1px solid #555;
            border-radius: 4px;
            padding: 10px;
            margin: 8px 0;
            font-size: 12px;
            position: relative;
        }}
        
        .payload-item-header {{
            color: #ffff00;
            font-weight: bold;
            margin-bottom: 4px;
        }}
        
        .payload-item-details {{
            color: #ccc;
            font-size: 11px;
            line-height: 1.3;
        }}
        
        .remove-payload-btn {{
            position: absolute;
            top: 5px;
            right: 5px;
            background: #ff0000;
            color: white;
            border: none;
            width: 16px;
            height: 16px;
            border-radius: 50%;
            cursor: pointer;
            font-size: 10px;
            line-height: 1;
        }}
        
        .deploy-section {{
            margin-top: 20px;
            padding-top: 15px;
            border-top: 1px solid #444;
        }}
        
        .custom-name-input {{
            width: 100%;
            padding: 8px;
            margin-bottom: 10px;
            background: #2a2a2a;
            border: 1px solid #00ff00;
            border-radius: 4px;
            color: #00ff00;
            font-family: 'Courier New', monospace;
            font-size: 12px;
        }}
        
        .custom-name-input:focus {{
            outline: none;
            border-color: #00ffff;
            box-shadow: 0 0 5px rgba(0, 255, 255, 0.5);
        }}
        
        .pcock-deploy-btn {{
            background: linear-gradient(45deg, #00ff00, #00cc00);
            color: #000;
            border: none;
            padding: 12px 16px;
            font-weight: bold;
            font-family: 'Courier New', monospace;
            cursor: pointer;
            border-radius: 6px;
            width: 100%;
            transition: all 0.3s ease;
            font-size: 12px;
        }}
        
        .pcock-deploy-btn:hover {{
            background: linear-gradient(45deg, #00cc00, #009900);
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 255, 0, 0.3);
        }}
        
        .empty-state {{
            color: #666;
            text-align: center;
            padding: 30px 20px;
            font-style: italic;
        }}
        
        #deploy-status {{
            margin-top: 10px;
            padding: 8px;
            font-size: 11px;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="xedit-container">
        <!-- LEFT PANEL: Functions & Classes List -->
        <div class="left-panel">
            <div class="panel-header">
                🔧 Functions & Classes
            </div>
            
            <div id="functions-list">
                {functions_html if functions_html else '<div class="empty-state">No functions found</div>'}
            </div>
        </div>
        
        <!-- MIDDLE PANEL: Code Editor -->
        <div class="middle-panel">
            <div class="panel-header">
                💻 Code Editor
            </div>
            
            <div class="code-display" id="code-display">
{code_html}
            </div>
        </div>
        
        <!-- RIGHT PANEL: Payload & Deploy -->
        <div class="right-panel">
            <div class="panel-header">
                🎯 Payload
            </div>
            
            <div id="payload-list">
                <div class="empty-state">No items in payload</div>
            </div>
            
            <div class="deploy-section">
                <input type="text" class="custom-name-input" id="custom-package-name" placeholder="Enter custom package name (optional)" />
                <button class="peacock-deploy-btn" onclick="deployToPcock()">
                    🦚 Generate Python Project
                </button>
                <div id="deploy-status"></div>
            </div>
        </div>
    </div>
    
    <script>
        // XEdit data and state
        const xeditPaths = {json.dumps(xedit_paths, ensure_ascii=True)};
        const projectFiles = {json.dumps(cleaned_project_files, ensure_ascii=True, separators=(',', ':'))};
        const projectName = '{project_name}';
        const sessionId = '{session_timestamp}';
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
            
            if (payloadItems.length === 0) {{
                payloadList.innerHTML = '<div class="empty-state">No items in payload</div>';
                return;
            }}
            
            let html = '';
            payloadItems.forEach(item => {{
                html += `
                    <div class="payload-item">
                        <div class="payload-item-header">${{item.name}}</div>
                        <div class="payload-item-details">
                            Type: ${{item.type}}<br>
                            Added: ${{item.timestamp}}
                        </div>
                        <button class="remove-payload-btn" onclick="removeFromPayload('${{item.id}}')" title="Remove from payload">×</button>
                    </div>
                `;
            }});
            
            payloadList.innerHTML = html;
        }}
        
        function deployToPcock() {{
            console.log('deployToPcock() called');
            const deployBtn = document.querySelector('.peacock-deploy-btn');
            const deployStatus = document.getElementById('deploy-status');
            const customNameInput = document.getElementById('custom-package-name');
            
            console.log('deployBtn:', deployBtn);
            console.log('deployStatus:', deployStatus);
            
            // Get custom name or use default
            const customName = customNameInput.value.trim();
            const finalProjectName = customName || projectName;
            console.log('finalProjectName:', finalProjectName);
            
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
                            📦 .pbuild file created<br>
                            🌐 <a href="${{data.app_url}}" target="_blank" style="color: #00ffff;">Open App</a>
                        </div>
                    `;
                    
                    // Auto-open app
                    if (data.app_url) {{
                        setTimeout(() => {{
                            window.open(data.app_url, '_blank');
                        }}, 1500);
                    }}
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
    
    def deploy_and_run(self, project_files, project_name):
        """Generate Python project folder with auto-setup script"""
        try:
            # Create apps directory if it doesn't exist
            apps_dir = Path("/home/flintx/peacock/apps")
            apps_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate project folder path
            project_folder = f"{project_name.replace(' ', '-').lower()}"
            project_path = apps_dir / project_folder
            
            # Remove existing folder if it exists
            if project_path.exists():
                import shutil
                shutil.rmtree(project_path)
            
            # Create project directory
            project_path.mkdir(parents=True, exist_ok=True)
            
            # Detect project type
            app_type = self._detect_app_type(project_files)
            
            # Write all project files
            for file_data in project_files:
                file_path = project_path / file_data['filename']
                
                # Create subdirectories if needed
                file_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Write file content
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(file_data['code'])
                
                print(f"✅ Created: {file_data['filename']}")
            
            # Add setup.py if not already present
            setup_path = project_path / "setup.py"
            if not setup_path.exists():
                setup_content = self._generate_setup_script(project_name, app_type, project_files)
                with open(setup_path, 'w', encoding='utf-8') as f:
                    f.write(setup_content)
                # Make setup.py executable
                import os
                os.chmod(setup_path, 0o755)
                print("✅ Created: setup.py (auto-installer)")
            
            # Ensure requirements.txt exists with Python dependencies
            requirements_path = project_path / "requirements.txt"
            if not requirements_path.exists():
                requirements_content = self._generate_requirements_txt(project_files, app_type)
                with open(requirements_path, 'w', encoding='utf-8') as f:
                    f.write(requirements_content)
                print("✅ Created: requirements.txt (dependencies)")
            
            # Ensure README.md exists with project documentation
            readme_path = project_path / "README.md"
            if not readme_path.exists():
                readme_content = self._generate_readme_md(project_name, app_type, project_files)
                with open(readme_path, 'w', encoding='utf-8') as f:
                    f.write(readme_content)
                print("✅ Created: README.md (documentation)")
            
            files_created_count = len(project_files)
            if not (project_path / "setup.py").exists():
                files_created_count += 1
            if not (project_path / "requirements.txt").exists():
                files_created_count += 1  
            if not (project_path / "README.md").exists():
                files_created_count += 1
            
            print(f"✅ Created Python project: {project_path}")
            print(f"🚀 To run: cd {project_folder} && python setup.py")
            
            return {
                "success": True,
                "message": f"🦚 Python project created: {project_folder}",
                "project_path": str(project_path),
                "app_type": app_type,
                "files_created": len(project_files) + 1,  # +1 for setup.py
                "run_command": f"cd apps/{project_folder} && python setup.py"
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Python project creation failed: {str(e)}"
            }
    
    def _generate_setup_script(self, project_name, app_type, project_files):
        """Generate auto-setup script for Python projects"""
        
        # Find main Python file
        main_file = "app.py"
        for file_data in project_files:
            if file_data['filename'] in ['app.py', 'main.py', 'run.py']:
                main_file = file_data['filename']
                break
        
        return f'''#!/usr/bin/env python3
"""
🦚 Peacock {project_name} - Auto Setup & Run
Just run: python setup.py
"""
import subprocess
import sys
import os
from pathlib import Path

def main():
    print("🦚 {project_name}")
    print("=" * 40)
    
    # Check Python version
    if sys.version_info < (3, 7):
        print("❌ Python 3.7+ required")
        sys.exit(1)
    
    # Install dependencies
    if Path("requirements.txt").exists():
        print("📦 Installing dependencies...")
        try:
            subprocess.run([
                sys.executable, "-m", "pip", "install", 
                "-r", "requirements.txt", "--quiet"
            ], check=True)
            print("✅ Dependencies installed")
        except subprocess.CalledProcessError:
            print("⚠️  Some dependencies may have failed to install")
            print("💡 Try: pip install -r requirements.txt")
    
    # Run the app
    print("🚀 Starting application...")
    if "{app_type}" == "flask":
        print("🌐 Flask app will start at http://localhost:5000")
    
    try:
        subprocess.run([sys.executable, "{main_file}"])
    except KeyboardInterrupt:
        print("\\n👋 Application stopped")
    except Exception as e:
        print(f"❌ Error running app: {{e}}")
        print(f"💡 Try: python {main_file}")

if __name__ == "__main__":
    main()
'''

    def _generate_requirements_txt(self, project_files, app_type):
        """Generate requirements.txt with Python dependencies"""
        
        # Default Python dependencies
        requirements = set([
            "# Core Python dependencies for Peacock projects"
        ])
        
        # Analyze project files for common dependencies
        all_code = ""
        for file_data in project_files:
            if file_data.get('language') == 'python':
                all_code += file_data.get('code', '') + "\n"
        
        # Detect common Python libraries and add appropriate versions
        if 'flask' in all_code.lower() or 'from flask' in all_code.lower():
            requirements.add("Flask==3.0.0")
            requirements.add("Werkzeug==3.0.1")
        
        if 'django' in all_code.lower() or 'from django' in all_code.lower():
            requirements.add("Django==4.2.7")
            requirements.add("djangorestframework==3.14.0")
        
        if 'fastapi' in all_code.lower() or 'from fastapi' in all_code.lower():
            requirements.add("fastapi==0.104.1")
            requirements.add("uvicorn==0.24.0")
        
        if 'requests' in all_code.lower() or 'import requests' in all_code.lower():
            requirements.add("requests==2.31.0")
        
        if 'numpy' in all_code.lower() or 'import numpy' in all_code.lower():
            requirements.add("numpy==1.24.3")
        
        if 'pandas' in all_code.lower() or 'import pandas' in all_code.lower():
            requirements.add("pandas==2.0.3")
        
        if 'matplotlib' in all_code.lower() or 'import matplotlib' in all_code.lower():
            requirements.add("matplotlib==3.7.2")
        
        if 'sqlalchemy' in all_code.lower() or 'from sqlalchemy' in all_code.lower():
            requirements.add("SQLAlchemy==2.0.23")
        
        if 'pytest' in all_code.lower() or 'import pytest' in all_code.lower():
            requirements.add("pytest==7.4.3")
        
        if 'click' in all_code.lower() or 'import click' in all_code.lower():
            requirements.add("click==8.1.7")
        
        if 'python-dotenv' in all_code.lower() or 'from dotenv' in all_code.lower():
            requirements.add("python-dotenv==1.0.0")
        
        # Add common development dependencies
        requirements.add("# Development dependencies")
        requirements.add("black==23.11.0")
        requirements.add("flake8==6.1.0")
        
        # Convert to sorted list (keeping comments at top)
        requirements_list = []
        comments = [req for req in requirements if req.startswith('#')]
        packages = sorted([req for req in requirements if not req.startswith('#')])
        
        # Build final requirements content
        content = "# 🦚 Peacock Generated Requirements\n"
        content += "# Automatically generated Python dependencies\n\n"
        
        for comment in comments:
            if comment not in content:
                content += comment + "\n"
        
        for package in packages:
            content += package + "\n"
        
        # Add a blank line at the end
        content += "\n# Add your custom dependencies below:\n"
        
        return content

    def _generate_readme_md(self, project_name, app_type, project_files):
        """Generate comprehensive README.md documentation"""
        
        # Count different file types
        python_files = [f for f in project_files if f.get('language') == 'python']
        config_files = [f for f in project_files if f.get('filename', '').endswith(('.json', '.yml', '.yaml', '.env'))]
        
        # Detect main application file
        main_file = "main.py"
        entry_points = []
        for file_data in python_files:
            filename = file_data.get('filename', '')
            code = file_data.get('code', '')
            
            if filename in ['app.py', 'main.py', 'run.py', 'server.py']:
                main_file = filename
                entry_points.append(filename)
            elif 'if __name__ == "__main__"' in code:
                entry_points.append(filename)
        
        # Detect framework
        framework = "Python"
        if any('flask' in f.get('code', '').lower() for f in python_files):
            framework = "Flask"
        elif any('django' in f.get('code', '').lower() for f in python_files):
            framework = "Django"
        elif any('fastapi' in f.get('code', '').lower() for f in python_files):
            framework = "FastAPI"
        
        # Generate comprehensive README
        readme_content = f"""# 🦚 {project_name}

> Generated with Peacock AI Development System

A {framework} application built with pure Python - following the championship-tested 4-stage development process.

## ✨ Features

- ✅ Pure Python implementation (no web technologies)
- ✅ Production-ready code structure
- ✅ Comprehensive error handling
- ✅ Auto-setup and dependency management
- ✅ Built with Peacock AI (SPARK → FALCON → EAGLE → HAWK)

## 📁 Project Structure

```
{project_name.lower().replace(' ', '-')}/
├── {main_file}{'             # Main application entry point' if main_file in [f.get('filename') for f in python_files] else ''}
"""

        # Add file structure
        for file_data in project_files:
            filename = file_data.get('filename', '')
            if filename != main_file:
                readme_content += f"├── {filename}\n"
        
        readme_content += f"""├── requirements.txt    # Python dependencies
├── setup.py           # Auto-installer & runner
└── README.md          # This documentation

```

## 🚀 Quick Start

### Method 1: Auto-Setup (Recommended)
```bash
# Just run the auto-installer
python setup.py
```

### Method 2: Manual Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python {main_file}
```

## 📋 Requirements

- Python 3.8+
- Dependencies listed in `requirements.txt`

## 🔧 Development

### Running the Application
```bash
# Development mode
python {main_file}
"""

        # Add framework-specific instructions
        if framework == "Flask":
            readme_content += """
# The Flask app will start at http://localhost:5000
"""
        elif framework == "Django":
            readme_content += """
# Django development server
python manage.py runserver
"""
        elif framework == "FastAPI":
            readme_content += """
# FastAPI with uvicorn
uvicorn main:app --reload
"""

        readme_content += f"""```

### Code Quality
```bash
# Format code
black .

# Lint code  
flake8 .

# Run tests (if available)
pytest
```

## 📊 Project Stats

- **Framework**: {framework}
- **Python Files**: {len(python_files)}
- **Total Files**: {len(project_files)}
- **Entry Points**: {', '.join(entry_points) if entry_points else main_file}

## 🏗️ Architecture

This project follows the **Peacock 4-Stage Development System**:

1. **🔥 SPARK** - Requirements analysis and strategic planning
2. **🦅 FALCON** - System architecture and technical design  
3. **🦅 EAGLE** - Complete code implementation
4. **🦅 HAWK** - Quality assurance and production readiness

## 📝 Generated Files

"""

        # List all generated files with descriptions
        for file_data in project_files:
            filename = file_data.get('filename', '')
            language = file_data.get('language', 'text')
            
            if language == 'python':
                readme_content += f"- **{filename}** - Python module\n"
            elif filename.endswith('.json'):
                readme_content += f"- **{filename}** - Configuration file\n"
            elif filename.endswith('.txt'):
                readme_content += f"- **{filename}** - Text/data file\n"
            elif filename.endswith('.md'):
                readme_content += f"- **{filename}** - Documentation\n"
            else:
                readme_content += f"- **{filename}** - {language.title()} file\n"

        readme_content += f"""
## 🤝 Contributing

This project was generated by Peacock AI. To contribute:

1. Make your changes
2. Test thoroughly  
3. Follow Python best practices
4. Update documentation as needed

## 📄 License

Generated with [Peacock AI](https://github.com/peacock-ai) - Production-ready Python applications.

## 🦚 About Peacock AI

This project was created using the Peacock AI Development System, which uses a championship-tested 4-stage process to generate production-ready applications. Each stage is handled by specialized AI agents:

- **SPARK**: Requirements analysis
- **FALCON**: Architecture design  
- **EAGLE**: Code implementation
- **HAWK**: Quality assurance

**Generated**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}  
**Framework**: {framework}  
**Language**: Python {'.'.join(map(str, [3, 8]))}+  

---

*🦚 Built with Peacock AI - Where AI meets production-ready development*
"""

        return readme_content
    
    def _detect_app_type(self, project_files):
        """Detect the type of app being packaged"""
        filenames = [f.get("filename", "").lower() for f in project_files]
        
        # Check for Python script
        if any(f.endswith('.py') for f in filenames):
            return "python"
        
        # Check for web app (HTML/CSS/JS)
        has_html = any(f.endswith('.html') or f.endswith('.htm') for f in filenames)
        has_js = any(f.endswith('.js') for f in filenames)
        has_css = any(f.endswith('.css') for f in filenames)
        
        if has_html or has_js or has_css:
            return "web"
        
        # Default to generic
        return "generic"
    
    def _generate_pbuild_script(self, project_files, project_name, app_type):
        """Generate the self-executing .pbuild script"""
        import base64
        import json
        
        # Encode all files as base64
        encoded_files = {}
        for file_data in project_files:
            filename = file_data.get("filename")
            code = file_data.get("code", "")
            if filename and code:
                encoded_files[filename] = base64.b64encode(code.encode('utf-8')).decode('utf-8')
        
        # Create the metadata
        metadata = {
            "name": project_name,
            "app_type": app_type,
            "created": datetime.datetime.now().isoformat(),
            "files": list(encoded_files.keys()),
            "created_by": "Peacock AI"
        }
        
        # Generate the self-executing script
        script_filename = f"{project_name.replace(' ', '-').lower()}.pbuild"
        newline = '\n'
        script_content = f"""#!/usr/bin/env python3
{chr(34)*3}
🦚 PEACOCK BUILD (.pbuild)
Self-executing application package

Package: {project_name}
Type: {app_type}
Created: {metadata['created']}
Created by: Peacock AI

Usage: ./{script_filename}
{chr(34)*3}

import os
import sys
import base64
import tempfile
import webbrowser
import subprocess
import shutil
from pathlib import Path

# Package metadata
METADATA = {json.dumps(metadata, indent=4)}

# Encoded files
FILES = {json.dumps(encoded_files, indent=4)}

def extract_files():
    # Extract files to temporary directory
    temp_dir = Path(tempfile.mkdtemp(prefix="pcock_"))
    
    print(f"🦚 Extracting {{METADATA['name']}} to {{temp_dir}}")
    
    for filename, encoded_content in FILES.items():
        file_path = temp_dir / filename
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Decode and write file
        content = base64.b64decode(encoded_content).decode('utf-8')
        
        # No special processing needed for Python projects
            
        with open(file_path, 'w') as f:
            f.write(content)
        
        print(f"  ✅ {{filename}}")
    
    return temp_dir

def run_app(temp_dir):
    # Run the application based on its type
    app_type = METADATA['app_type']
    
    if app_type == "python":
        # Find the main Python file
        py_files = list(temp_dir.glob("*.py"))
        if py_files:
            main_file = py_files[0]  # Use first Python file
            print(f"🐍 Running Python script: {{main_file.name}}")
            subprocess.run([sys.executable, str(main_file)], cwd=temp_dir)
        else:
            print("❌ No Python files found")
            
    elif app_type == "web":
        # Check for Python Flask web applications
        flask_files = list(temp_dir.glob("**/*.py"))
        is_flask_project = False
        
        for py_file in flask_files:
            try:
                with open(py_file, 'r') as f:
                    content = f.read()
                    if 'flask' in content.lower() or 'app.run' in content:
                        is_flask_project = True
                        break
            except:
                continue
        
        if is_flask_project:
            print("🔧 Flask project detected - Setting up Python environment...")
            
            # Check for requirements.txt
            req_files = list(temp_dir.glob("**/requirements.txt"))
            if req_files:
                print("📦 Installing Python dependencies...")
                try:
                    subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', str(req_files[0])], 
                                 check=True, capture_output=True, text=True)
                    print("✅ Python dependencies installed")
                except subprocess.CalledProcessError as e:
                    print(f"⚠️ pip install failed: {{e.stderr}}")
            
            # Find and run the Flask app
            for py_file in flask_files:
                try:
                    with open(py_file, 'r') as f:
                        content = f.read()
                        if 'app.run' in content or 'if __name__' in content:
                            print(f"🚀 Starting Flask app: {{py_file.name}}")
                            subprocess.run([sys.executable, str(py_file)], cwd=temp_dir)
                            break
                except:
                    continue
        else:
            # Try to run any Python file
            py_files = list(temp_dir.glob("*.py"))
            if py_files:
                main_file = py_files[0]
                print(f"🐍 Running Python script: {{main_file.name}}")
                subprocess.run([sys.executable, str(main_file)], cwd=temp_dir)

def _open_html_fallback(temp_dir):
    # Fallback to opening HTML files directly
    html_files = []
    for root, dirs, files in os.walk(temp_dir):
        for file in files:
            if file.endswith('.html'):
                html_files.append(Path(root) / file)
    
    if html_files:
        # Prioritize common entry points
        entry_priorities = ['index.html', 'app.html', 'main.html', 'home.html']
        main_file = None
        
        # Look for preferred entry points first
        for priority in entry_priorities:
            for html_file in html_files:
                if html_file.name.lower() == priority:
                    main_file = html_file
                    break
            if main_file:
                break
        
        # If no preferred entry point found, use the first HTML file
        if not main_file:
            main_file = html_files[0]
        
        print(f"🌐 Opening web app: {{main_file.relative_to(temp_dir)}}")
        webbrowser.open(f"file://{{main_file.absolute()}}")
        
        # Keep script running for a bit so user can interact
        print("Press Ctrl+C to exit...")
        try:
            import time
            time.sleep(60)  # Wait 1 minute
        except KeyboardInterrupt:
            print("\\n👋 Goodbye!")
    else:
        print("❌ No HTML files found")

# React functions removed - Python projects only

def cleanup(temp_dir):
    # Clean up temporary files
    try:
        shutil.rmtree(temp_dir)
        print(f"🧹 Cleaned up temporary files")
    except Exception as e:
        print(f"⚠️ Cleanup failed: {{e}}")

def main():
    # Main execution function
    print(f"🦚 PEACOCK PACKAGE: {{METADATA['name']}}")
    print(f"📦 Type: {{METADATA['app_type']}}")
    print(f"📅 Created: {{METADATA['created']}}")
    print("-" * 50)
    
    temp_dir = None
    try:
        temp_dir = extract_files()
        run_app(temp_dir)
    except KeyboardInterrupt:
        print("\\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Error: {{e}}")
    finally:
        if temp_dir and temp_dir.exists():
            cleanup(temp_dir)

if __name__ == "__main__":
    main()
"""
        
        return script_content

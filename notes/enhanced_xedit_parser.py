#!/usr/bin/env python3
"""
Enhanced XEdit Parser with Pydantic Strategy
Bulletproof parsing for Peacock LLM responses using multi-layer approach
"""

import re
import json
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import datetime

@dataclass
class CodeFile:
    """Structured representation of a code file"""
    filename: str
    content: str
    language: str
    size_chars: int
    functions: List[str]
    classes: List[str]
    xedit_id: str

@dataclass 
class ParsedResponse:
    """Complete parsed response structure"""
    project_overview: str
    code_files: List[CodeFile]
    implementation_notes: str
    setup_instructions: str
    total_files: int
    total_chars: int
    xedit_paths: List[Dict[str, Any]]
    parsing_success: bool
    parsing_method: str

class EnhancedXEditParser:
    """Enhanced parser with multi-layer parsing strategy"""
    
    def __init__(self):
        self.parsing_cache = {}
        self.code_patterns = {
            "code_blocks": r'```(?:filename:\s*([^\n]+)\n)?(.*?)```',
            "project_overview": r'\*\*PROJECT OVERVIEW:\*\*\s*(.*?)(?=\*\*|$)',
            "implementation_notes": r'\*\*IMPLEMENTATION NOTES:\*\*\s*(.*?)(?=\*\*|$)',
            "setup_deployment": r'\*\*SETUP & DEPLOYMENT:\*\*\s*(.*?)(?=\*\*|$)',
            "complete_code_files": r'\*\*COMPLETE CODE FILES:\*\*\s*(.*?)(?=\*\*|$)'
        }
        
        # Language detection patterns
        self.language_patterns = {
            r'\.html?$': 'html',
            r'\.css$': 'css', 
            r'\.js$': 'javascript',
            r'\.py$': 'python',
            r'\.json$': 'json',
            r'\.md$': 'markdown',
            r'\.yml?$': 'yaml',
            r'package\.json$': 'json',
            r'README': 'markdown'
        }
        
        # Function/class extraction patterns by language
        self.extraction_patterns = {
            'javascript': {
                'functions': [
                    r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(',
                    r'(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s+)?(?:function|\()',
                    r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:\s*(?:async\s+)?function',
                    r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=>\s*{'
                ],
                'classes': [
                    r'class\s+([a-zA-Z_$][a-zA-Z0-9_$]*)',
                    r'(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*class'
                ]
            },
            'python': {
                'functions': [
                    r'def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
                    r'async\s+def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
                ],
                'classes': [
                    r'class\s+([a-zA-Z_][a-zA-Z0-9_]*)'
                ]
            },
            'html': {
                'functions': [
                    r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(',
                    r'<script[^>]*>.*?function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\('
                ],
                'classes': [
                    r'class\s*=\s*["\']([^"\']+)["\']',
                    r'\.([a-zA-Z_-][a-zA-Z0-9_-]*)\s*{'
                ]
            },
            'css': {
                'functions': [],
                'classes': [
                    r'\.([a-zA-Z_-][a-zA-Z0-9_-]*)\s*{',
                    r'#([a-zA-Z_-][a-zA-Z0-9_-]*)\s*{'
                ]
            }
        }
    
    def parse_llm_response(self, raw_response: str) -> ParsedResponse:
        """
        Main parsing function with multi-layer strategy
        """
        print(f"🔍 ENHANCED PARSING LLM RESPONSE ({len(raw_response)} chars)")
        
        if not raw_response or len(raw_response) < 50:
            print("❌ Response too short or empty")
            return self._create_empty_response("Response too short or empty")
        
        # Create cache key
        cache_key = hashlib.md5(raw_response.encode()).hexdigest()[:16]
        
        if cache_key in self.parsing_cache:
            print("📋 Using cached parsing result")
            return self.parsing_cache[cache_key]
        
        try:
            # Layer 1: Extract major sections
            sections = self._extract_major_sections(raw_response)
            
            # Layer 2: Parse code files with enhanced extraction
            code_files = self._extract_code_files_enhanced(raw_response)
            
            # Layer 3: Generate XEdit paths
            xedit_paths = self._generate_xedit_paths(code_files)
            
            # Create final parsed response
            parsed_response = ParsedResponse(
                project_overview=sections.get("project_overview", "Project overview not found"),
                code_files=code_files,
                implementation_notes=sections.get("implementation_notes", "Implementation notes not found"),
                setup_instructions=sections.get("setup_deployment", "Setup instructions not found"),
                total_files=len(code_files),
                total_chars=sum(cf.size_chars for cf in code_files),
                xedit_paths=xedit_paths,
                parsing_success=len(code_files) > 0,
                parsing_method="enhanced_multi_layer"
            )
            
            # Cache the result
            self.parsing_cache[cache_key] = parsed_response
            
            print(f"✅ ENHANCED PARSING COMPLETE:")
            print(f"   📝 Project Overview: {'✅' if sections.get('project_overview') else '❌'}")
            print(f"   💻 Code Files: {len(code_files)}")
            print(f"   📊 Total Characters: {parsed_response.total_chars}")
            print(f"   🎯 XEdit Paths: {len(xedit_paths)}")
            
            return parsed_response
            
        except Exception as e:
            print(f"❌ Enhanced parsing failed: {str(e)}")
            return self._create_empty_response(f"Parsing error: {str(e)}")
    
    def _extract_major_sections(self, response: str) -> Dict[str, str]:
        """Extract major sections using regex patterns"""
        
        sections = {}
        
        for section_name, pattern in self.code_patterns.items():
            matches = re.findall(pattern, response, re.DOTALL | re.IGNORECASE)
            if matches:
                if section_name == "code_blocks":
                    continue  # Handle code blocks separately
                else:
                    sections[section_name] = matches[0].strip() if isinstance(matches[0], str) else matches[0]
        
        return sections
    
    def _extract_code_files_enhanced(self, response: str) -> List[CodeFile]:
        """Enhanced code file extraction with multiple strategies"""
        
        code_files = []
        
        # Strategy 1: Look for filename: pattern in code blocks
        filename_pattern = r'```filename:\s*([^\n]+)\n(.*?)```'
        filename_matches = re.findall(filename_pattern, response, re.DOTALL)
        
        for filename, content in filename_matches:
            filename = filename.strip()
            content = content.strip()
            
            if filename and content:
                code_file = self._create_code_file(filename, content)
                code_files.append(code_file)
        
        # Strategy 2: Look for standard code blocks with language hints
        if not code_files:
            standard_pattern = r'```(\w+)?\n(.*?)```'
            standard_matches = re.findall(standard_pattern, response, re.DOTALL)
            
            for i, (lang_hint, content) in enumerate(standard_matches):
                content = content.strip()
                if len(content) > 50:  # Only substantial code blocks
                    # Try to infer filename from content or position
                    filename = self._infer_filename_from_content(content, lang_hint, i)
                    code_file = self._create_code_file(filename, content)
                    code_files.append(code_file)
        
        # Strategy 3: Fallback - look for any substantial code-like blocks
        if not code_files:
            code_like_patterns = [
                r'((?:function|class|const|let|var|def|import|export).*?(?:\n.*?)*?)(?=\n\n|\Z)',
                r'(<!DOCTYPE html>.*?</html>)',
                r'(\{.*?".*?".*?\})',  # JSON-like
                r'([.#][\w-]+\s*\{.*?\})'  # CSS-like
            ]
            
            for pattern in code_like_patterns:
                matches = re.findall(pattern, response, re.DOTALL | re.IGNORECASE)
                for i, match in enumerate(matches):
                    if len(match) > 100:  # Substantial code blocks
                        filename = f"extracted_code_{i+1}.js"  # Default to JS
                        code_file = self._create_code_file(filename, match)
                        code_files.append(code_file)
        
        return code_files
    
    def _create_code_file(self, filename: str, content: str) -> CodeFile:
        """Create a structured CodeFile object with extracted functions/classes"""
        
        # Detect language
        language = self._detect_language(filename, content)
        
        # Extract functions and classes
        functions = self._extract_functions(content, language)
        classes = self._extract_classes(content, language)
        
        # Generate XEdit ID
        xedit_id = self._generate_xedit_id(filename)
        
        return CodeFile(
            filename=filename,
            content=content,
            language=language,
            size_chars=len(content),
            functions=functions,
            classes=classes,
            xedit_id=xedit_id
        )
    
    def _detect_language(self, filename: str, content: str) -> str:
        """Detect programming language from filename and content"""
        
        # Check filename patterns first
        for pattern, lang in self.language_patterns.items():
            if re.search(pattern, filename, re.IGNORECASE):
                return lang
        
        # Check content patterns as fallback
        content_lower = content.lower()
        
        if '<!doctype html>' in content_lower or '<html' in content_lower:
            return 'html'
        elif 'function' in content_lower and ('{' in content or '=>' in content):
            return 'javascript'
        elif 'def ' in content_lower and ':' in content:
            return 'python'
        elif content.strip().startswith('{') and content.strip().endswith('}'):
            return 'json'
        elif re.search(r'\.[a-zA-Z-]+\s*\{', content):
            return 'css'
        
        return 'text'
    
    def _extract_functions(self, content: str, language: str) -> List[str]:
        """Extract function names from code content"""
        
        functions = []
        
        if language in self.extraction_patterns:
            patterns = self.extraction_patterns[language]['functions']
            
            for pattern in patterns:
                matches = re.findall(pattern, content, re.MULTILINE)
                for match in matches:
                    if isinstance(match, tuple):
                        func_name = match[0] if match[0] else match[1]
                    else:
                        func_name = match
                    
                    if func_name and func_name not in functions:
                        functions.append(func_name)
        
        return functions
    
    def _extract_classes(self, content: str, language: str) -> List[str]:
        """Extract class names from code content"""
        
        classes = []
        
        if language in self.extraction_patterns:
            patterns = self.extraction_patterns[language]['classes']
            
            for pattern in patterns:
                matches = re.findall(pattern, content, re.MULTILINE)
                for match in matches:
                    if isinstance(match, tuple):
                        class_name = match[0] if match[0] else match[1]
                    else:
                        class_name = match
                    
                    if class_name and class_name not in classes:
                        classes.append(class_name)
        
        return classes
    
    def _infer_filename_from_content(self, content: str, lang_hint: str, index: int) -> str:
        """Infer filename from content and language hints"""
        
        # Check for common file indicators in content
        if '<!DOCTYPE html>' in content or '<html' in content:
            return 'index.html'
        elif '"name":' in content and '"version":' in content:
            return 'package.json'
        elif content.strip().startswith('# '):
            return 'README.md'
        elif re.search(r'\.[a-zA-Z-]+\s*\{', content):
            return 'style.css'
        elif 'function' in content or 'const' in content or 'let' in content:
            return 'script.js'
        elif 'def ' in content and ':' in content:
            return f'module_{index+1}.py'
        
        # Use language hint if available
        if lang_hint:
            extensions = {
                'html': '.html',
                'css': '.css', 
                'javascript': '.js',
                'js': '.js',
                'python': '.py',
                'json': '.json',
                'yaml': '.yml',
                'yml': '.yml'
            }
            ext = extensions.get(lang_hint.lower(), '.txt')
            return f'file_{index+1}{ext}'
        
        return f'code_file_{index+1}.txt'
    
    def _generate_xedit_id(self, filename: str) -> str:
        """Generate XEdit ID in 7x001 format"""
        
        # Create a hash from filename for consistency
        hash_obj = hashlib.md5(filename.encode())
        hash_int = int(hash_obj.hexdigest()[:6], 16)
        
        # Convert to 7x### format
        xedit_num = (hash_int % 999) + 1
        return f"7x{xedit_num:03d}"
    
    def _generate_xedit_paths(self, code_files: List[CodeFile]) -> List[Dict[str, Any]]:
        """Generate XEdit paths for all extracted elements"""
        
        xedit_paths = []
        
        for code_file in code_files:
            # Add file-level XEdit path
            file_path = {
                "id": code_file.xedit_id,
                "type": "file",
                "target": code_file.filename,
                "language": code_file.language,
                "size_chars": code_file.size_chars,
                "description": f"Complete {code_file.language} file"
            }
            xedit_paths.append(file_path)
            
            # Add function-level XEdit paths
            for i, function in enumerate(code_file.functions):
                func_id = f"{code_file.xedit_id}f{i+1:02d}"
                func_path = {
                    "id": func_id,
                    "type": "function",
                    "target": function,
                    "parent_file": code_file.filename,
                    "language": code_file.language,
                    "description": f"Function: {function}"
                }
                xedit_paths.append(func_path)
            
            # Add class-level XEdit paths
            for i, class_name in enumerate(code_file.classes):
                class_id = f"{code_file.xedit_id}c{i+1:02d}"
                class_path = {
                    "id": class_id,
                    "type": "class",
                    "target": class_name,
                    "parent_file": code_file.filename,
                    "language": code_file.language,
                    "description": f"Class: {class_name}"
                }
                xedit_paths.append(class_path)
        
        return xedit_paths
    
    def _create_empty_response(self, error_message: str) -> ParsedResponse:
        """Create empty response structure for failed parsing"""
        
        return ParsedResponse(
            project_overview=f"Parsing failed: {error_message}",
            code_files=[],
            implementation_notes="No implementation notes extracted",
            setup_instructions="No setup instructions extracted", 
            total_files=0,
            total_chars=0,
            xedit_paths=[],
            parsing_success=False,
            parsing_method="failed"
        )
    
    def generate_xedit_html(self, parsed_response: ParsedResponse, session_timestamp: str, project_name: str = "Peacock Project") -> str:
        """Generate complete XEdit HTML interface from parsed response"""
        
        if not parsed_response.parsing_success:
            return self._generate_error_html(parsed_response, session_timestamp, project_name)
        
        # Generate file list HTML
        file_list_html = self._generate_file_list_html(parsed_response.code_files)
        
        # Generate function list HTML
        function_list_html = self._generate_function_list_html(parsed_response.xedit_paths)
        
        # Generate main content HTML
        main_content_html = self._generate_main_content_html(parsed_response.code_files)
        
        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XEdit - {project_name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: #ffffff;
            height: 100vh;
            overflow: hidden;
        }}
        
        .header {{
            background: rgba(0,0,0,0.3);
            padding: 15px 25px;
            border-bottom: 2px solid #00ff88;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .header h1 {{
            color: #00ff88;
            font-size: 24px;
            text-shadow: 0 0 10px #00ff88;
        }}
        
        .stats {{
            color: #ffffff;
            font-size: 14px;
        }}
        
        .container {{
            display: flex;
            height: calc(100vh - 80px);
        }}
        
        .sidebar {{
            width: 350px;
            background: rgba(0,0,0,0.4);
            border-right: 2px solid #00ff88;
            overflow-y: auto;
        }}
        
        .sidebar-section {{
            border-bottom: 1px solid rgba(0,255,136,0.3);
            padding: 15px;
        }}
        
        .sidebar-title {{
            color: #00ff88;
            font-size: 16px;
            font-weight: bold;
            margin-bottom: 10px;
            text-transform: uppercase;
        }}
        
        .file-item, .function-item {{
            background: rgba(255,255,255,0.1);
            margin: 5px 0;
            padding: 8px 12px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.3s ease;
            border-left: 3px solid transparent;
        }}
        
        .file-item:hover, .function-item:hover {{
            background: rgba(0,255,136,0.2);
            border-left-color: #00ff88;
            transform: translateX(5px);
        }}
        
        .file-name {{
            color: #ffffff;
            font-weight: bold;
        }}
        
        .file-details {{
            color: #cccccc;
            font-size: 12px;
            margin-top: 2px;
        }}
        
        .function-id {{
            color: #ffaa00;
            font-size: 12px;
            font-weight: bold;
        }}
        
        .function-name {{
            color: #ffffff;
            margin-top: 2px;
        }}
        
        .main-content {{
            flex: 1;
            background: rgba(0,0,0,0.2);
            overflow-y: auto;
            padding: 20px;
        }}
        
        .code-section {{
            background: rgba(0,0,0,0.6);
            border: 1px solid #00ff88;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        
        .code-header {{
            background: rgba(0,255,136,0.1);
            padding: 10px 15px;
            border-bottom: 1px solid #00ff88;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .code-filename {{
            color: #00ff88;
            font-weight: bold;
        }}
        
        .code-language {{
            background: #00ff88;
            color: #000000;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
        }}
        
        .code-content {{
            padding: 15px;
            color: #ffffff;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            line-height: 1.5;
            white-space: pre-wrap;
            overflow-x: auto;
        }}
        
        .project-overview {{
            background: rgba(0,255,136,0.1);
            border: 1px solid #00ff88;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        
        .overview-title {{
            color: #00ff88;
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        
        .overview-content {{
            color: #ffffff;
            line-height: 1.6;
        }}
        
        .deploy-button {{
            background: linear-gradient(45deg, #00ff88, #00cc70);
            color: #000000;
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
        }}
        
        .deploy-button:hover {{
            transform: scale(1.05);
            box-shadow: 0 5px 15px rgba(0,255,136,0.4);
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🎯 XEdit - {project_name}</h1>
        <div class="stats">
            Session: {session_timestamp} | Files: {parsed_response.total_files} | Chars: {parsed_response.total_chars:,} | XEdit Paths: {len(parsed_response.xedit_paths)}
        </div>
        <button class="deploy-button" onclick="deployProject()">🚀 Deploy PCOCK</button>
    </div>
    
    <div class="container">
        <div class="sidebar">
            <div class="sidebar-section">
                <div class="sidebar-title">📁 Code Files</div>
                {file_list_html}
            </div>
            
            <div class="sidebar-section">
                <div class="sidebar-title">🎯 XEdit Paths</div>
                {function_list_html}
            </div>
        </div>
        
        <div class="main-content">
            <div class="project-overview">
                <div class="overview-title">📋 Project Overview</div>
                <div class="overview-content">{parsed_response.project_overview}</div>
            </div>
            
            {main_content_html}
        </div>
    </div>
    
    <script>
        function deployProject() {{
            console.log('🚀 Deploying PCOCK package...');
            // Add PCOCK deployment logic here
            alert('🚀 PCOCK deployment initiated!');
        }}
        
        function selectFile(filename) {{
            document.querySelectorAll('.file-item').forEach(item => {{
                item.style.borderLeftColor = 'transparent';
            }});
            event.target.closest('.file-item').style.borderLeftColor = '#00ff88';
            
            const codeSection = document.getElementById('code-' + filename.replace(/[^a-zA-Z0-9]/g, ''));
            if (codeSection) {{
                codeSection.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
            }}
        }}
        
        function selectFunction(xeditId) {{
            document.querySelectorAll('.function-item').forEach(item => {{
                item.style.borderLeftColor = 'transparent';
            }});
            event.target.closest('.function-item').style.borderLeftColor = '#ffaa00';
            
            console.log('Selected XEdit path:', xeditId);
        }}
    </script>
</body>
</html>"""
        
        return html_template
    
    def _generate_file_list_html(self, code_files: List[CodeFile]) -> str:
        """Generate HTML for file list sidebar"""
        
        if not code_files:
            return '<div class="file-item">No code files found</div>'
        
        html_parts = []
        for code_file in code_files:
            file_id = code_file.filename.replace(/[^a-zA-Z0-9]/g, '')
            html_parts.append(f'''
                <div class="file-item" onclick="selectFile('{code_file.filename}')">
                    <div class="file-name">{code_file.filename}</div>
                    <div class="file-details">
                        {code_file.language.upper()} • {code_file.size_chars:,} chars • 
                        {len(code_file.functions)} functions • {len(code_file.classes)} classes
                    </div>
                </div>
            ''')
        
        return ''.join(html_parts)
    
    def _generate_function_list_html(self, xedit_paths: List[Dict[str, Any]]) -> str:
        """Generate HTML for function/XEdit paths list"""
        
        if not xedit_paths:
            return '<div class="function-item">No XEdit paths generated</div>'
        
        html_parts = []
        for path in xedit_paths:
            html_parts.append(f'''
                <div class="function-item" onclick="selectFunction('{path['id']}')">
                    <div class="function-id">{path['id']}</div>
                    <div class="function-name">{path['description']}</div>
                </div>
            ''')
        
        return ''.join(html_parts)
    
    def _generate_main_content_html(self, code_files: List[CodeFile]) -> str:
        """Generate HTML for main content area showing code"""
        
        if not code_files:
            return '<div class="code-section"><div class="code-content">No code files to display</div></div>'
        
        html_parts = []
        for code_file in code_files:
            file_id = code_file.filename.replace(/[^a-zA-Z0-9]/g, '')
            html_parts.append(f'''
                <div class="code-section" id="code-{file_id}">
                    <div class="code-header">
                        <div class="code-filename">{code_file.filename}</div>
                        <div class="code-language">{code_file.language.upper()}</div>
                    </div>
                    <div class="code-content">{self._escape_html(code_file.content)}</div>
                </div>
            ''')
        
        return ''.join(html_parts)
    
    def _generate_error_html(self, parsed_response: ParsedResponse, session_timestamp: str, project_name: str) -> str:
        """Generate error HTML when parsing fails"""
        
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XEdit Error - {project_name}</title>
    <style>
        body {{
            font-family: 'Consolas', monospace;
            background: #1a1a1a;
            color: #ff6b6b;
            padding: 40px;
            text-align: center;
        }}
        .error-container {{
            max-width: 600px;
            margin: 0 auto;
            background: rgba(255,107,107,0.1);
            border: 2px solid #ff6b6b;
            border-radius: 8px;
            padding: 40px;
        }}
        h1 {{ color: #ff6b6b; margin-bottom: 20px; }}
        .error-message {{ font-size: 18px; margin-bottom: 20px; }}
        .session-info {{ color: #888; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="error-container">
        <h1>❌ XEdit Parsing Error</h1>
        <div class="error-message">{parsed_response.project_overview}</div>
        <div class="session-info">Session: {session_timestamp}</div>
    </div>
</body>
</html>'''
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML characters for safe display"""
        return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')

# Factory function for integration
def create_enhanced_xedit_parser():
    """Factory function to create enhanced parser"""
    return EnhancedXEditParser()
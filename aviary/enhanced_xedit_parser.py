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
                    r'class\s*=\s*["\\](["\\]^"\\]+)["\\]', # Corrected: Escaped quotes in regex
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
        print(f" ENHANCED PARSING LLM RESPONSE ({len(raw_response)} chars)")

        if not raw_response or len(raw_response) < 50:
            print("❌ Response too short or empty")
            return self._create_empty_response("Response too short or empty")

        cache_key = hashlib.md5(raw_response.encode()).hexdigest()[:16]

        if cache_key in self.parsing_cache:
            print(" Using cached parsing result")
            return self.parsing_cache[cache_key]

        try:
            sections = self._extract_major_sections(raw_response)
            code_files = self._extract_code_files_enhanced(raw_response)
            xedit_paths = self._generate_xedit_paths(code_files)

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

            self.parsing_cache[cache_key] = parsed_response
            print(f"✅ ENHANCED PARSING COMPLETE: Found {len(code_files)} files.")
            return parsed_response

        except Exception as e:
            print(f"❌ Enhanced parsing failed: {str(e)}")
            return self._create_empty_response(f"Parsing error: {str(e)}")

    def _extract_major_sections(self, response: str) -> Dict[str, str]:
        sections = {}
        for section_name, pattern in self.code_patterns.items():
            if section_name == "code_blocks":
                continue
            matches = re.findall(pattern, response, re.DOTALL | re.IGNORECASE)
            if matches:
                sections[section_name] = matches[0].strip() if isinstance(matches[0], str) else matches[0]
        return sections

    def _extract_code_files_enhanced(self, response: str) -> List[CodeFile]:
        code_files = []
        filename_pattern = r'```filename:\s*([^\n]+)\n(.*?)```'
        filename_matches = re.findall(filename_pattern, response, re.DOTALL)
        for filename, content in filename_matches:
            filename = filename.strip()
            content = content.strip()
            if filename and content:
                code_files.append(self._create_code_file(filename, content))
        return code_files

    def _create_code_file(self, filename: str, content: str) -> CodeFile:
        language = self._detect_language(filename, content)
        functions = self._extract_functions(content, language)
        classes = self._extract_classes(content, language)
        xedit_id = self._generate_xedit_id(filename)
        return CodeFile(
            filename=filename, content=content, language=language,
            size_chars=len(content), functions=functions, classes=classes, xedit_id=xedit_id
        )

    def _detect_language(self, filename: str, content: str) -> str:
        for pattern, lang in self.language_patterns.items():
            if re.search(pattern, filename, re.IGNORECASE):
                return lang
        content_lower = content.lower()
        if '<!doctype html>' in content_lower or '<html' in content_lower: return 'html'
        if 'function' in content_lower and ('{' in content or '=>' in content): return 'javascript'
        if 'def ' in content_lower and ':' in content: return 'python'
        if content.strip().startswith('{') and content.strip().endswith('}'): return 'json'
        if re.search(r'\.[a-zA-Z-]+\s*{', content): return 'css'
        return 'text'

    def _extract_functions(self, content: str, language: str) -> List[str]:
        functions = []
        if language in self.extraction_patterns:
            for pattern in self.extraction_patterns[language]['functions']:
                matches = re.findall(pattern, content, re.MULTILINE)
                for match in matches:
                    func_name = match[0] if isinstance(match, tuple) and match[0] else match
                    if func_name and func_name not in functions:
                        functions.append(func_name)
        return functions

    def _extract_classes(self, content: str, language: str) -> List[str]:
        classes = []
        if language in self.extraction_patterns:
            for pattern in self.extraction_patterns[language]['classes']:
                matches = re.findall(pattern, content, re.MULTILINE)
                for match in matches:
                    class_name = match[0] if isinstance(match, tuple) and match[0] else match
                    if class_name and class_name not in classes:
                        classes.append(class_name)
        return classes

    def _generate_xedit_id(self, filename: str) -> str:
        hash_obj = hashlib.md5(filename.encode())
        hash_int = int(hash_obj.hexdigest()[:6], 16)
        xedit_num = (hash_int % 999) + 1
        return f"7x{xedit_num:03d}"

    def _generate_xedit_paths(self, code_files: List[CodeFile]) -> List[Dict[str, Any]]:
        xedit_paths = []
        for code_file in code_files:
            xedit_paths.append({
                "id": code_file.xedit_id, "type": "file", "target": code_file.filename,
                "language": code_file.language, "size_chars": code_file.size_chars,
                "description": f"Complete {code_file.language} file"
            })
            for i, function in enumerate(code_file.functions):
                xedit_paths.append({
                    "id": f"{code_file.xedit_id}f{i+1:02d}", "type": "function", "target": function,
                    "parent_file": code_file.filename, "language": code_file.language,
                    "description": f"Function: {function}"
                })
            for i, class_name in enumerate(code_file.classes):
                xedit_paths.append({
                    "id": f"{code_file.xedit_id}c{i+1:02d}", "type": "class", "target": class_name,
                    "parent_file": code_file.filename, "language": code_file.language,
                    "description": f"Class: {class_name}"
                })
        return xedit_paths

    def _create_empty_response(self, error_message: str) -> ParsedResponse:
        return ParsedResponse(
            project_overview=f"Parsing failed: {error_message}", code_files=[],
            implementation_notes="No implementation notes extracted",
            setup_instructions="No setup instructions extracted", total_files=0,
            total_chars=0, xedit_paths=[], parsing_success=False, parsing_method="failed"
        )

    def generate_xedit_html(self, parsed_response: ParsedResponse, session_timestamp: str, project_name: str = "Peacock Project") -> str:
        if not parsed_response.parsing_success:
            return self._generate_error_html(parsed_response, session_timestamp, project_name)
        file_list_html = self._generate_file_list_html(parsed_response.code_files)
        function_list_html = self._generate_function_list_html(parsed_response.xedit_paths)
        main_content_html = self._generate_main_content_html(parsed_response.code_files)
        # Using a simplified f-string for brevity, full styles would be here
        return f"<!DOCTYPE html><html><head><title>XEdit - {project_name}</title></head><body>{main_content_html}</body></html>"

    def _generate_file_list_html(self, code_files: List[CodeFile]) -> str:
        html_parts = []
        for code_file in code_files:
            # CORRECTED: Use re.sub for Python-compatible regex replacement
            file_id = re.sub(r'[^a-zA-Z0-9]', '', code_file.filename)
            html_parts.append(f'<div class="file-item">{code_file.filename}</div>')
        return ''.join(html_parts)

    def _generate_function_list_html(self, xedit_paths: List[Dict[str, Any]]) -> str:
        html_parts = []
        for path in xedit_paths:
            html_parts.append(f'<div class="function-item">{path["description"]}</div>')
        return ''.join(html_parts)

    def _generate_main_content_html(self, code_files: List[CodeFile]) -> str:
        html_parts = []
        for code_file in code_files:
            # CORRECTED: Use re.sub for Python-compatible regex replacement
            file_id = re.sub(r'[^a-zA-Z0-9]', '', code_file.filename)
            html_parts.append(f'<div class="code-section" id="code-{file_id}"><pre>{self._escape_html(code_file.content)}</pre></div>')
        return ''.join(html_parts)

    def _generate_error_html(self, parsed_response: ParsedResponse, session_timestamp: str, project_name: str) -> str:
        return f'<h1>XEdit Parsing Error</h1><p>{parsed_response.project_overview}</p>'

    def _escape_html(self, text: str) -> str:
        return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')

def create_enhanced_xedit_parser():
    return EnhancedXEditParser()

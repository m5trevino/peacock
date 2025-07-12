#!/usr/bin/env python3
"""
master_parser.py - The One True Parser for the Peacock System
This is the specialist. The safe-cracker. Its only job is to take raw,
unpredictable LLM output and turn it into clean, structured, and validated data.
It uses a multi-layer strategy to ensure we always get the goods.
"""

import json
import re
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum

import sys
sys.path.insert(0, '../aviary')
from schemas import CodeFile, FinalCodeOutput

class ParseMethod(Enum):
    PYDANTIC_SCHEMA = "pydantic_schema"
    FILENAME_REGEX = "filename_regex"
    QWEN_JSON_FORMAT = "qwen_json_format"
    FALLBACK_RECOVERY = "fallback_recovery"

@dataclass
class ParseResult:
    success: bool
    data: Optional[FinalCodeOutput] = None
    method: Optional[ParseMethod] = None
    raw_response: str = ""
    errors: Optional[List[str]] = None
    file_count: int = 0
    char_count: int = 0

class MasterParser:
    def parse(self, raw_response: str) -> ParseResult:
        char_count = len(raw_response)
        clean_response = self._strip_think_block(raw_response)

        # STRATEGY 1: Pydantic Schema
        try:
            json_text = self._extract_json_from_response(clean_response)
            if json_text:
                parsed_data = FinalCodeOutput.model_validate_json(json_text)
                print("✅ PARSER: Success with PYDANTIC_SCHEMA method.")
                return ParseResult(success=True, data=parsed_data, method=ParseMethod.PYDANTIC_SCHEMA, raw_response=raw_response, file_count=len(parsed_data.files), char_count=char_count)
        except Exception:
            pass

        # STRATEGY 2: Filename Regex
        try:
            files = self._parse_filename_blocks(clean_response)
            if files:
                project_name = self._infer_project_name(clean_response, files)
                parsed_data = FinalCodeOutput(project_name=project_name, files=files)
                print("✅ PARSER: Success with FILENAME_REGEX method.")
                return ParseResult(success=True, data=parsed_data, method=ParseMethod.FILENAME_REGEX, raw_response=raw_response, file_count=len(files), char_count=char_count)
        except Exception as e:
            pass

        # STRATEGY 3: Qwen's Custom JSON Format
        try:
            json_text = self._extract_json_from_response(clean_response)
            if json_text:
                files = self._parse_qwen_json_format(json_text)
                if files:
                    project_name = self._infer_project_name(clean_response, files)
                    parsed_data = FinalCodeOutput(project_name=project_name, files=files)
                    print("✅ PARSER: Success with QWEN_JSON_FORMAT method.")
                    return ParseResult(success=True, data=parsed_data, method=ParseMethod.QWEN_JSON_FORMAT, raw_response=raw_response, file_count=len(files), char_count=char_count)
        except Exception:
            pass
            
        # STRATEGY 4: Fallback Recovery
        print("❌ PARSER: All parsing strategies failed. Using FALLBACK_RECOVERY.")
        error_message = "Could not parse LLM response into any known structure."
        return ParseResult(success=False, raw_response=raw_response, method=ParseMethod.FALLBACK_RECOVERY, errors=[error_message], char_count=char_count)

    def _strip_think_block(self, text: str) -> str:
        return re.sub(r'<think>.*?</think>\s*', '', text, flags=re.DOTALL)

    def _extract_json_from_response(self, text: str) -> Optional[str]:
        match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
        if match:
            return match.group(1)
        start = text.find('{')
        end = text.rfind('}')
        if start != -1 and end != -1 and end > start:
            potential_json = text[start:end+1]
            try:
                json.loads(potential_json)
                return potential_json
            except json.JSONDecodeError:
                return None
        return None

    def _parse_filename_blocks(self, text: str) -> List[CodeFile]:
        files = []
        patterns = [
            r'\*\*filename:\s*([^\*]+)\*\*\s*```(?:[a-zA-Z]*)?\n(.*?)\n?```',
            r'filename:\s*([^\n]+)\s*```(?:[a-zA-Z]*)?\n(.*?)\n?```',
        ]
        found_code = set()
        for pattern in patterns:
            matches = re.findall(pattern, text, re.DOTALL)
            for filename, code in matches:
                filename = filename.strip()
                code = code.strip()
                if filename and code and code not in found_code:
                    files.append(CodeFile(filename=filename, language=self._detect_language(filename), code=code))
                    found_code.add(code)
        return files
        
    def _parse_qwen_json_format(self, json_text: str) -> List[CodeFile]:
        """Handles the specific case where Qwen returns a single large JSON object."""
        data = json.loads(json_text)
        if 'codeFiles' not in data:
            return []

        files = []
        for filename, file_data in data['codeFiles'].items():
            # Handle nested content structures
            content_obj = file_data.get('content', {})
            code = content_obj.get('code', '')
            if code:
                files.append(CodeFile(
                    filename=filename,
                    language=self._detect_language(filename),
                    code=code
                ))
        return files

    def _detect_language(self, filename: str) -> str:
        ext = Path(filename).suffix.lower()
        lang_map = {'.js': 'javascript', '.py': 'python', '.html': 'html', '.css': 'css', '.json': 'json', '.md': 'markdown', '.sh': 'bash', '.sql': 'sql', '.ts': 'typescript', '.dockerfile': 'dockerfile', '.yml': 'yaml'}
        return lang_map.get(ext, 'text')

    def _infer_project_name(self, text: str, files: List[CodeFile]) -> str:
        for file in files:
            if 'package.json' in file.filename:
                try:
                    pkg_data = json.loads(file.code)
                    if 'name' in pkg_data:
                        return pkg_data['name'].replace('-', ' ').title()
                except: pass
        
        match = re.search(r'#+\s*(.*Project.*|.*Application.*)', text, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return "Untitled Peacock Project"

#!/usr/bin/env python3
"""
🦚 XEDIT - v2.0 - Professional Peacock Code Interface Generator
Generates the final, interactive, three-panel HTML UI based on the target design.
"""

import json
import re
import datetime
from typing import Dict, List, Any
from dataclasses import dataclass
from pathlib import Path
import hashlib

# --- Data Classes for Structured Parsing ---
@dataclass
class CodeFile:
    filename: str
    content: str
    language: str
    size_chars: int
    functions: List[str]
    classes: List[str]
    xedit_id: str

@dataclass
class ParsedResponse:
    project_overview: str
    code_files: List[CodeFile]
    total_files: int
    total_chars: int
    xedit_paths: List[Dict[str, Any]]
    parsing_success: bool

# --- The Main Parser and UI Generator Class ---
class EnhancedXEditParser:
    def __init__(self):
        self.language_patterns = {
            r'\.py$': 'python', r'\.js$': 'javascript', r'\.html?$': 'html',
            r'\.css$': 'css', r'\.json$': 'json', r'\.md$': 'markdown'
        }
        self.extraction_patterns = {
            'python': {'functions': [r'def\s+([a-zA-Z_][a-zA-Z0-9_]*)'], 'classes': [r'class\s+([a-zA-Z_][a-zA-Z0-9_]*)']},
            'javascript': {'functions': [r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)'], 'classes': [r'class\s+([a-zA-Z_$][a-zA-Z0-9_$]*)']}
        }

    def parse_llm_response(self, raw_response: str) -> ParsedResponse:
        print(f"🔍 Parsing LLM code response ({len(raw_response)} chars)...")
        code_files = []
        # A more robust regex to handle code blocks that might not end with a newline before the next ```
        file_matches = re.findall(r"```filename:\s*([^\n]+)\n(.*?)(?=```filename:|\Z)", raw_response, re.DOTALL)
        for filename, content in file_matches:
            if filename.strip() and content.strip():
                code_files.append(self._create_code_file(filename.strip(), content.strip()))
        
        overview_match = re.search(r'\*\*PROJECT OVERVIEW:\*\*\s*(.*?)(?=\*\*COMPLETE CODE FILES:\*\*)', raw_response, re.DOTALL)
        overview = overview_match.group(1).strip() if overview_match else "Project overview not generated."
        
        return ParsedResponse(
            project_overview=overview,
            code_files=code_files,
            total_files=len(code_files),
            total_chars=sum(cf.size_chars for cf in code_files),
            xedit_paths=self._generate_xedit_paths(code_files),
            parsing_success=len(code_files) > 0
        )

    def _create_code_file(self, filename: str, content: str) -> CodeFile:
        lang = self._detect_language(filename)
        # Clean up the start/end of the code block
        content = re.sub(r'^```[a-zA-Z]*\n|```\s*$', '', content).strip()
        return CodeFile(filename=filename, content=content, language=lang, size_chars=len(content),
                        functions=self._extract_patterns(content, lang, 'functions'),
                        classes=self._extract_patterns(content, lang, 'classes'),
                        xedit_id=f"file_{hashlib.md5(filename.encode()).hexdigest()[:6]}")

    def _detect_language(self, filename: str) -> str:
        for pattern, lang in self.language_patterns.items():
            if re.search(pattern, filename): return lang
        return 'text'

    def _extract_patterns(self, content: str, lang: str, p_type: str) -> List[str]:
        patterns = self.extraction_patterns.get(lang, {}).get(p_type, [])
        return re.findall(r'|'.join(patterns), content) if patterns else []

    def _generate_xedit_paths(self, code_files: List[CodeFile]) -> List[Dict[str, Any]]:
        paths = []
        for cf in code_files:
            for i, func in enumerate(cf.functions):
                paths.append({'id': f"{cf.xedit_id}_f{i}", 'name': func, 'type': 'FUNCTION', 'file': cf.filename})
            for i, cls in enumerate(cf.classes):
                paths.append({'id': f"{cf.xedit_id}_c{i}", 'name': cls, 'type': 'CLASS', 'file': cf.filename})
        return paths

    def _escape_html(self, text: str) -> str:
        """Properly escape text for HTML display."""
        return text.replace('&', '&').replace('<', '<').replace('>', '>').replace('"', '"').replace("'", ''')

    def generate_xedit_html(self, parsed_data: ParsedResponse, session_id: str, project_name: str) -> str:
        html_dir = Path("/home/flintx/peacock/html")
        html_dir.mkdir(exist_ok=True)
        output_path = html_dir / f"xedit-{session_id}.html"

        if not parsed_data.parsing_success:
            error_html = f"<h1>XEdit Parsing Error</h1><p>{self._escape_html(parsed_data.project_overview)}</p>"
            with open(output_path, 'w', encoding='utf-8') as f: f.write(error_html)
            return str(output_path)
        
        functions_html = ""
        for path in parsed_data.xedit_paths:
            icon = "⚡" if path['type'] == 'FUNCTION' else "🏗️"
            # Using single quotes for JS onclick to avoid escaping hell
            functions_html += f"""
            <div class='function-item' onclick='highlightCode(`{path['name']}`, `{path['type']}`)'>
                <span>{icon} {path['name']}()</span>
                <span class='item-type'>{path['type']}</span>
                <button class='add-btn' onclick="event.stopPropagation(); addToPayload('{path['id']}', '{path['name']}')">+</button>
            </div>"""

        code_html = ""
        for cf in parsed_data.code_files:
            escaped_code = self._escape_html(cf.content)
            code_html += f"<h3>{cf.filename}</h3><pre><code class='language-{cf.language}'>{escaped_code}</code></pre>"

        final_html = f"""
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>🦚 Peacock XEdit Interface - {project_name}</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/atom-one-dark.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
<style>
    body, html {{ margin: 0; padding: 0; font-family: 'SF Mono', 'Menlo', monospace; background: #0d1117; color: #c9d1d9; }}
    .container {{ display: flex; height: 100vh; }}
    .sidebar, .main, .payload-bar {{ padding: 15px; overflow-y: auto; }}
    .sidebar {{ width: 25%; background: #161b22; border-right: 1px solid #30363d; }}
    .main {{ width: 50%; }}
    .payload-bar {{ width: 25%; background: #161b22; border-left: 1px solid #30363d;}}
    .function-item {{ display: flex; justify-content: space-between; align-items: center; padding: 8px; margin-bottom: 5px; background: #21262d; border-radius: 6px; cursor: pointer; border: 1px solid #30363d; transition: background-color 0.2s; }}
    .function-item:hover {{ background-color: #30363d; }}
    .item-type {{ font-size: 0.7em; padding: 2px 5px; background: #30363d; border-radius: 4px; }}
    .add-btn {{ background: #c9d1d9; color: #161b22; border: none; border-radius: 50%; width: 20px; height: 20px; cursor: pointer; font-weight: bold; }}
    h2 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; margin-bottom: 10px;}}
    h3 {{ color: #c9d1d9; margin-top: 20px; margin-bottom: 10px; }}
    pre code {{ border-radius: 6px; padding: 1em !important; }}
    .highlight {{ background-color: rgba(255, 229, 100, 0.15); box-shadow: -3px 0 0 0 #ffaf38; }}
</style>
</head><body><div class="container">
<div class="sidebar"><h2>Functions & Classes</h2><div id="functions-list">{functions_html}</div></div>
<div class="main"><h2>Generated Code</h2><div id="code-container">{code_html}</div></div>
<div class="payload-bar"><h2>Optimized Payload</h2><div id="payload-display">Click functions to add to payload...</div></div>
</div>
<script>
    document.addEventListener('DOMContentLoaded', () => hljs.highlightAll());
    const payload = [];
    function highlightCode(name, type) {{
        document.querySelectorAll('span.highlight').forEach(el => el.classList.remove('highlight'));
        // Build a robust regex to find the function/class definition
        const cleanedName = name.replace(/[-\/\\^$*+?.()|[\]{{}}]/g, '\\\\$&');
        const regex = new RegExp('(class|def|function)\\\\s+' + cleanedName + '[\\\\s(:]', 'g');
        const codeElements = document.querySelectorAll('code');
        codeElements.forEach(el => {{
            const codeText = el.textContent;
            if (codeText.match(regex)) {{
                const highlightedText = codeText.replace(regex, `<span class="highlight">$&</span>`);
                el.innerHTML = highlightedText;
                // Scroll to the highlighted element
                const highlightedEl = el.querySelector('.highlight');
                if(highlightedEl) highlightedEl.scrollIntoView({{behavior: 'smooth', block: 'center'}});
            }}
        }});
    }}
    function addToPayload(id, name) {{
        if (!payload.find(p => p.id === id)) {{
            payload.push({{id, name}});
            updatePayloadUI();
        }}
    }}
    function updatePayloadUI() {{
        const container = document.getElementById('payload-display');
        container.innerHTML = payload.map(p => `<div class="payload-item">${{p.name}}</div>`).join('');
    }}
</script>
</body></html>"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(final_html)
        print(f"✅ Professional XEdit HTML generated: {output_path}")
        return str(output_path)

def create_enhanced_xedit_parser(): return EnhancedXEditParser()

if __name__ == '__main__':
    print("This is a library module. It should be imported by the MCP.")
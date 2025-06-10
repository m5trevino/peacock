#!/usr/bin/env python3
"""
Updated MCP Server with New XEdit Parser Integration
Replaces the broken auto-xedit generation with the new parser system
"""

import http.server
import socketserver
import json
import os
import sys
import argparse
import datetime
import re
from pathlib import Path

# --- CONFIGURATION ---
HOST = "127.0.0.1"
PORT = 8000
PROCESS_PATH = "/process"

# GROQ API CONFIGURATION
GROQ_API_KEY = "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"

# PEACOCK MULTI-MODEL STRATEGY (Based on your test results)
PEACOCK_MODEL_STRATEGY = {
    "primary_model": "gemma2-9b-it",        # Best overall mixed content
    "speed_model": "llama3-8b-8192",        # When speed is critical  
    "explanation_model": "llama3-8b-8192",  # When detailed explanations needed
    "json_model": "llama3-8b-8192",         # Most reliable JSON parsing
    "fallback_model": "llama-3.1-8b-instant"
}

# STAGE-SPECIFIC MODEL ASSIGNMENT (Based on your optimization results)
PEACOCK_STAGE_MODELS = {
    "spark_analysis": "llama3-8b-8192",        # 63.2 - Speed for requirements
    "falcon_architecture": "gemma2-9b-it",     # 66.9 - Structure champion  
    "eagle_implementation": "llama-3.1-8b-instant", # 70.1 - Code generation beast
    "hawk_qa": "gemma2-9b-it",                  # 61.8 - QA structure
    "code_analysis": "llama-3.1-8b-instant"    # 70.6 - Code review king
}

# OPTIMIZED GROQ CONFIG (No JSON mode - mantequilla style)
GROQ_CONFIG = {
    "temperature": 0.3,  # Optimized for consistency
    "max_tokens": 1024,  # Sufficient for most tasks
    "top_p": 0.8,
    "use_json_mode": False  # CRITICAL: Don't use JSON mode
}

# GLOBAL LOGGING SETTINGS
LOGGING_ENABLED = False
SESSION_TIMESTAMP = ""

def init_logging():
    """Initialize logging with session timestamp"""
    global SESSION_TIMESTAMP
    now = datetime.datetime.now()
    week = now.isocalendar()[1]  # Week of year
    day = now.day
    hour = now.hour
    minute = now.minute
    SESSION_TIMESTAMP = f"{week}-{day}-{hour}{minute:02d}"
    
    # Create logs directory
    logs_dir = Path("/home/flintx/peacock/logs")
    logs_dir.mkdir(exist_ok=True)
    
    if LOGGING_ENABLED:
        print(f"🔍 LOGGING ENABLED - Session: {SESSION_TIMESTAMP}")
        print(f"📁 Logs: /home/flintx/peacock/logs/")

def cli_progress(stage, status, message="", error=None):
    """Enhanced CLI progress output"""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    
    stage_icons = {
        "SPARK": "⚡",
        "FALCON": "🦅", 
        "EAGLE": "🦅",
        "HAWK": "🦅",
        "XEDIT": "🎯"
    }
    
    stage_colors = {
        "START": "\033[94m",     # Blue
        "WORKING": "\033[93m",   # Yellow
        "SUCCESS": "\033[92m",   # Green
        "ERROR": "\033[91m",     # Red
        "END": "\033[0m"         # Reset
    }
    
    icon = stage_icons.get(stage, "🔄")
    color = stage_colors.get(status, "")
    reset = stage_colors["END"]
    
    if status == "START":
        print(f"\n{color}[{timestamp}] {icon} {stage} STARTING{reset}")
        if message:
            print(f"         └─ {message}")
    elif status == "WORKING":
        print(f"{color}[{timestamp}] {icon} {stage} PROCESSING...{reset}")
        if message:
            print(f"         └─ {message}")
    elif status == "SUCCESS":
        print(f"{color}[{timestamp}] ✅ {stage} COMPLETED{reset}")
        if message:
            print(f"         └─ {message}")
    elif status == "ERROR":
        print(f"{color}[{timestamp}] ❌ {stage} FAILED{reset}")
        if error:
            print(f"         └─ ERROR: {error}")
        if message:
            print(f"         └─ {message}")
    
    # Always flush output immediately
    sys.stdout.flush()

def select_optimal_model(command, priority="balanced"):
    """Select best model based on task and priority"""
    
    if priority == "speed":
        return PEACOCK_MODEL_STRATEGY["speed_model"]
    elif priority == "structure":
        return "gemma2-9b-it"
    elif priority == "explanation":
        return PEACOCK_MODEL_STRATEGY["explanation_model"]
    
    # Default assignments by stage
    return PEACOCK_STAGE_MODELS.get(command, PEACOCK_MODEL_STRATEGY["primary_model"])

def validate_response_quality(response_content, command):
    """Fixed validation - EAGLE generates code not JSON"""
    if len(response_content.strip()) < 50: 
        return False
    if command == "eagle_implementation": 
        return "```" in response_content or "filename:" in response_content
    return True

def parse_mixed_response(response_text, expected_format="mixed"):
    """Parse responses containing multiple content types"""
    
    parsed_data = {
        "explanation": "",
        "structured_data": {},
        "code_blocks": [],
        "success": False
    }
    
    # Extract explanations (text outside code blocks and JSON)
    explanation_text = re.sub(r'```.*?```', '', response_text, flags=re.DOTALL)
    explanation_text = re.sub(r'\{.*?\}', '', explanation_text, flags=re.DOTALL)
    parsed_data["explanation"] = explanation_text.strip()
    
    # Extract code blocks
    code_blocks = re.findall(r'```[\w]*\n(.*?)\n```', response_text, re.DOTALL)
    parsed_data["code_blocks"] = [block.strip() for block in code_blocks]
    
    # Extract JSON
    json_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
    json_matches = re.findall(json_pattern, response_text, re.DOTALL)
    
    for match in json_matches:
        try:
            parsed_json = json.loads(match)
            parsed_data["structured_data"] = parsed_json
            parsed_data["success"] = True
            break
        except:
            continue
    
    return parsed_data

def call_optimized_groq(prompt, command):
    """Call Groq with optimized model selection and fallback logic"""
    
    primary_model = select_optimal_model(command)
    fallback_models = [
        PEACOCK_MODEL_STRATEGY["speed_model"], 
        PEACOCK_MODEL_STRATEGY["fallback_model"]
    ]
    
    # Build models to try (primary + fallbacks, avoid duplicates)
    models_to_try = [primary_model] + [m for m in fallback_models if m != primary_model]
    
    cli_progress(command.upper(), "START", f"Using {primary_model}")

    # PROMPT LOGGING: Always log prompts if logging is enabled
    if LOGGING_ENABLED:
        prompt_log_file = f"/home/flintx/peacock/logs/promptlog-{SESSION_TIMESTAMP}.txt"
        with open(prompt_log_file, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {command.upper()} PROMPT TO {primary_model}\n")
            f.write("=" * 80 + "\n")
            f.write(f"STAGE: {command}\n")
            f.write(f"PROMPT LENGTH: {len(prompt)} chars\n")
            f.write("-" * 40 + "\n")
            f.write(prompt)
            f.write("\n" + "=" * 80 + "\n\n")

    for model in models_to_try:
        try:
            from groq import Groq
            client = Groq(api_key=GROQ_API_KEY)
            
            cli_progress(command.upper(), "WORKING", f"Calling {model}...")
            
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=GROQ_CONFIG["temperature"],
                max_tokens=GROQ_CONFIG["max_tokens"],
                top_p=GROQ_CONFIG["top_p"]
                # NO response_format parameter - this is critical
            )
            
            content = response.choices[0].message.content
            
            # Validate response quality
            if validate_response_quality(content, command):
                cli_progress(command.upper(), "SUCCESS", f"Model: {model}, Length: {len(content)} chars")
                
                if LOGGING_ENABLED:
                    log_file = f"/home/flintx/peacock/logs/response-{SESSION_TIMESTAMP}.txt"
                    with open(log_file, "a", encoding="utf-8") as f:
                        f.write(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {command.upper()} SUCCESS - {model}\n")
                        f.write("=" * 80 + "\n")
                        f.write(content)
                        f.write("\n" + "=" * 80 + "\n\n")
                
                return {
                    "success": True,
                    "text": content,
                    "model_used": model,
                    "parsed": parse_mixed_response(content)
                }
            else:
                print(f"         └─ Quality validation failed for {model}")
                
        except Exception as e:
            cli_progress(command.upper(), "ERROR", f"Model {model} failed", str(e))
            continue

    return {
        "success": False, 
        "error": "All models failed",
        "models_tried": models_to_try
    }

# ===== NEW XEDIT PARSER INTEGRATION =====

class PeacockResponseParser:
    """Parse LLM responses into structured content for XEdit generation"""
    
    def __init__(self):
        self.session_timestamp = SESSION_TIMESTAMP
        
    def parse_llm_response(self, response_text: str, project_name: str = "Generated Project"):
        """Main parsing function - converts raw LLM response to structured data"""
        
        cli_progress("XEDIT", "WORKING", f"Parsing response ({len(response_text)} chars)")
        
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
            # Extract code files with proper structure
            parsed_data["code_files"] = self._extract_code_files(response_text)
            cli_progress("XEDIT", "WORKING", f"Found {len(parsed_data['code_files'])} code files")
            
            # Extract explanations
            parsed_data["explanations"] = self._extract_explanations(response_text)
            
            # Extract JSON data
            parsed_data["json_data"] = self._extract_json_data(response_text)
            
            # Calculate totals
            parsed_data["total_sections"] = (
                len(parsed_data["explanations"]) + 
                len(parsed_data["code_files"]) + 
                len(parsed_data["json_data"])
            )
            
        except Exception as e:
            cli_progress("XEDIT", "ERROR", "Parsing failed", str(e))
            parsed_data["parsing_success"] = False
            parsed_data["error"] = str(e)
        
        return parsed_data
    
    def _extract_code_files(self, text: str):
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
                "type": "code_file"
            })
        
        # Pattern 2: Simple code blocks if no filename-based blocks found
        if not code_files:
            pattern2 = r'```(\w+)?\s*(.*?)```'
            matches2 = re.findall(pattern2, text, re.DOTALL)
            
            for i, (language, code) in enumerate(matches2):
                if len(code.strip()) > 50:
                    ext = self._language_to_extension(language)
                    code_files.append({
                        "filename": f"main{ext}",
                        "language": language.lower() if language else "text",
                        "code": code.strip(),
                        "size": len(code.strip()),
                        "type": "code_file"
                    })
        
        return code_files
    
    def _extract_explanations(self, text: str):
        """Extract explanation paragraphs from response"""
        explanations = []
        
        # Remove code blocks and JSON from text
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
    
    def _extract_json_data(self, text: str):
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
    
    def _detect_language(self, filename: str):
        """Detect programming language from filename"""
        ext_map = {
            '.html': 'html', '.css': 'css', '.js': 'javascript',
            '.py': 'python', '.java': 'java', '.cpp': 'cpp'
        }
        
        for ext, lang in ext_map.items():
            if filename.lower().endswith(ext):
                return lang
        return 'text'
    
    def _language_to_extension(self, language: str):
        """Convert language to file extension"""
        lang_map = {
            'html': '.html', 'css': '.css', 'javascript': '.js',
            'python': '.py', 'java': '.java', 'cpp': '.cpp'
        }
        return lang_map.get(language.lower(), '.txt')

class XEditPathGenerator:
    """Generate 7x001 style XEdit paths from parsed code"""
    
    def __init__(self):
        self.path_counter = 1
        
    def generate_xedit_paths(self, code_files):
        """Generate clean 7x001 style paths for all code elements"""
        
        xedit_paths = {}
        
        for file_data in code_files:
            filename = file_data["filename"]
            language = file_data["language"]
            code = file_data["code"]
            
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
        
        return xedit_paths
    
    def _parse_code_elements(self, code: str, language: str, filename: str):
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
    
    def _parse_python_elements(self, lines):
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
    
    def _parse_javascript_elements(self, lines):
        """Parse JavaScript functions and classes"""
        elements = []
        
        for i, line in enumerate(lines, 1):
            # Function declarations
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
    
    def _parse_html_elements(self, lines):
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
    
    def _parse_css_elements(self, lines):
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
    
    def _parse_generic_elements(self, lines):
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
    
    def _select_optimal_model(self, element_type: str, language: str):
        """Select optimal model based on element type and language"""
        # Based on your test results
        if element_type == "class" or language in ["html", "css"]:
            return "gemma2-9b-it"  # Better structure handling
        else:
            return "llama-3.1-8b-instant"  # Better code analysis

def generate_xedit_interface_html(parsed_data, xedit_paths):
    """Generate complete XEdit HTML interface"""
    
    project_name = parsed_data["project_name"]
    session_timestamp = parsed_data["session_timestamp"]
    
    # Combine all code for display
    combined_code = ""
    for file_data in parsed_data["code_files"]:
        combined_code += f"// File: {file_data['filename']}\n"
        combined_code += f"// Language: {file_data['language']}\n"
        combined_code += f"// Size: {file_data['size']} characters\n\n"
        combined_code += file_data['code'] + "\n\n"
        combined_code += "// " + "="*60 + "\n\n"
    
    # Generate functions list HTML
    functions_html = ""
    for xedit_id, path_data in xedit_paths.items():
        icon = "🏗️" if path_data["type"] == "class" else "⚡"
        
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
    
    # Generate code display with line numbers
    lines = combined_code.split('\n')
    code_html = ""
    for i, line in enumerate(lines, 1):
        escaped_line = line.replace('<', '&lt;').replace('>', '&gt;')
        code_html += f'<div class="code-line" data-line="{i}"><span class="line-number">{i:3d}</span><span class="line-content">{escaped_line}</span></div>\n'
    
    # Complete HTML interface
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
            Project: {project_name} • Session: <span class="session-info">{session_timestamp}</span>
        </div>
    </div>

    <div class="main-container">
        <div class="left-panel">
            <div class="panel-header">📋 Functions & Classes ({len(xedit_paths)} items)</div>
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
            <div class="code-header">📁 {project_name}: Generated Code</div>
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
                    alert(`✅ MCP processed ${{xeditIds.length}} XEdit-Paths successfully!`);
                }} else {{
                    alert(`❌ Error: ${{data.error}}`);
                }}
            }})
            .catch(error => {{
                console.error('Error:', error);
                alert(`❌ Connection error: ${{error.message}}`);
            }});
        }}
    </script>
</body>
</html>"""
    
    return html_content

def process_eagle_response_to_xedit(eagle_response_text, project_name="Generated Project"):
    """
    Main function to convert EAGLE response to XEdit interface
    This replaces the broken auto-xedit generation
    """
    
    cli_progress("XEDIT", "START", "Processing EAGLE response to XEdit interface")
    
    try:
        # Step 1: Parse the response
        parser = PeacockResponseParser()
        parsed_data = parser.parse_llm_response(eagle_response_text, project_name)
        
        if not parsed_data["parsing_success"]:
            cli_progress("XEDIT", "ERROR", "Response parsing failed", parsed_data.get('error'))
            return {"success": False, "error": f"Parsing failed: {parsed_data.get('error')}"}
        
        # Step 2: Generate XEdit paths
        path_generator = XEditPathGenerator()
        xedit_paths = path_generator.generate_xedit_paths(parsed_data["code_files"])
        
        cli_progress("XEDIT", "WORKING", f"Generated {len(xedit_paths)} XEdit paths")
        
        # Step 3: Generate HTML interface
        html_interface = generate_xedit_interface_html(parsed_data, xedit_paths)
        
        # Step 4: Save to file
        output_dir = Path("/home/flintx/peacock/html")
        output_dir.mkdir(exist_ok=True)
        
        file_path = output_dir / f"xedit-{SESSION_TIMESTAMP}.html"
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_interface)
        
        cli_progress("XEDIT", "SUCCESS", f"XEdit interface saved: {file_path}")
        
        return {
            "success": True,
            "file_path": str(file_path),
            "xedit_paths": xedit_paths,
            "parsed_data": parsed_data,
            "session_timestamp": SESSION_TIMESTAMP
        }
        
    except Exception as e:
        cli_progress("XEDIT", "ERROR", "XEdit generation failed", str(e))
        return {"success": False, "error": str(e)}

# ===== END NEW XEDIT PARSER INTEGRATION =====

def run_peacock_pipeline(user_request):
    """Run the complete 4-stage Peacock pipeline with NEW XEdit integration"""
    print("\n🦚" + "="*60 + "🦚")
    print("    PEACOCK 4-STAGE PIPELINE (WITH NEW XEDIT)")
    print("🦚" + "="*60 + "🦚")
    print(f"📝 REQUEST: {user_request}")
    print(f"🔥 STRATEGY: Multi-Model Optimization + New XEdit Parser")
    print(f"📝 SESSION: {SESSION_TIMESTAMP}")
    print("="*70)
    
    pipeline_results = {}
    
    # STAGE 1: SPARK (Requirements Analysis)
    spark_prompt = f"""<thinking>
The user wants me to analyze this project idea strategically. I need to break this down into clear, actionable components.

Project: {user_request}

I should provide:
1. Core objective - what's the main goal?
2. Current state - what problems does this solve?
3. Target state - what's the desired outcome?
4. In scope - what features are included?
5. Out of scope - what's not included?
</thinking>

Act as Spark, a strategic requirements analyst. Analyze this project idea:

Project: {user_request}

Provide analysis in this EXACT format:

**1. Core Objective:**
[One clear sentence describing the main goal]

**2. Current State:**
[Current situation/problems this solves]

**3. Target State:**
[Desired end state after implementation]

**4. In Scope:**
- [Feature 1]
- [Feature 2] 
- [Feature 3]

**5. Out of Scope:**
- [What's NOT included]
- [Future considerations]

Then provide the structured data as JSON:
```json
{{
    "core_objective": "string",
    "current_state": "string",
    "target_state": "string", 
    "in_scope": ["list"],
    "out_of_scope": ["list"],
    "confidence_score": 8
}}
```

Keep it strategic and concise. Use your reasoning capabilities."""
    
    spark_response = call_optimized_groq(spark_prompt, "spark_analysis")
    
    if not spark_response.get("success"):
        return {"error": "Spark stage failed", "stage": "SPARK", "details": spark_response}
    
    pipeline_results["spark"] = spark_response
    
    # STAGE 2: FALCON (Architecture Design)
    falcon_prompt = f"""<thinking>
Based on the requirements from Spark, I need to design a technical architecture.

Requirements: {spark_response['text']}

I should think about:
- What technologies would work best
- How to structure the codebase
- What components are needed
- How they interact
</thinking>

Act as Falcon, a senior software architect. Design the technical architecture for this project.

Requirements Analysis:
{spark_response['text']}

Provide architecture design in this EXACT format:

**TECHNOLOGY STACK:**
- Frontend: [Technology choices]
- Backend: [Technology choices]  
- Database: [Technology choices]
- Additional: [Other technologies]

**CORE COMPONENTS:**
1. [Component Name] - [Purpose and functionality]
2. [Component Name] - [Purpose and functionality]
3. [Component Name] - [Purpose and functionality]

**FILE STRUCTURE:**
```
project_root/
├── [folder1]/
│   ├── [file1.ext]
│   └── [file2.ext]
├── [folder2]/
└── [file3.ext]
```

**COMPONENT INTERACTIONS:**
[Describe how components communicate and data flows]

Then provide the structured data as JSON:
```json
{{
    "tech_stack": {{
        "frontend": "string",
        "backend": "string",
        "database": "string"
    }},
    "components": ["list"],
    "complexity": "simple|moderate|complex",
    "confidence_score": 8
}}
```

Focus on practical, implementable architecture."""
    
    falcon_response = call_optimized_groq(falcon_prompt, "falcon_architecture")
    
    if not falcon_response.get("success"):
        return {"error": "Falcon stage failed", "stage": "FALCON", "details": falcon_response}
    
    pipeline_results["falcon"] = falcon_response
    
    # STAGE 3: EAGLE (Implementation)
    eagle_prompt = f"""<thinking>
I need to implement actual code based on this architecture.

Architecture: {falcon_response['text']}

I should:
- Generate complete, working code files
- Follow best practices
- Include proper error handling
- Make sure everything integrates properly
</thinking>

Act as Eagle, a senior developer. Implement the complete codebase based on this architecture.

Architecture Design:
{falcon_response['text']}

Generate complete, working code for each file specified in the architecture.

Format each file as:

**filename: path/to/file.ext**
```language
[Complete file content]
```

Provide:
- Complete, production-ready code
- Proper error handling
- Clear documentation
- Best practices implementation
- All necessary imports and dependencies

Make it work perfectly from the start."""
    
    eagle_response = call_optimized_groq(eagle_prompt, "eagle_implementation")
    
    if not eagle_response.get("success"):
        return {"error": "Eagle stage failed", "stage": "EAGLE", "details": eagle_response}
    
    pipeline_results["eagle"] = eagle_response
    
    # STAGE 4: HAWK (Quality Assurance)
    hawk_prompt = f"""<thinking>
I need to create a comprehensive QA strategy for this implementation.

Implementation: {eagle_response['text']}

I should focus on:
- Test cases for core functionality
- Security validation
- Performance considerations
- Error handling scenarios
- Production readiness
</thinking>

Act as Hawk, a quality assurance specialist. Create comprehensive QA strategy for this implementation.

Implementation Details:
{eagle_response['text']}

Provide QA strategy in this EXACT format:

**1. Test Cases:**
- Functional tests for core features
- Edge cases and error scenarios
- Integration test requirements

**2. Security Validation:**
- Authentication/authorization checks
- Input validation requirements
- Data protection measures

**3. Performance Considerations:**
- Load testing requirements
- Scalability checkpoints
- Resource optimization

**4. Error Handling Scenarios:**
- Network failure handling
- Data corruption recovery
- User error management

**5. Production Readiness Checklist:**
- Deployment requirements
- Monitoring setup
- Backup strategies

Then provide the structured data as JSON:
```json
{{
    "test_coverage": 85,
    "security_score": 9,
    "performance_rating": "good",
    "production_ready": true,
    "confidence_score": 8
}}
```

Be specific and actionable for each area."""
    
    hawk_response = call_optimized_groq(hawk_prompt, "hawk_qa")
    
    if not hawk_response.get("success"):
        return {"error": "Hawk stage failed", "stage": "HAWK", "details": hawk_response}
    
    pipeline_results["hawk"] = hawk_response
    
    # PIPELINE COMPLETE
    print("\n🦚" + "="*60 + "🦚")
    print("    PEACOCK PIPELINE COMPLETED!")
    print("🦚" + "="*60 + "🦚")
    print(f"✅ SPARK: {pipeline_results['spark']['model_used']}")
    print(f"✅ FALCON: {pipeline_results['falcon']['model_used']}") 
    print(f"✅ EAGLE: {pipeline_results['eagle']['model_used']}")
    print(f"✅ HAWK: {pipeline_results['hawk']['model_used']}")
    print(f"📝 SESSION: {SESSION_TIMESTAMP}")
    print("="*70)

    # NEW XEDIT GENERATION WITH PARSER
    try:
        cli_progress("PIPELINE", "SUCCESS", "Auto-generating XEdit interface with new parser...")
        
        # Extract EAGLE response
        eagle_text = pipeline_results.get("eagle", {}).get("text", "")
        
        if eagle_text:
            # Use the new parser system
            project_name = user_request[:50].strip() + " Project"
            xedit_result = process_eagle_response_to_xedit(eagle_text, project_name)
            
            if xedit_result["success"]:
                cli_progress("AUTO-XEDIT", "SUCCESS", 
                    f"XEdit generated: {xedit_result['file_path']} ({len(xedit_result['xedit_paths'])} paths)")
                
                # Add xedit info to results
                pipeline_results["xedit_result"] = xedit_result
            else:
                cli_progress("AUTO-XEDIT", "ERROR", "XEdit generation failed", xedit_result["error"])
        else:
            cli_progress("AUTO-XEDIT", "ERROR", "No EAGLE code found")
    except Exception as e:
        cli_progress("AUTO-XEDIT", "ERROR", "XEdit generation failed", str(e))
    
    return {
        "success": True,
        "pipeline_results": pipeline_results,
        "session": SESSION_TIMESTAMP,
        "optimization": "multi-model-strategy-enabled",
        "xedit_generated": "xedit_result" in pipeline_results
    }

# --- HTTP SERVER (unchanged) ---
class PeacockRequestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        """Override to use our logging system"""
        if LOGGING_ENABLED:
            log_file = f"/home/flintx/peacock/logs/mcplog-{SESSION_TIMESTAMP}.txt"
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] HTTP: {format % args}\n")

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>🦚 Peacock MCP Server - Enhanced with New XEdit Parser</title>
                <style>
                    body {{ 
                        font-family: 'JetBrains Mono', monospace; 
                        background: #0f0f0f; 
                        color: #00ff88; 
                        padding: 20px; 
                    }}
                    .status {{ 
                        background: #1e1e1e; 
                        padding: 20px; 
                        border-radius: 8px; 
                        border: 1px solid #00ff88; 
                    }}
                    .enhancement {{ 
                        background: #2a2a2a; 
                        padding: 15px; 
                        margin: 15px 0; 
                        border-radius: 6px; 
                        border-left: 4px solid #ff6b35; 
                    }}
                </style>
            </head>
            <body>
                <h1>🦚 Peacock MCP Server - Enhanced with New XEdit Parser</h1>
                <div class="status">
                    <h2>✅ Server Status: Online</h2>
                    <p><strong>Primary Model:</strong> {PEACOCK_MODEL_STRATEGY['primary_model']}</p>
                    <p><strong>Speed Model:</strong> {PEACOCK_MODEL_STRATEGY['speed_model']}</p>
                    <p><strong>Session:</strong> {SESSION_TIMESTAMP}</p>
                    <p><strong>Logging:</strong> {'Enabled' if LOGGING_ENABLED else 'Disabled'}</p>
                    <p>🔗 Processing: <code>http://{HOST}:{PORT}{PROCESS_PATH}</code></p>
                </div>
                
                <div class="enhancement">
                    <h3>🎯 NEW XEDIT PARSER INTEGRATION</h3>
                    <p><strong>✅ Fixed:</strong> Broken auto-xedit generation</p>
                    <p><strong>✅ Added:</strong> Advanced response parsing</p>
                    <p><strong>✅ Added:</strong> 7x001 XEdit path generation</p>
                    <p><strong>✅ Added:</strong> Complete HTML interface generation</p>
                    <p><strong>🧈 Result:</strong> Mantequilla smooth handoffs!</p>
                </div>
            </body>
            </html>
            """
            self.wfile.write(html_content.encode("utf-8"))
            
        elif self.path == "/health":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            health_data = {
                "status": "healthy", 
                "models": PEACOCK_MODEL_STRATEGY,
                "stage_models": PEACOCK_STAGE_MODELS,
                "session": SESSION_TIMESTAMP,
                "logging": LOGGING_ENABLED,
                "optimization": "enabled",
                "xedit_parser": "integrated"
            }
            self.wfile.write(json.dumps(health_data).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == PROCESS_PATH:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)

            try:
                received_data = json.loads(post_data.decode('utf-8'))
                
                command = received_data.get('command', 'unknown')
                text_to_process = received_data.get('text', '')
                
                print(f"\n🔄 INCOMING REQUEST: {command}")
                print(f"📝 Request: {text_to_process[:100]}...")
                
                if LOGGING_ENABLED:
                    log_file = f"/home/flintx/peacock/logs/mcplog-{SESSION_TIMESTAMP}.txt"
                    with open(log_file, "a", encoding="utf-8") as f:
                        f.write(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] POST REQUEST: {command}\n")

                # Process request
                if command == "peacock_full":
                    print(f"🦚 STARTING ENHANCED PEACOCK PIPELINE WITH NEW XEDIT PARSER")
                    result = run_peacock_pipeline(text_to_process)
                
                elif command == "fix_xedit_paths":
                    xedit_paths = received_data.get('xedit_paths', [])
                    print(f"🎯 PROCESSING XEDIT PATHS: {xedit_paths}")
                    
                    prompt = f"Fix and improve the code at these XEdit-Paths: {', '.join(xedit_paths)}"
                    llm_response = call_optimized_groq(prompt, "code_analysis")
                    
                    if llm_response.get("success"):
                        result = {
                            "success": True,
                            "response": llm_response['text'],
                            "paths_processed": len(xedit_paths),
                            "model_used": llm_response['model_used']
                        }
                    else:
                        result = {
                            "success": False,
                            "error": llm_response.get('error')
                        }
                
                else:
                    # Default processing with optimized model selection
                    print(f"🔄 PROCESSING DEFAULT COMMAND: {command}")
                    prompt = f"Process this request: {text_to_process}"
                    llm_response = call_optimized_groq(prompt, "general")
                    
                    if llm_response.get("success"):
                        result = {
                            "success": True,
                            "response": llm_response['text'],
                            "model_used": llm_response['model_used']
                        }
                    else:
                        result = {
                            "success": False,
                            "error": llm_response.get('error')
                        }

                # Send response
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                
                response_json = json.dumps(result, indent=2)
                self.wfile.write(response_json.encode("utf-8"))
                
                print(f"✅ RESPONSE SENT: {len(response_json)} bytes")

            except Exception as e:
                print(f"❌ SERVER ERROR: {e}")
                self.send_response(500)
                self.send_header("Content-type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                error_response = {
                    "success": False,
                    "error": f"Server error: {str(e)}"
                }
                self.wfile.write(json.dumps(error_response).encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

def main():
    """Main function with argument parsing"""
    global LOGGING_ENABLED, PORT
    
    parser = argparse.ArgumentParser(description='🦚 Peacock MCP Server - Enhanced with New XEdit Parser')
    parser.add_argument('--log', '-l', action='store_true', help='Enable maxed logging')
    parser.add_argument('--port', '-p', type=int, default=8000, help='Server port (default: 8000)')
    
    args = parser.parse_args()
    
    LOGGING_ENABLED = args.log
    PORT = args.port
    
    # Initialize logging
    init_logging()
    
    print("🦚" + "="*60 + "🦚")
    print("    PEACOCK MCP SERVER - ENHANCED WITH NEW XEDIT PARSER")
    print("🦚" + "="*60 + "🦚")
    print()
    print(f"🔥 Primary Model: {PEACOCK_MODEL_STRATEGY['primary_model']}")
    print(f"⚡ Speed Model: {PEACOCK_MODEL_STRATEGY['speed_model']}")
    print(f"🧠 Strategy: Intelligent Model Routing")
    print(f"🎯 XEdit Parser: Integrated and Ready")
    print(f"📝 Session: {SESSION_TIMESTAMP}")
    print(f"🔍 Logging: {'Enabled' if LOGGING_ENABLED else 'Disabled'}")
    print()
    print(f"🌐 Server starting on http://{HOST}:{PORT}")
    print()
    print("🚀 ENHANCED PEACOCK SERVER READY!")
    print("   ✅ Fixed broken auto-xedit generation")
    print("   ✅ Added advanced response parsing")
    print("   ✅ Added 7x001 XEdit path generation")
    print("   🧈 Mantequilla smooth handoffs enabled!")
    print("="*70)
    
    try:
        with socketserver.TCPServer((HOST, PORT), PeacockRequestHandler) as httpd:
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Server error: {e}")

if __name__ == "__main__":
    main()
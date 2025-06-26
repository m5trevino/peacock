#!/usr/bin/env python3
"""
xedit.py - Production Peacock XEdit Parser (Pydantic + JSON Schema Implementation)
Based on: Peacock LLM Output Parsing Strategy - The Real Blueprint
"""

import json
import re
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field, validator
from enum import Enum

# PRODUCTION PYDANTIC MODELS (FROM YOUR BLUEPRINT)
class CommandType(str, Enum):
    ANALYZE = "analyze"
    FIX = "fix"
    SPARK = "spark"
    EXPAND = "expand"
    PEACOCK_FULL = "peacock_full"

class CodeLocation(BaseModel):
    file_path: str = Field(description="Full path to the file")
    start_line: int = Field(description="Starting line number (1-based)")
    end_line: int = Field(description="Ending line number (1-based)")
    function_name: Optional[str] = Field(description="Function name if applicable")

class AnalysisResult(BaseModel):
    command_type: CommandType
    confidence_score: int = Field(ge=1, le=10, description="Confidence in analysis (1-10)")
    key_findings: List[str] = Field(description="Main discoveries from analysis")
    recommendations: List[str] = Field(description="Actionable recommendations")
    code_quality_score: Optional[int] = Field(ge=1, le=10, description="Code quality rating")
    
    @validator('key_findings')
    def validate_findings(cls, v):
        if len(v) == 0:
            raise ValueError('At least one finding is required')
        return v

class FixSuggestion(BaseModel):
    command_type: CommandType = CommandType.FIX
    issue_description: str = Field(description="What problem was identified")
    fix_explanation: str = Field(description="Why this fix addresses the issue")
    original_code: str = Field(description="Original problematic code")
    replacement_code: str = Field(description="Fixed code to replace original")
    location: CodeLocation
    confidence_score: int = Field(ge=1, le=10)
    requires_wider_review: bool = Field(description="Whether this fix might affect other code")

class SparkRequirements(BaseModel):
    command_type: CommandType = CommandType.SPARK
    core_objective: str = Field(description="Main goal of the project")
    current_state: str = Field(description="What exists now")
    target_state: str = Field(description="What needs to be built")
    in_scope: List[str] = Field(description="Features/components to include")
    out_of_scope: List[str] = Field(description="Features/components to exclude")
    technical_preferences: Dict[str, str] = Field(default_factory=dict)
    priority_level: str = Field(default="medium", description="Project priority")

class PeacockProjectData(BaseModel):
    command_type: CommandType = CommandType.PEACOCK_FULL
    project_name: str = Field(description="Name of the generated project")
    code_files: List[Dict[str, Any]] = Field(description="Generated code files")
    architecture_notes: Optional[str] = Field(description="Architecture decisions")
    implementation_notes: Optional[str] = Field(description="Implementation details")
    session_timestamp: str = Field(description="Session timestamp")

# PRODUCTION JSON EXTRACTION (FROM YOUR BLUEPRINT)
def extract_json_from_response(response: str) -> str:
    """Extract JSON from LLM response with multiple fallback strategies"""
    
    # Strategy 1: Look for JSON code blocks
    json_block_pattern = r'```(?:json)?\s*(\{.*?\})\s*```'
    matches = re.findall(json_block_pattern, response, re.DOTALL)
    if matches:
        return matches[-1].strip()
    
    # Strategy 2: Look for naked JSON objects
    json_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
    matches = re.findall(json_pattern, response, re.DOTALL)
    for match in reversed(matches):  # Try last match first
        try:
            json.loads(match)
            return match
        except:
            continue
    
    # Strategy 3: Try to clean and extract
    cleaned = response.strip()
    if cleaned.startswith('```') and cleaned.endswith('```'):
        lines = cleaned.split('\n')
        cleaned = '\n'.join(lines[1:-1])
    
    # Strategy 4: Last resort - try the whole response
    try:
        json.loads(cleaned)
        return cleaned
    except:
        raise ValueError("No valid JSON found in response")

# PRODUCTION PARSER WITH ERROR RECOVERY (FROM YOUR BLUEPRINT)
class PeacockResponseParser:
    """Production parser with Pydantic validation and error recovery"""
    
    def __init__(self):
        self.session_timestamp = self._get_session_timestamp()
        self.schema_models = {
            "analyze": AnalysisResult,
            "fix": FixSuggestion,
            "spark": SparkRequirements,
            "peacock_full": PeacockProjectData
        }
        
        # Fallback regex patterns for when JSON parsing fails
        self.fallback_patterns = {
            "peacock_full": {
                "code_files": r'```(\w+)?\s*(?:#\s*(.+?)\s*)?\n(.*?)\n```',
                "project_sections": r'#{1,3}\s*(.+?)\n(.*?)(?=\n#{1,3}|\Z)'
            }
        }
    
    def parse_llm_response(self, response_text: str, project_name: str = "Generated Project") -> Dict[str, Any]:
        """Main parsing function with schema validation and fallbacks"""
        
        # Try Pydantic schema parsing first
        schema_result = self._parse_with_schema(response_text, "peacock_full")
        if schema_result["success"]:
            return {
                "project_name": project_name,
                "session_timestamp": self.session_timestamp,
                "code_files": schema_result["data"].get("code_files", []),
                "parsing_success": True,
                "parsing_method": "pydantic_schema"
            }
        
        # Fallback to regex extraction
        fallback_result = self._fallback_parse(response_text, project_name)
        return fallback_result
    
    def _parse_with_schema(self, response_text: str, command_type: str) -> Dict[str, Any]:
        """Parse using Pydantic schema validation"""
        
        try:
            # Extract JSON from response
            json_text = extract_json_from_response(response_text)
            
            # Get the appropriate schema model
            schema_model = self.schema_models.get(command_type)
            if not schema_model:
                return {"success": False, "error": "unknown_command_type"}
            
            # Parse and validate using Pydantic
            parsed_obj = schema_model.parse_raw(json_text)
            
            return {
                "success": True,
                "data": parsed_obj.dict(),
                "method": "pydantic_schema"
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "method": "schema_failed"
            }
    
    def _fallback_parse(self, response_text: str, project_name: str) -> Dict[str, Any]:
        """Fallback regex parsing when schema fails"""
        
        code_files = []
        
        # Extract code blocks using regex
        code_pattern = r'```(\w+)?\s*(?:#\s*(.+?)\s*)?\n(.*?)\n```'
        matches = re.findall(code_pattern, response_text, re.DOTALL)
        
        for i, (language, filename_comment, code) in enumerate(matches):
            if len(code.strip()) > 20:  # Only substantial code blocks
                
                # Determine filename
                if filename_comment:
                    filename = filename_comment.strip()
                elif language:
                    filename = f"file{i+1:02d}.{language}"
                else:
                    filename = f"file{i+1:02d}.txt"
                
                code_files.append({
                    "id": f"code{i+1:03d}",
                    "filename": filename,
                    "language": language or "text",
                    "code": code.strip(),
                    "size": len(code.strip()),
                    "type": "code_file"
                })
        
        return {
            "project_name": project_name,
            "session_timestamp": self.session_timestamp,
            "code_files": code_files,
            "parsing_success": True,
            "parsing_method": "regex_fallback"
        }
    
    def _get_session_timestamp(self) -> str:
        """Generate session timestamp matching MCP format"""
        now = datetime.datetime.now()
        return f"{now.strftime('%U')}-{now.strftime('%w')}-{now.strftime('%H%M')}"

# PRODUCTION XEDIT PATH GENERATOR
class XEditPathGenerator:
    """Generate 7x001 style XEdit paths from parsed content"""
    
    def __init__(self):
        self.path_counter = 1
    
    def generate_xedit_paths(self, code_files: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Generate clean 7x001 style paths for all code elements"""
        
        xedit_paths = {}
        
        for file_data in code_files:
            if "code" in file_data:
                # Parse code structure
                code_elements = self._parse_code_structure(file_data["code"], file_data.get("language", "text"))
                
                # Generate XEdit paths for each element
                for element in code_elements:
                    xedit_id = f"7x{self.path_counter:03d}"
                    
                    xedit_paths[xedit_id] = {
                        "display_name": element["name"],
                        "type": element["type"],
                        "filename": file_data["filename"],
                        "language": file_data.get("language", "text"),
                        "line_start": element["line_start"],
                        "line_end": element["line_end"],
                        "lines_display": f"{element['line_start']}-{element['line_end']}",
                        "technical_path": f"{file_data['filename']}::{element['type']}.{element['name']}"
                    }
                    
                    self.path_counter += 1
        
        return xedit_paths
    
    def _parse_code_structure(self, code_content: str, language: str) -> List[Dict[str, Any]]:
        """Parse code to extract functions, classes, and structure"""
        
        elements = []
        lines = code_content.split('\n')
        
        # Language-specific patterns
        if language in ['python', 'py']:
            patterns = [
                (r'def\s+(\w+)\s*\(', 'function'),
                (r'class\s+(\w+)', 'class'),
            ]
        elif language in ['javascript', 'js']:
            patterns = [
                (r'function\s+(\w+)\s*\(', 'function'),
                (r'const\s+(\w+)\s*=\s*\(', 'function'),
                (r'class\s+(\w+)', 'class'),
            ]
        else:
            patterns = [
                (r'function\s+(\w+)', 'function'),
                (r'def\s+(\w+)', 'function'),
                (r'class\s+(\w+)', 'class'),
            ]
        
        for i, line in enumerate(lines, 1):
            for pattern, element_type in patterns:
                match = re.search(pattern, line)
                if match:
                    elements.append({
                        "name": match.group(1),
                        "type": element_type,
                        "line_start": i,
                        "line_end": min(i + 20, len(lines)),  # Estimate end line
                    })
        
        return elements

# PRODUCTION INTERFACE GENERATOR
class XEditInterfaceGenerator:
    """Generate production XEdit HTML interfaces"""
    
    def generate_xedit_interface_html(self, parsed_data: Dict[str, Any], xedit_paths: Dict[str, Dict[str, Any]]) -> str:
        """Generate complete XEdit HTML interface with production features"""
        
        project_name = parsed_data.get("project_name", "Peacock Project")
        session_timestamp = parsed_data.get("session_timestamp", "unknown")
        
        # Generate XEdit paths if not provided
        if not xedit_paths and parsed_data.get("code_files"):
            path_generator = XEditPathGenerator()
            xedit_paths = path_generator.generate_xedit_paths(parsed_data["code_files"])
        
        # Build functions list HTML
        functions_html = self._generate_functions_html(xedit_paths)
        
        # Build combined code HTML
        code_html = self._generate_code_html(parsed_data.get("code_files", []))
        
        # Generate complete HTML interface
        return self._build_complete_interface(
            project_name, 
            session_timestamp, 
            functions_html, 
            code_html,
            xedit_paths
        )
    
    def _generate_functions_html(self, xedit_paths: Dict[str, Dict[str, Any]]) -> str:
        """Generate HTML for functions list"""
        
        if not xedit_paths:
            return '<div style="color: #6e7681; text-align: center; padding: 20px;">No functions found</div>'
        
        functions_html = ""
        for xedit_id, data in xedit_paths.items():
            icon = "🏗️" if data["type"] == "class" else "⚡"
            
            functions_html += f'''
            <div class="function-item" onclick="highlightFunction('{xedit_id}')">
                <div class="function-info">
                    <span class="function-icon">{icon}</span>
                    <span class="function-name">{data["display_name"]}</span>
                    <span class="function-type">{data["type"]}</span>
                    <div class="function-details">
                        <div class="function-file">{data.get("filename", "unknown")}</div>
                        <div class="function-lines">Lines {data.get("lines_display", "?")}</div>
                    </div>
                </div>
                <button class="add-btn" onclick="addToPayload('{xedit_id}')" title="Add to payload">+</button>
            </div>'''
        
        return functions_html
    
    def _generate_code_html(self, code_files: List[Dict[str, Any]]) -> str:
        """Generate HTML for code display with line numbers"""
        
        if not code_files:
            return '<div style="color: #6e7681; padding: 20px;">No code files available</div>'
        
        # Combine all code files
        combined_code = ""
        for file_data in code_files:
            combined_code += f"// === {file_data.get('filename', 'unknown')} ===\n"
            combined_code += file_data.get('code', '') + "\n\n"
        
        # Generate line-by-line HTML
        lines = combined_code.split('\n')
        code_html = ""
        
        for i, line in enumerate(lines, 1):
            escaped_line = line.replace('<', '&lt;').replace('>', '&gt;')
            code_html += f'<div class="code-line" data-line="{i}"><span class="line-number">{i:3d}</span><span class="line-content">{escaped_line}</span></div>\n'
        
        return code_html
    
    def _build_complete_interface(self, project_name: str, session_timestamp: str, 
                                functions_html: str, code_html: str, 
                                xedit_paths: Dict[str, Dict[str, Any]]) -> str:
        """Build the complete HTML interface"""
        
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🦚 Peacock XEdit Interface - Production</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'SF Mono', monospace; background: #0d1117; color: #e6edf3; height: 100vh; overflow: hidden; }}
        .header {{ background: #161b22; border-bottom: 1px solid #30363d; padding: 12px 20px; display: flex; justify-content: space-between; align-items: center; }}
        .peacock-logo {{ font-size: 18px; font-weight: bold; color: #ff6b35; }}
        .project-info {{ color: #8b949e; font-size: 14px; }}
        .session-info {{ background: rgba(0, 255, 136, 0.1); border: 1px solid #00ff88; border-radius: 6px; padding: 4px 8px; font-size: 12px; color: #00ff88; }}
        .production-badge {{ background: rgba(255, 107, 53, 0.1); border: 1px solid #ff6b35; border-radius: 6px; padding: 4px 8px; font-size: 12px; color: #ff6b35; margin-left: 8px; }}
        .main-container {{ display: flex; height: calc(100vh - 60px); }}
        .left-panel {{ width: 320px; background: #161b22; border-right: 1px solid #30363d; display: flex; flex-direction: column; }}
        .panel-header {{ background: #21262d; padding: 12px 16px; border-bottom: 1px solid #30363d; font-weight: 600; font-size: 13px; color: #7c3aed; }}
        .functions-list {{ flex: 1; overflow-y: auto; padding: 8px; }}
        .function-item {{ background: #21262d; border: 1px solid #30363d; border-radius: 6px; padding: 12px; margin-bottom: 8px; cursor: pointer; transition: all 0.2s; position: relative; }}
        .function-item:hover {{ border-color: #ff6b35; background: #2d333b; transform: translateX(3px); }}
        .function-item.selected {{ border-color: #ff6b35; background: #2d333b; box-shadow: 0 0 0 1px #ff6b35; }}
        .function-info {{ display: flex; flex-direction: column; gap: 4px; }}
        .function-name {{ font-weight: 600; color: #79c0ff; }}
        .function-type {{ background: #30363d; color: #8b949e; padding: 2px 6px; border-radius: 3px; font-size: 10px; text-transform: uppercase; width: fit-content; }}
        .function-details {{ font-size: 11px; color: #6e7681; }}
        .add-btn {{ position: absolute; top: 8px; right: 8px; background: #238636; border: none; color: white; width: 24px; height: 24px; border-radius: 4px; cursor: pointer; font-size: 14px; opacity: 0; transition: opacity 0.2s; }}
        .function-item:hover .add-btn {{ opacity: 1; }}
        .middle-panel {{ width: 300px; background: #161b22; border-right: 1px solid #30363d; display: flex; flex-direction: column; }}
        .payload-header {{ background: #238636; color: white; padding: 12px 16px; font-weight: 600; font-size: 14px; text-align: center; }}
        .payload-container {{ flex: 1; padding: 16px; display: flex; flex-direction: column; }}
        .payload-list {{ flex: 1; background: #21262d; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 16px; overflow-y: auto; min-height: 200px; }}
        .payload-empty {{ color: #6e7681; text-align: center; font-style: italic; margin-top: 50px; }}
        .payload-item {{ background: #2d333b; border: 1px solid #30363d; border-radius: 6px; padding: 12px; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center; }}
        .xedit-id {{ font-family: 'SF Mono', monospace; background: #30363d; color: #ff6b35; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .remove-btn {{ background: #da3633; border: none; color: white; width: 20px; height: 20px; border-radius: 3px; cursor: pointer; font-size: 12px; }}
        .send-button {{ width: 100%; background: #238636; border: none; color: white; padding: 15px; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; transition: all 0.2s; margin-bottom: 15px; }}
        .send-button:disabled {{ background: #30363d; color: #8b949e; cursor: not-allowed; }}
        .deploy-section {{ padding: 15px; background: rgba(46, 204, 113, 0.1); border: 1px solid #2ecc71; border-radius: 8px; }}
        .deploy-title {{ color: #2ecc71; margin-bottom: 10px; font-weight: 600; }}
        .deploy-button {{ width: 100%; padding: 12px; background: linear-gradient(45deg, #2ecc71, #27ae60); border: none; border-radius: 6px; color: white; font-weight: 600; cursor: pointer; }}
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
            <span class="production-badge">Production</span>
        </div>
    </div>

    <div class="main-container">
        <div class="left-panel">
            <div class="panel-header">📋 Functions & Classes</div>
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
                <button class="send-button" id="send-button" onclick="sendToLLM()" disabled>
                    🚀 Send 0 to Production Pipeline
                </button>
                
                <div class="deploy-section">
                    <div class="deploy-title">🦚 PCOCK Deploy</div>
                    <button class="deploy-button" onclick="deployPCOCK()">📦 Create PCOCK Package</button>
                </div>
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
            document.querySelectorAll('.code-line').forEach(line => {{
                line.classList.remove('highlighted');
            }});
            
            document.querySelectorAll('.function-item').forEach(item => {{
                item.classList.remove('selected');
            }});
            
            event.currentTarget.classList.add('selected');
            
            const pathData = xeditPaths[xeditId];
            if (pathData && pathData.line_start && pathData.line_end) {{
                for (let i = pathData.line_start; i <= pathData.line_end; i++) {{
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
            
            if (document.getElementById(`payload-${{xeditId}}`)) {{
                return;
            }}
            
            const emptyMsg = payloadList.querySelector('.payload-empty');
            if (emptyMsg) {{
                emptyMsg.remove();
            }}
            
            const payloadItem = document.createElement("div");
            payloadItem.className = "payload-item";
            payloadItem.id = `payload-${{xeditId}}`;
            payloadItem.innerHTML = `
                <span class="xedit-id">${{xeditId}}</span>
                <button class="remove-btn" onclick="removeFromPayload('${{xeditId}}')">&times;</button>
            `;
            
            payloadList.appendChild(payloadItem);
            
            const count = payloadList.children.length;
            sendButton.textContent = `🚀 Send ${{count}} to Production Pipeline`;
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
                sendButton.textContent = "🚀 Send 0 to Production Pipeline";
                sendButton.disabled = true;
            }} else {{
                sendButton.textContent = `🚀 Send ${{count}} to Production Pipeline`;
            }}
        }}

        function sendToLLM() {{
            const payloadItems = document.querySelectorAll('.payload-item');
            const xeditIds = Array.from(payloadItems).map(item => {{
                return item.querySelector('.xedit-id').textContent;
            }});
            
            fetch('http://127.0.0.1:8000/process', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{
                    command: 'fix_xedit_paths',
                    xedit_paths: xeditIds,
                    session: sessionTimestamp
                }})
            }})
            .then(response => response.json())
            .then(data => {{
                if (data.success) {{
                    alert(`✅ Production pipeline processed ${{xeditIds.length}} XEdit-Paths!`);
                }} else {{
                    alert(`❌ Error: ${{data.error}}`);
                }}
            }})
            .catch(error => {{
                alert(`❌ Connection error: ${{error.message}}`);
            }});
        }}

        function deployPCOCK() {{
            fetch('http://127.0.0.1:8000/process', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{
                    command: 'deploy_pcock',
                    project_name: projectName,
                    session: sessionTimestamp
                }})
            }})
            .then(response => response.json())
            .then(data => {{
                if (data.success) {{
                    alert('🦚 PCOCK package created successfully!');
                }} else {{
                    alert(`❌ Deploy error: ${{data.error}}`);
                }}
            }})
            .catch(error => {{
                alert(`❌ Deploy failed: ${{error.message}}`);
            }});
        }}
    </script>
</body>
</html>'''

def get_session_timestamp():
    """Get session timestamp matching MCP format"""
    now = datetime.datetime.now()
    return f"{now.strftime('%U')}-{now.strftime('%w')}-{now.strftime('%H%M')}"

# PRODUCTION READY - NO MORE BOOTISE TEST CODE
if __name__ == "__main__":
    print(f"✅ Production XEdit ready: {get_session_timestamp()}")
    print("🦚 Pydantic schemas loaded, JSON extraction ready, error recovery enabled")
    print("💯 Ready for enterprise workloads")

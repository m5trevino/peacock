#!/usr/bin/env python3
"""
Enhanced Peacock Formatter with Professional HTML Output
"""

import json
import re
from datetime import datetime
from pathlib import Path

class EnhancedPeacockFormatter:
    def __init__(self):
        self.templates_dir = Path(__file__).parent.parent / "templates"
        self.reports_dir = Path(__file__).parent.parent / "html/reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
    
    def format_spark_to_json(self, llm1_response, user_request):
        """Convert Spark analysis to structured JSON for LLM2"""
        
        # Parse the Spark response sections
        sections = self._parse_spark_sections(llm1_response)
        
        structured_json = {
            "project_meta": {
                "original_request": user_request,
                "timestamp": datetime.now().isoformat(),
                "stage": "spark_to_llm2"
            },
            "requirements": {
                "core_objective": sections.get("core_objective", ""),
                "current_state": sections.get("current_state", ""),
                "target_state": sections.get("target_state", ""),
                "in_scope": sections.get("in_scope", []),
                "out_of_scope": sections.get("out_of_scope", [])
            },
            "llm2_instructions": {
                "task": "generate_complete_implementation",
                "output_format": "structured_code_files",
                "requirements_priority": "high",
                "code_quality": "production_ready"
            }
        }
        
        return structured_json
    
    def format_llm2_to_html(self, llm2_response, structured_json):
        """Convert LLM2 code output to clean HTML dashboard"""
        
        # Parse code files from LLM2 response
        code_files = self._parse_code_files(llm2_response)
        
        html_data = {
            "project_info": structured_json["project_meta"],
            "requirements": structured_json["requirements"],
            "generated_files": code_files,
            "file_count": len(code_files),
            "generation_complete": True
        }
        
        # Generate HTML report
        html_path = self._generate_enhanced_html(html_data)
        
        return {
            "status": "success",
            "html_path": str(html_path),
            "file_count": len(code_files),
            "data": html_data
        }
    
    def _parse_spark_sections(self, text):
        """Extract structured data from Spark analysis"""
        sections = {}
        
        # Simple regex patterns for now - we'll enhance this
        patterns = {
            "core_objective": r"(?:1\)|Core Objective:)(.*?)(?=(?:\d\)|Current State:|$))",
            "current_state": r"(?:2\)|Current State:)(.*?)(?=(?:\d\)|Target State:|$))",
            "target_state": r"(?:3\)|Target State:)(.*?)(?=(?:\d\)|In Scope:|$))",
            "in_scope": r"(?:4\)|In Scope:)(.*?)(?=(?:\d\)|Out of Scope:|$))",
            "out_of_scope": r"(?:5\)|Out of Scope:)(.*?)$"
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            if match:
                content = match.group(1).strip()
                if "scope" in key:
                    # Convert to list for scope items
                    items = [item.strip("- ").strip() for item in content.split('\n') if item.strip()]
                    sections[key] = [item for item in items if item]
                else:
                    sections[key] = content
        
        return sections
    
    def _parse_code_files(self, llm2_text):
        """Extract code files from LLM2 response"""
        files = []
        
        # Look for file patterns like ```filename: path/file.ext
        file_pattern = r'```(?:filename:\s*)?([^\n]+\.[\w]+)\n(.*?)```'
        matches = re.findall(file_pattern, llm2_text, re.DOTALL)
        
        for filename, content in matches:
            files.append({
                "name": filename.strip(),
                "content": content.strip(),
                "language": self._detect_language(filename),
                "lines": len(content.strip().split('\n'))
            })
        
        return files
    
    def _detect_language(self, filename):
        """Detect programming language from filename"""
        ext_map = {
            '.py': 'python', '.js': 'javascript', '.html': 'html',
            '.css': 'css', '.json': 'json', '.md': 'markdown',
            '.sh': 'bash', '.yml': 'yaml', '.yaml': 'yaml'
        }
        
        ext = Path(filename).suffix.lower()
        return ext_map.get(ext, 'text')
    
    def _generate_enhanced_html(self, data):
        """Generate professional-looking HTML with modern styling"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"peacock_report_{timestamp}.html"
        filepath = self.reports_dir / filename
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Peacock Report - {data['project_info']['original_request'][:50]}...</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #2d3748;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
        }}
        
        .peacock-badge {{
            display: inline-block;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 14px;
            margin-bottom: 15px;
        }}
        
        .project-title {{
            font-size: 2rem;
            font-weight: 700;
            color: #1a202c;
            margin-bottom: 10px;
        }}
        
        .project-meta {{
            color: #718096;
            font-size: 14px;
        }}
        
        .section {{
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
        }}
        
        .section-title {{
            font-size: 1.5rem;
            font-weight: 600;
            color: #2d3748;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .requirements-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }}
        
        .requirement-item {{
            background: #f7fafc;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        
        .requirement-label {{
            font-weight: 600;
            color: #4a5568;
            margin-bottom: 5px;
        }}
        
        .files-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }}
        
        .file-count {{
            background: #48bb78;
            color: white;
            padding: 6px 12px;
            border-radius: 12px;
            font-size: 14px;
            font-weight: 600;
        }}
        
        .file-grid {{
            display: grid;
            gap: 20px;
        }}
        
        .file-card {{
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 12px;
            overflow: hidden;
            transition: all 0.2s ease;
        }}
        
        .file-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 12px 20px -5px rgba(0, 0, 0, 0.15);
        }}
        
        .file-header {{
            background: #f8fafc;
            padding: 15px 20px;
            border-bottom: 1px solid #e2e8f0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .file-name {{
            font-weight: 600;
            color: #2d3748;
            font-family: 'SF Mono', Monaco, monospace;
        }}
        
        .file-meta {{
            color: #718096;
            font-size: 14px;
        }}
        
        .code-container {{
            position: relative;
        }}
        
        .code-content {{
            background: #1a202c;
            color: #e2e8f0;
            padding: 20px;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
            font-size: 14px;
            line-height: 1.6;
            overflow-x: auto;
        }}
        
        .copy-btn {{
            position: absolute;
            top: 15px;
            right: 15px;
            background: #4a5568;
            color: white;
            border: none;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 12px;
            cursor: pointer;
            transition: all 0.2s ease;
        }}
        
        .copy-btn:hover {{
            background: #2d3748;
        }}
        
        .stats-bar {{
            background: #f7fafc;
            padding: 15px 20px;
            border-top: 1px solid #e2e8f0;
            display: flex;
            gap: 20px;
            font-size: 14px;
            color: #718096;
        }}
        
        @media (max-width: 768px) {{
            .requirements-grid {{
                grid-template-columns: 1fr;
            }}
            
            .container {{
                padding: 10px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="peacock-badge">🦚 PEACOCK ANALYSIS</div>
            <h1 class="project-title">{data['project_info']['original_request']}</h1>
            <div class="project-meta">
                Generated: {datetime.fromisoformat(data['project_info']['timestamp']).strftime('%B %d, %Y at %I:%M %p')}
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">📋 Requirements Analysis</h2>
            <div class="requirements-grid">
                <div class="requirement-item">
                    <div class="requirement-label">Core Objective</div>
                    <div>{data['requirements']['core_objective']}</div>
                </div>
                <div class="requirement-item">
                    <div class="requirement-label">Current State</div>
                    <div>{data['requirements']['current_state']}</div>
                </div>
                <div class="requirement-item">
                    <div class="requirement-label">Target State</div>
                    <div>{data['requirements']['target_state']}</div>
                </div>
                <div class="requirement-item">
                    <div class="requirement-label">Project Scope</div>
                    <div>
                        <strong>In Scope:</strong> {len(data['requirements']['in_scope'])} items<br>
                        <strong>Out of Scope:</strong> {len(data['requirements']['out_of_scope'])} items
                    </div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <div class="files-header">
                <h2 class="section-title">📁 Generated Code Files</h2>
                <div class="file-count">{data['file_count']} files</div>
            </div>
            
            <div class="file-grid">
"""
        
        # Add each file with enhanced styling
        for i, file_data in enumerate(data['generated_files']):
            html_content += f"""
                <div class="file-card">
                    <div class="file-header">
                        <div class="file-name">{file_data['name']}</div>
                        <div class="file-meta">{file_data['language']} • {file_data['lines']} lines</div>
                    </div>
                    <div class="code-container">
                        <button class="copy-btn" onclick="copyCode({i})">Copy</button>
                        <pre class="code-content" id="code-{i}">{file_data['content']}</pre>
                    </div>
                    <div class="stats-bar">
                        <span>Language: {file_data['language'].title()}</span>
                        <span>Lines: {file_data['lines']}</span>
                        <span>Characters: {len(file_data['content'])}</span>
                    </div>
                </div>
"""
        
        html_content += """
            </div>
        </div>
    </div>
    
    <script>
        function copyCode(index) {
            const codeElement = document.getElementById('code-' + index);
            const text = codeElement.textContent;
            
            navigator.clipboard.writeText(text).then(() => {
                const btn = event.target;
                const originalText = btn.textContent;
                btn.textContent = 'Copied!';
                btn.style.background = '#48bb78';
                
                setTimeout(() => {
                    btn.textContent = originalText;
                    btn.style.background = '#4a5568';
                }, 2000);
            });
        }
    </script>
</body>
</html>
"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filepath

# Test the formatter
if __name__ == "__main__":
    formatter = EnhancedPeacockFormatter()
    print("🦚 Enhanced Peacock Formatter initialized!")
    print(f"Templates dir: {formatter.templates_dir}")
    print(f"Reports dir: {formatter.reports_dir}")

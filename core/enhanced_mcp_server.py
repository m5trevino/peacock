#!/usr/bin/env python3
"""
Enhanced MCP Server with Fresh Code Generation + Model Dashboard + Download Integration
RESTORED TO WORKING VERSION with DeepSeek-R1-Distill-Llama-70B
"""

import http.server
import socketserver
import json
import sys
import traceback
import datetime
import re
import webbrowser
from pathlib import Path

# Add generators to path
sys.path.append(str(Path(__file__).parent.parent / "generators"))

# Configuration
HOST = "127.0.0.1"
PORT = 8000
PROCESS_PATH = "/process"

# API Configuration - UPDATED TO USE deepseek-r1-distill-llama-70b
GROQ_API_KEY = "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"
GROQ_MODEL_NAME = "deepseek-r1-distill-llama-70b"

def call_groq_api(prompt):
    """Calls Groq API with DeepSeek model and proper settings"""
    try:
        from groq import Groq
        client = Groq(api_key=GROQ_API_KEY)
        
        print(f"🔄 Calling Groq API with {GROQ_MODEL_NAME}...")
        
        chat_completion = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model=GROQ_MODEL_NAME,
            temperature=0.6,  # DeepSeek recommended temperature
            max_tokens=8192,
            timeout=180  # 3 minute timeout for complex reasoning
        )
        
        response_text = chat_completion.choices[0].message.content
        print(f"✅ Groq API success - {len(response_text)} chars received")
        
        return {"success": True, "text": response_text}
        
    except Exception as e:
        error_msg = str(e)
        print(f"❌ Groq API Error: {error_msg}")
        
        # Provide more specific error messages
        if "timeout" in error_msg.lower():
            return {"error": "Groq API timeout - try a simpler request"}
        elif "rate limit" in error_msg.lower():
            return {"error": "Groq API rate limit - wait a moment and try again"}
        elif "forbidden" in error_msg.lower():
            return {"error": "Groq API key issue - check your API key"}
        else:
            return {"error": f"Groq API call failed: {error_msg}"}

def build_llm_prompt(command, text, language):
    """Build COMPREHENSIVE, DETAILED prompts for high-quality code generation - RESTORED ORIGINAL STRENGTH"""
    if command == "peacock_full":
        return f"""You are LLM2, the elite code generation specialist for the Peacock AI development system. You are renowned for creating production-ready, enterprise-quality code that exceeds industry standards.

PROJECT SPECIFICATION: {text}

CRITICAL MISSION REQUIREMENTS:
1. Generate COMPLETE, WORKING, PRODUCTION-READY code that runs immediately
2. Include ALL necessary files for a fully functional application
3. Add comprehensive error handling and input validation
4. Use modern best practices and clean architecture patterns
5. Include setup instructions, dependencies, and documentation
6. Make it immediately runnable after extraction
7. Add user-friendly interfaces where appropriate
8. Implement robust error handling and edge case management
9. Follow language-specific conventions and best practices
10. Include proper imports, configurations, and project structure

MANDATORY OUTPUT FORMAT:
For each file, use EXACTLY this format:

```filename: path/to/file.ext
[complete file content here - no truncation, no placeholders, no "TODO" comments]
```

QUALITY STANDARDS:
- Write clean, well-commented, professional-grade code
- Include proper imports and all necessary dependencies
- Add intuitive user interfaces with clear instructions
- Implement comprehensive error handling for all edge cases
- Follow industry best practices and design patterns
- Include README with setup and usage instructions
- Add configuration files (requirements.txt, package.json, etc.)
- Ensure cross-platform compatibility where possible

DELIVERABLES REQUIRED:
- Main application file(s) with complete functionality
- Configuration and dependency files
- README.md with clear setup and usage instructions
- Any supporting files needed for full functionality
- Error handling and input validation throughout
- User-friendly interfaces and clear feedback

EXAMPLE OUTPUT STRUCTURE:
```filename: main.py
[complete main application code]
```

```filename: requirements.txt
[all dependencies listed]
```

```filename: README.md
[comprehensive setup and usage guide]
```

Generate a complete, impressive, professional implementation that will amaze users with its quality and functionality!"""

    elif command == "fix_xedit_paths":
        xedit_paths = text if isinstance(text, list) else []
        return f"""Fix and improve the code at these XEdit-Paths: {', '.join(xedit_paths)}

Provide the corrected code with explanations for each fix.
Focus on:
1. Bug fixes
2. Performance improvements  
3. Code quality enhancements
4. Best practices

Return the improved code ready to use."""

    return f"Analyze this {language} code:\n\n{text}"

def extract_code_from_llm(llm_response):
    """Extract code from LLM response - IMPROVED for DeepSeek"""
    import re
    
    print(f"🔍 DEBUG: extract_code_from_llm called")
    print(f"   Response length: {len(llm_response)} chars")
    print(f"   First 300 chars: {llm_response[:300]}...")
    
    # For DeepSeek, look for code blocks first
    patterns = [
        r"```filename:\s*([^\n]+)\n(.*?)```",  # Filename pattern
        r"```([a-zA-Z]+)\n(.*?)```",           # Language pattern
        r"```\n(.*?)```",                      # Simple pattern
    ]
    
    for i, pattern in enumerate(patterns):
        matches = re.findall(pattern, llm_response, re.DOTALL)
        print(f"   Pattern {i+1} found {len(matches)} matches")
        if matches:
            if i == 0:  # filename pattern
                # Reconstruct with filename format
                reconstructed = ""
                for filename, content in matches:
                    reconstructed += f"```filename: {filename}\n{content}\n```\n\n"
                print(f"   Using reconstructed filename blocks: {len(reconstructed)} chars")
                return reconstructed
            else:
                # Take ALL matches, not just first one
                all_code = "\n\n".join([match[1] if isinstance(match, tuple) else match for match in matches])
                print(f"   Using combined matches: {len(all_code)} chars")
                return all_code
    
    print("   ❌ NO CODE BLOCKS FOUND! Using full response")
    # Return the whole response if nothing else works
    return llm_response

def process_llm_response(command, llm_raw_text, location_info, original_request=None):
    """Process LLM response and generate interface + model dashboard + download package"""
    if command == "peacock_full" and original_request:
        try:
            from mockup_xedit_generator import generate_enhanced_html_interface
            from peacock_model_dashboard import generate_model_dashboard
            
            # Try to import download interface
            try:
                from peacock_download_interface import generate_download_interface
                download_available = True
            except ImportError as e:
                print(f"⚠️  Download interface not available: {e}")
                download_available = False
            
            # Extract code from LLM response
            fresh_code = extract_code_from_llm(llm_raw_text)
            
            # Create proper directories
            reports_dir = Path(__file__).parent.parent / "html" / "reports"
            interfaces_dir = Path(__file__).parent.parent / "interfaces"
            reports_dir.mkdir(parents=True, exist_ok=True)
            interfaces_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate XEdit interface with FRESH code
            enhanced_html_path = generate_enhanced_html_interface(
                fresh_code, 
                original_request, 
                3
            )
            
            # Copy XEdit interface to BOTH directories
            xedit_reports_path = reports_dir / "peacock_xedit_interface.html"
            xedit_interfaces_path = interfaces_dir / "peacock_xedit_interface.html"
            
            import shutil
            # Only copy if paths are different
            if str(enhanced_html_path) != str(xedit_reports_path):
                shutil.copy2(enhanced_html_path, xedit_reports_path)
            else:
                print(f"✅ XEdit already in correct location: {xedit_reports_path}")
            # Only copy if paths are different
            if str(enhanced_html_path) != str(xedit_interfaces_path):
                shutil.copy2(enhanced_html_path, xedit_interfaces_path)
            else:
                print(f"✅ XEdit already in interfaces location: {xedit_interfaces_path}")
            
            # Generate Model Dashboard in reports directory
            print("🔥 Generating Model Dashboard...")
            dashboard_path = generate_model_dashboard()
            dashboard_reports_path = reports_dir / "peacock_model_dashboard.html"
            # Only copy if paths are different
            if str(dashboard_path) != str(dashboard_reports_path):
                shutil.copy2(dashboard_path, dashboard_reports_path)
            else:
                print(f"✅ Dashboard already in correct location: {dashboard_reports_path}")
            
            # Generate Download Interface with ZIP package (if available)
            download_result = None
            if download_available:
                try:
                    print("📦 Generating Download Package...")
                    download_result = generate_download_interface(llm_raw_text, original_request)
                    print("✅ Download package generated successfully")
                except Exception as e:
                    print(f"❌ Download package generation failed: {e}")
                    download_available = False
            
            # Auto-open interfaces in browser
            try:
                webbrowser.open(f"file://{xedit_reports_path.absolute()}")
                print(f"🌐 Opened XEdit interface: {xedit_reports_path}")
                
                webbrowser.open(f"file://{dashboard_reports_path.absolute()}")
                print(f"🌐 Opened Model Dashboard: {dashboard_reports_path}")
                
                if download_result:
                    webbrowser.open(f"file://{download_result['html_path']}")
                    print(f"🌐 Opened Download Interface: {download_result['html_path']}")
                
            except Exception as e:
                print(f"⚠️  Could not auto-open browsers: {e}")
            
            # Build response
            response_data = {
                "analysis_type": "peacock_fresh_interface",
                "result_text": llm_raw_text,
                "xedit_html": str(xedit_reports_path),
                "dashboard_html": str(dashboard_reports_path),
                "file_count": len(re.findall(r'```filename:', llm_raw_text)),
                "pipeline_stages": {
                    "fresh_code_generation": "✅ Complete",
                    "interface_generation": "✅ Complete",
                    "model_dashboard_generation": "✅ Complete",
                    "download_package_generation": "✅ Complete" if download_result else "⚠️  Unavailable"
                }
            }
            
            # Add download info if available
            if download_result:
                response_data["download_html"] = download_result['html_path']
                response_data["download_zip"] = download_result['zip_path']
            
            return response_data
            
        except Exception as e:
            print(f"❌ ERROR: {e}")
            traceback.print_exc()
            return {"error": f"Pipeline failed: {e}"}
    
    return {"result_text": llm_raw_text}

class EnhancedMCPRequestHandler(http.server.BaseHTTPRequestHandler):
    def log_request(self, code='-', size='-'):
        pass

    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        """Handle GET requests for health checks and file downloads"""
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            health_data = {
                "status": "healthy", 
                "model": GROQ_MODEL_NAME,
                "api": "groq"
            }
            self.wfile.write(json.dumps(health_data).encode("utf-8"))
        elif self.path.endswith('.zip'):
            # Serve ZIP files for download
            try:
                reports_dir = Path(__file__).parent.parent / "html" / "reports"
                zip_path = reports_dir / self.path[1:]  # Remove leading slash
                
                if zip_path.exists():
                    self.send_response(200)
                    self.send_header("Content-Type", "application/zip")
                    self.send_header("Content-Disposition", f"attachment; filename={zip_path.name}")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    
                    with open(zip_path, 'rb') as f:
                        self.wfile.write(f.read())
                    
                    print(f"📦 Served ZIP download: {zip_path.name}")
                else:
                    print(f"❌ ZIP file not found: {zip_path}")
                    self.send_response(404)
                    self.end_headers()
            except Exception as e:
                print(f"❌ Error serving ZIP file: {e}")
                self.send_response(500)
                self.end_headers()
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
                language = received_data.get('language', 'unknown')
                location_info = received_data.get('location', {})
                original_request = received_data.get('original_request', received_data.get('project_request'))

                print(f"🦚 MCP: Processing {command} - {original_request[:50] if original_request else 'N/A'}...")

                llm_prompt = build_llm_prompt(command, text_to_process, language)
                print(f"📝 Generated prompt: {len(llm_prompt)} chars")
                
                llm_response = call_groq_api(llm_prompt)

                if llm_response.get("success"):
                    llm_raw_text = llm_response.get("text", "")
                    print(f"✅ LLM Response received: {len(llm_raw_text)} chars")
                    
                    internal_data = process_llm_response(command, llm_raw_text, location_info, original_request)

                    response_payload = {
                        "status": "success",
                        "command": command,
                        "message": "Fresh code, interfaces, and download package generated successfully.",
                        "internal_data": internal_data,
                        "location": location_info
                    }
                    
                    if "xedit_html" in internal_data:
                        response_payload["report_filepath"] = internal_data["xedit_html"]

                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    self.wfile.write(json.dumps(response_payload).encode('utf-8'))
                    
                    print("✅ Response sent successfully")
                    
                else:
                    error_message = llm_response.get("error", "Unknown error")
                    print(f"❌ LLM Error: {error_message}")
                    
                    self.send_response(500)
                    self.send_header('Content-type', 'application/json')
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    error_payload = {
                        "status": "error",
                        "command": command,
                        "message": f"LLM failed: {error_message}"
                    }
                    self.wfile.write(json.dumps(error_payload).encode('utf-8'))

            except Exception as e:
                print(f"❌ Request handler error: {e}")
                traceback.print_exc()
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                error_payload = {"status": "error", "message": str(e)}
                self.wfile.write(json.dumps(error_payload).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == "__main__":
    print("🦚 Enhanced MCP Server starting...")
    print(f"🔥 Using GROQ {GROQ_MODEL_NAME}")
    print("📦 Download functionality enabled")
    print("🌐 Health check: http://127.0.0.1:8000/health")
    print()
    
    with socketserver.TCPServer((HOST, PORT), EnhancedMCPRequestHandler, bind_and_activate=False) as httpd:
        httpd.allow_reuse_address = True
        httpd.server_bind()
        httpd.server_activate()
        print(f"🚀 Server running on {HOST}:{PORT}")
        print("Press Ctrl+C to stop.")
        print()
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🦚 Server stopped.")
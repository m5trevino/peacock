#!/usr/bin/env python3
"""
Enhanced MCP Server with Fresh Code Generation + Model Dashboard + Download Integration
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

# API Configuration - UPDATED TO USE qwen-qwq-32b
GROQ_API_KEY = "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"
GROQ_MODEL_NAME = "qwen-qwq-32b"

def call_groq_api(prompt):
    """Calls Groq API"""
    try:
        from groq import Groq
        client = Groq(api_key=GROQ_API_KEY)
        chat_completion = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model=GROQ_MODEL_NAME,
            temperature=0.1
        )
        return {"success": True, "text": chat_completion.choices[0].message.content}
    except Exception as e:
        return {"error": f"Groq API call failed: {str(e)}"}

def build_llm_prompt(command, text, language):
    """Build prompts for code generation"""
    if command == "peacock_full":
        return f"""
You are LLM2 - expert code generator for Peacock.

Generate COMPLETE, WORKING code for this project:
{text}

Requirements:
1. Make it ACTUALLY functional and ready to run
2. Include ALL necessary files
3. Add proper error handling
4. Use modern best practices

Format each file as:
```filename: path/to/file.ext
[complete file content here]
```

Generate a complete implementation now:
"""
    return f"Analyze this {language} code:\n\n{text}"

def extract_code_from_llm(llm_response):
    """Extract code from LLM response - FIXED for qwen-qwq"""
    import re
    
    print(f"🔍 DEBUG: extract_code_from_llm called")
    print(f"   Response length: {len(llm_response)} chars")
    print(f"   First 300 chars: {llm_response[:300]}...")
    
    # For qwen-qwq, extract EVERYTHING after </think>
    think_match = re.search(r"</think>\s*(.*)", llm_response, re.DOTALL)
    if think_match:
        code_content = think_match.group(1).strip()
        print(f"   Found content after </think>: {len(code_content)} chars")
        print(f"   Using full post-think content as code")
        return code_content
    
    # Fallback - look for code blocks
    patterns = [
        r"```(?:filename:\s*)?[^\n]*\n(.*?)```",  # Original pattern
        r"```python\n(.*?)```",                     # Python specific
        r"```\n(.*?)```",                           # Simple pattern
    ]
    
    for i, pattern in enumerate(patterns):
        matches = re.findall(pattern, llm_response, re.DOTALL)
        print(f"   Pattern {i+1} found {len(matches)} matches")
        if matches:
            # Take ALL matches, not just first one
            all_code = "\n\n".join(matches)
            print(f"   Using combined matches: {len(all_code)} chars")
            return all_code
    
    print("   ❌ NO CODE BLOCKS FOUND! Using full response")
    # Return the whole damn response if nothing else works
    return llm_response

def process_llm_response(command, llm_raw_text, location_info, original_request=None):
    """Process LLM response and generate interface + model dashboard + download package"""
    if command == "peacock_full" and original_request:
        try:
            from mockup_xedit_generator import generate_enhanced_html_interface
            from peacock_model_dashboard import generate_model_dashboard
            from peacock_download_interface import generate_download_interface
            
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
            
            # Generate Download Interface with ZIP package
            print("📦 Generating Download Package...")
            download_result = generate_download_interface(llm_raw_text, original_request)
            
            # Auto-open BOTH files in browser
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
            
            return {
                "analysis_type": "peacock_fresh_interface",
                "result_text": llm_raw_text,
                "xedit_html": str(xedit_reports_path),
                "dashboard_html": str(dashboard_reports_path),
                "download_html": download_result['html_path'] if download_result else None,
                "download_zip": download_result['zip_path'] if download_result else None,
                "file_count": len(re.findall(r'```filename:', llm_raw_text)),
                "pipeline_stages": {
                    "fresh_code_generation": "✅ Complete",
                    "interface_generation": "✅ Complete",
                    "model_dashboard_generation": "✅ Complete",
                    "download_package_generation": "✅ Complete" if download_result else "❌ Failed"
                }
            }
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
                else:
                    self.send_response(404)
                    self.end_headers()
            except Exception as e:
                print(f"Error serving ZIP file: {e}")
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
                llm_response = call_groq_api(llm_prompt)

                if llm_response.get("success"):
                    llm_raw_text = llm_response.get("text", "")
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
                else:
                    error_message = llm_response.get("error", "Unknown error")
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
    with socketserver.TCPServer((HOST, PORT), EnhancedMCPRequestHandler, bind_and_activate=False) as httpd:
        httpd.allow_reuse_address = True
        httpd.server_bind()
        httpd.server_activate()
        print(f"🔥 Server running on {HOST}:{PORT} with GROQ {GROQ_MODEL_NAME}")
        print("📦 Download functionality enabled")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🦚 Server stopped.")
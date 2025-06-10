#!/usr/bin/env python3
"""
FIXED pea-mcp.py - ALL 4 WIRES CONNECTED + Session Coordination
Wire #2: MCP → Birds (orchestrate_full_pipeline)
Wire #4: Response → XEdit (auto-generation with session sync)
"""

import http.server
import socketserver
import json
import os
import sys
import argparse
import datetime
import re
import subprocess
import webbrowser
from pathlib import Path

# Import the birds from the aviary directory
sys.path.append(str(Path(__file__).parent.parent / "aviary"))
try:
    from out_homing import create_homing_orchestrator
    from spark import create_spark_analyst
    from falcon import create_falcon_architect
    from eagle import create_eagle_implementer
    from hawk import create_hawk_qa_specialist
except ImportError as e:
    print(f"Warning: Could not import birds modules: {e}")
    # Create dummy functions to prevent crashes
    def create_homing_orchestrator():
        return None
    def create_spark_analyst():
        return None
    def create_falcon_architect():
        return None
    def create_eagle_implementer():
        return None
    def create_hawk_qa_specialist():
        return None

# Import XEdit parser from core directory
sys.path.append(str(Path(__file__).parent))
try:
    from xedit import PeacockResponseParser, XEditPathGenerator, XEditInterfaceGenerator
except ImportError as e:
    print(f"Warning: Could not import XEdit parser: {e}")

# --- CONFIGURATION ---
HOST = "127.0.0.1"
PORT = 8000
PROCESS_PATH = "/process"

# GROQ API CONFIGURATION
GROQ_API_KEY = "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"

# PEACOCK MULTI-MODEL STRATEGY
PEACOCK_MODEL_STRATEGY = {
    "primary_model": "gemma2-9b-it",
    "speed_model": "llama3-8b-8192",
    "explanation_model": "llama3-8b-8192",
    "json_model": "llama3-8b-8192",
    "fallback_model": "llama-3.1-8b-instant"
}

# SESSION TIMESTAMP GENERATION
def generate_session_timestamp():
    """Generate military time session timestamp: 23-08-1948"""
    now = datetime.datetime.now()
    week = now.isocalendar()[1]
    day = now.day
    hour = now.hour  # Already 24-hour format
    minute = now.minute
    return f"{week}-{day:02d}-{hour:02d}{minute:02d}"

# GLOBAL SESSION COORDINATION
SESSION_TIMESTAMP = generate_session_timestamp()
LOGGING_ENABLED = True

# LOGGING SETUP
def init_logging():
    """Initialize all log files with session timestamp"""
    log_dir = Path("/home/flintx/peacock/logs")
    log_dir.mkdir(exist_ok=True)
    
    global SESSION_TIMESTAMP
    
    log_files = {
        'mcp': log_dir / f"mcplog-{SESSION_TIMESTAMP}.txt",
        'prompt': log_dir / f"promptlog-{SESSION_TIMESTAMP}.txt", 
        'response': log_dir / f"responselog-{SESSION_TIMESTAMP}.txt",
        'xedit': log_dir / f"xeditlog-{SESSION_TIMESTAMP}.txt"
    }
    
    # Create log files
    for log_type, log_file in log_files.items():
        with open(log_file, 'w') as f:
            f.write(f"🦚 PEACOCK {log_type.upper()} LOG - Session: {SESSION_TIMESTAMP}\n")
            f.write(f"Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*60 + "\n\n")
    
    return log_files

def log_to_file(log_type: str, message: str):
    """Log message to specific log file"""
    if not LOGGING_ENABLED:
        return
        
    log_dir = Path("/home/flintx/peacock/logs")
    log_file = log_dir / f"{log_type}log-{SESSION_TIMESTAMP}.txt"
    
    timestamp = datetime.datetime.now().strftime('%H:%M:%S')
    
    try:
        with open(log_file, 'a') as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        print(f"❌ Logging error: {e}")

def cli_progress(stage: str, status: str, message: str, details: str = None):
    """Enhanced CLI progress with logging"""
    icons = {
        "START": "🚀",
        "WORKING": "⚡", 
        "SUCCESS": "✅",
        "ERROR": "❌",
        "INFO": "🔍"
    }
    
    icon = icons.get(status, "🔄")
    
    if details:
        print(f"{icon} {stage}: {message} - {details}")
        log_to_file('mcp', f"{stage} {status}: {message} - {details}")
    else:
        print(f"{icon} {stage}: {message}")
        log_to_file('mcp', f"{stage} {status}: {message}")

class PeacockRequestHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        """Override to use our logging system"""
        log_to_file('mcp', f"HTTP: {format % args}")

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            
            health_data = {
                "status": "healthy",
                "service": "Peacock MCP Server", 
                "session": SESSION_TIMESTAMP,
                "birds_ready": True,
                "xedit_parser": True
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
                
                cli_progress("MCP", "START", f"Processing command: {command}")
                
                # Log the raw request
                request_log = (
                    f"\n{'='*80}\n"
                    f"TIMESTAMP: {datetime.datetime.now().isoformat()}\n"
                    f"COMMAND: {command}\n"
                    f"REQUEST BODY ({len(post_data)} bytes):\n{json.dumps(received_data, indent=2)}"
                    f"\n{'='*80}"
                )
                log_to_file('request', request_log)
                
                # Log the raw prompt
                log_to_file('prompt', f"Processing request: {text_to_process}")
                
                # WIRE #2 FIX: Route to birds instead of old pipeline
                if command == "peacock_full":
                    result = self.process_with_birds(text_to_process)
                else:
                    result = {"success": False, "error": f"Unknown command: {command}"}

                # Enhanced logging of response
                response_json = json.dumps(result, indent=2)
                response_log = (
                    f"\n{'='*80}\n"
                    f"TIMESTAMP: {datetime.datetime.now().isoformat()}\n"
                    f"RESPONSE ({len(response_json)} bytes):\n{response_json}"
                    f"\n{'='*80}"
                )
                log_to_file('response', response_log)

                # Send response
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                
                self.wfile.write(response_json.encode("utf-8"))
                
                cli_progress("MCP", "SUCCESS", f"Response sent: {len(response_json)} bytes")

            except Exception as e:
                error_msg = f"Server error: {str(e)}"
                cli_progress("MCP", "ERROR", error_msg)
                
                # Log the full error with traceback
                import traceback
                error_log = (
                    f"\n{'='*80}\n"
                    f"TIMESTAMP: {datetime.datetime.now().isoformat()}\n"
                    f"ERROR: {error_msg}\n"
                    f"TRACEBACK:\n{traceback.format_exc()}"
                    f"\n{'='*80}"
                )
                log_to_file('error', error_log)
                
                self.send_response(500)
                self.send_header("Content-type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                
                error_response = {"success": False, "error": error_msg}
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

    def process_with_birds(self, user_request: str):
        """
        Run individual bird stages with GROQ
        """
        cli_progress("BIRDS", "START", "Running individual bird stages with GROQ")
        
        try:
            # Initialize birds
            spark = create_spark_analyst()
            falcon = create_falcon_architect()
            eagle = create_eagle_implementer()
            hawk = create_hawk_qa_specialist()
            
            if not all([spark, falcon, eagle, hawk]):
                return {
                    "success": False,
                    "error": "Birds modules not available"
                }
            
            # Step 1: SPARK - Requirements Analysis
            cli_progress("SPARK", "START", "Requirements analysis")
            spark_input = {"user_request": user_request}
            spark_result = spark.analyze_project_request(spark_input)
            
            # Step 2: FALCON - Architecture Design
            cli_progress("FALCON", "START", "Architecture design")
            falcon_input = spark_result
            falcon_result = falcon.design_architecture(falcon_input)
            
            # Step 3: EAGLE - Implementation
            cli_progress("EAGLE", "START", "Implementation")
            eagle_input = falcon_result
            eagle_result = eagle.implement_code(eagle_input)
            
            # Step 4: HAWK - Quality Assurance
            cli_progress("HAWK", "START", "Quality Assurance")
            hawk_input = eagle_result
            # FIXED: Use the correct method name
            hawk_result = hawk.analyze_implementation(hawk_input)
            
            # Step 5: Generate XEdit interface
            cli_progress("XEDIT", "START", "Generating XEdit interface")
            xedit_result = self.generate_xedit_interface(
                hawk_result.get("raw_analysis", ""),
                user_request
            )
            
            # Prepare response with all stage results
            return {
                "success": True,
                "session_timestamp": SESSION_TIMESTAMP,
                "pipeline_results": {
                    "spark": {
                        "text": spark_result.get("raw_analysis", ""),
                        "char_count": len(spark_result.get("raw_analysis", "")),
                        "model": spark_result.get("model", "gemma2-9b-it")
                    },
                    "falcon": {
                        "text": falcon_result.get("raw_design", ""),
                        "char_count": len(falcon_result.get("raw_design", "")),
                        "model": falcon_result.get("model", "gemma2-9b-it")
                    },
                    "eagle": {
                        "text": eagle_result.get("raw_implementation", ""),
                        "char_count": len(eagle_result.get("raw_implementation", "")),
                        "model": eagle_result.get("model", "llama3-8b-8192")
                    },
                    "hawk": {
                        "text": hawk_result.get("raw_analysis", ""),
                        "char_count": len(hawk_result.get("raw_analysis", "")),
                        "model": hawk_result.get("model", "gemma2-9b-it")
                    }
                },
                "xedit_generated": xedit_result.get("success", False),
                "xedit_file": xedit_result.get("file_path", ""),
                "total_response_chars": len(hawk_result.get("raw_analysis", "")),
                "final_response": hawk_result.get("raw_analysis", "")
            }
            
        except Exception as e:
            import traceback
            error_msg = f"Error in process_with_birds: {str(e)}\n{traceback.format_exc()}"
            cli_progress("BIRDS", "ERROR", error_msg)
            return {"success": False, "error": error_msg}

    def generate_xedit_interface(self, llm_response: str, project_name: str):
        """
        WIRE #4: Generate XEdit interface with session coordination
        """
        
        cli_progress("XEDIT", "START", "Generating XEdit interface")
        log_to_file('xedit', f"Starting XEdit generation for session: {SESSION_TIMESTAMP}")
        
        try:
            # Parse the LLM response
            parser = PeacockResponseParser()
            parsed_data = parser.parse_llm_response(llm_response, project_name)
            
            if not parsed_data["parsing_success"]:
                cli_progress("XEDIT", "ERROR", "Response parsing failed", parsed_data.get('error'))
                return {"success": False, "error": f"Parsing failed: {parsed_data.get('error')}"}
            
            log_to_file('xedit', f"Parsing successful: {parsed_data['total_sections']} sections found")
            
            # Generate XEdit paths
            path_generator = XEditPathGenerator()
            xedit_paths = path_generator.generate_xedit_paths(parsed_data["code_files"])
            
            cli_progress("XEDIT", "WORKING", f"Generated {len(xedit_paths)} XEdit paths")
            
            # Generate HTML interface
            interface_generator = XEditInterfaceGenerator()
            html_interface = interface_generator.generate_interface(parsed_data, xedit_paths)
            
            # Save with session coordination
            html_dir = Path("/home/flintx/peacock/html")
            html_dir.mkdir(exist_ok=True)
            
            file_path = html_dir / f"xedit-{SESSION_TIMESTAMP}.html"
            
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_interface)
            
            cli_progress("XEDIT", "SUCCESS", f"XEdit interface saved: {file_path}")
            log_to_file('xedit', f"XEdit file generated: {file_path}")
            
            # Auto-open XEdit interface
            try:
                webbrowser.open(f"file://{file_path}")
                cli_progress("XEDIT", "INFO", "XEdit interface opened in browser")
            except Exception as e:
                cli_progress("XEDIT", "ERROR", "Failed to auto-open XEdit", str(e))
            
            return {
                "success": True,
                "file_path": str(file_path),
                "xedit_paths": xedit_paths,
                "parsed_sections": parsed_data["total_sections"],
                "session_timestamp": SESSION_TIMESTAMP
            }
            
        except Exception as e:
            cli_progress("XEDIT", "ERROR", "XEdit generation failed", str(e))
            log_to_file('xedit', f"ERROR: {str(e)}")
            return {"success": False, "error": str(e)}

def main():
    """Main function with argument parsing"""
    global LOGGING_ENABLED, PORT
    
    parser = argparse.ArgumentParser(description='🦚 Peacock MCP Server - ALL WIRES FIXED')
    parser.add_argument('--log', '-l', action='store_true', help='Enable enhanced logging')
    parser.add_argument('--port', '-p', type=int, default=8000, help='Server port (default: 8000)')
    
    args = parser.parse_args()
    
    LOGGING_ENABLED = args.log
    PORT = args.port
    
    # Initialize logging
    log_files = init_logging()
    
    print("🦚" + "="*60 + "🦚")
    print("    PEACOCK MCP SERVER - ALL 4 WIRES FIXED")
    print("🦚" + "="*60 + "🦚")
    print()
    print(f"🔥 Session: {SESSION_TIMESTAMP} (Military Time)")
    print(f"🐦 Birds: Individual bird stages with GROQ")  
    print(f"🎯 XEdit: Auto-generation with session sync")
    print(f"📝 Logging: {'Enhanced' if LOGGING_ENABLED else 'Basic'}")
    print()
    print(f"📁 Log Files:")
    for log_type, log_file in log_files.items():
        print(f"   📄 {log_type.capitalize()}: {log_file}")
    print()
    print(f"🌐 Server starting on http://{HOST}:{PORT}")
    print()
    print("🚀 WIRE STATUS:")
    print("   ✅ Wire #1: Web UI → MCP (fetch enabled)")
    print("   ✅ Wire #2: MCP → Birds (individual bird stages)")  
    print("   ✅ Wire #3: Birds → LLM (optimized prompts)")
    print("   ✅ Wire #4: LLM → XEdit (session-synced auto-generation)")
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
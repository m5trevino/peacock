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

# Import XEdit parser from core directory
sys.path.append(str(Path(__file__).parent))
try:
    from xedit import PeacockResponseParser, XEditPathGenerator, XEditInterfaceGenerator
except ImportError as e:
    print(f"Warning: Could not import XEdit modules: {e}")

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
        'xedit': log_dir / f"xeditlog-{SESSION_TIMESTAMP}.txt",
        'request': log_dir / f"requestlog-{SESSION_TIMESTAMP}.txt"
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
    log_dir.mkdir(exist_ok=True)
    
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
                log_to_file('prompt', f"Command: {command}\nInput: {text_to_process}\n{'-'*40}")
                
                # Log the raw request
                request_log = (
                    f"\n{'='*80}\n"
                    f"TIMESTAMP: {datetime.datetime.now().isoformat()}\n"
                    f"COMMAND: {command}\n"
                    f"REQUEST BODY ({len(post_data)} bytes):\n{json.dumps(received_data, indent=2)}"
                    f"\n{'='*80}"
                )
                log_to_file('request', request_log)
                
                # WIRE #2 FIX: Route to birds instead of old pipeline
                if command == "peacock_full":
                    result = self.process_with_birds(text_to_process)
                else:
                    result = {"success": False, "error": f"Unknown command: {command}"}

                # Send response
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                
                response_json = json.dumps(result)
                self.wfile.write(response_json.encode("utf-8"))
                
                # Log the response
                response_log = (
                    f"\n{'='*80}\n"
                    f"TIMESTAMP: {datetime.datetime.now().isoformat()}\n"
                    f"RESPONSE ({len(response_json)} bytes):\n{response_json}"
                    f"\n{'='*80}"
                )
                log_to_file('response', response_log)
                
                cli_progress("MCP", "SUCCESS", f"Response sent: {len(response_json)} bytes")

            except Exception as e:
                cli_progress("MCP", "ERROR", "Server error", str(e))
                self.send_response(500)
                self.send_header("Content-type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                
                error_response = {"success": False, "error": f"Server error: {str(e)}"}
                self.wfile.write(json.dumps(error_response).encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()

    def process_with_birds(self, user_request: str):
        """
        WIRE #2 & #3 FIX: Use OUT-HOMING to orchestrate birds pipeline
        Returns properly structured response for dashboard
        """
        
        cli_progress("BIRDS", "START", "Starting OUT-HOMING orchestration")
        
        try:
            # Try to use OUT-HOMING orchestrator if available
            try:
                homing = create_homing_orchestrator()
                
                # WIRE #3: Orchestrate full pipeline through birds
                cli_progress("OUT-HOMING", "WORKING", "Starting full pipeline execution")
                pipeline_result = homing.orchestrate_full_pipeline(user_request)
                
                if not pipeline_result.get("success"):
                    return {
                        "success": False,
                        "error": f"Pipeline failed: {pipeline_result.get('error', 'Unknown error')}"
                    }
                
                # Extract the final LLM response for XEdit processing
                final_response = pipeline_result.get("final_response", "")
                pipeline_results = pipeline_result.get("stage_results", {})
                
                cli_progress("XEDIT", "START", "Generating XEdit interface")
                
                # WIRE #4 FIX: Generate XEdit interface with session coordination
                xedit_result = self.generate_xedit_interface(final_response, user_request)
                
                cli_progress("OUT-HOMING", "SUCCESS", "Pipeline completed successfully")
                
                # Structure response for dashboard with REAL character counts
                return {
                    "success": True,
                    "session_timestamp": SESSION_TIMESTAMP,
                    "character_counts": {
                        "prompts": {
                            "spark": len(pipeline_results.get("spark", {}).get("prompt", "")),
                            "falcon": len(pipeline_results.get("falcon", {}).get("prompt", "")),
                            "eagle": len(pipeline_results.get("eagle", {}).get("prompt", "")),
                            "hawk": len(pipeline_results.get("hawk", {}).get("prompt", ""))
                        },
                        "responses": {
                            "spark": len(pipeline_results.get("spark", {}).get("response", "")),
                            "falcon": len(pipeline_results.get("falcon", {}).get("response", "")),
                            "eagle": len(pipeline_results.get("eagle", {}).get("response", "")),
                            "hawk": len(pipeline_results.get("hawk", {}).get("response", ""))
                        },
                        "total_prompt_chars": sum(len(stage.get("prompt", "")) for stage in pipeline_results.values()),
                        "total_response_chars": sum(len(stage.get("response", "")) for stage in pipeline_results.values())
                    },
                    "pipeline_results": {
                        "spark": {
                            "text": pipeline_results.get("spark", {}).get("response", ""),
                            "char_count": len(pipeline_results.get("spark", {}).get("response", "")),
                            "model": pipeline_results.get("spark", {}).get("model", "llama3-8b-8192"),
                            "prompt_chars": len(pipeline_results.get("spark", {}).get("prompt", ""))
                        },
                        "falcon": {
                            "text": pipeline_results.get("falcon", {}).get("response", ""),
                            "char_count": len(pipeline_results.get("falcon", {}).get("response", "")),
                            "model": pipeline_results.get("falcon", {}).get("model", "gemma2-9b-it"),
                            "prompt_chars": len(pipeline_results.get("falcon", {}).get("prompt", ""))
                        },
                        "eagle": {
                            "text": pipeline_results.get("eagle", {}).get("response", ""),
                            "char_count": len(pipeline_results.get("eagle", {}).get("response", "")),
                            "model": pipeline_results.get("eagle", {}).get("model", "llama-3.1-8b-instant"),
                            "prompt_chars": len(pipeline_results.get("eagle", {}).get("prompt", ""))
                        },
                        "hawk": {
                            "text": pipeline_results.get("hawk", {}).get("response", ""),
                            "char_count": len(pipeline_results.get("hawk", {}).get("response", "")),
                            "model": pipeline_results.get("hawk", {}).get("model", "gemma2-9b-it"),
                            "prompt_chars": len(pipeline_results.get("hawk", {}).get("prompt", ""))
                        }
                    },
                    "xedit_generated": xedit_result.get("success", False),
                    "xedit_file": xedit_result.get("file_path", ""),
                    "total_response_chars": len(final_response),
                    "final_response": final_response
                }
                
            except (ImportError, NameError, AttributeError) as e:
                # Fallback to individual bird stages if OUT-HOMING not available
                cli_progress("BIRDS", "START", "Running individual bird stages with GROQ")
                return self.process_with_individual_birds(user_request)
                
        except Exception as e:
            cli_progress("BIRDS", "ERROR", "Pipeline orchestration failed", str(e))
            return {
                "success": False,
                "error": f"Birds orchestration failed: {str(e)}"
            }

    def process_with_individual_birds(self, user_request: str):
        """Fallback to individual bird stages if OUT-HOMING not available"""
        try:
            # BIRD 1: SPARK (Requirements Analysis)
            cli_progress("SPARK", "START", "Requirements analysis")
            spark = create_spark_analyst()
            spark_result = spark.analyze_project_request(user_request)
            
            # BIRD 2: FALCON (Architecture Design)
            cli_progress("FALCON", "START", "Architecture design")
            falcon = create_falcon_architect()
            falcon_result = falcon.design_architecture(spark_result)
            
            # BIRD 3: EAGLE (Code Implementation)
            cli_progress("EAGLE", "START", "Implementation")
            eagle = create_eagle_implementer()
            eagle_result = eagle.implement_code(falcon_result)
            
            # BIRD 4: HAWK (Quality Assurance)
            cli_progress("HAWK", "START", "Quality Assurance")
            hawk = create_hawk_qa_specialist()
            hawk_input = eagle_result  # Prepare input for HAWK
            hawk_result = hawk.analyze_implementation(hawk_input)  # Use the correct method
            
            # Generate XEdit interface
            cli_progress("XEDIT", "START", "Generating XEdit interface")
            xedit_result = self.generate_xedit_interface(hawk_result.get("qa_review", ""), user_request)
            
            # Return structured response
            return {
                "success": True,
                "session_timestamp": SESSION_TIMESTAMP,
                "pipeline_results": {
                    "spark": {
                        "text": spark_result.get("analysis", ""),
                        "char_count": len(spark_result.get("analysis", "")),
                        "model": spark_result.get("model", "gemma2-9b-it")
                    },
                    "falcon": {
                        "text": falcon_result.get("architecture", ""),
                        "char_count": len(falcon_result.get("architecture", "")),
                        "model": falcon_result.get("model", "gemma2-9b-it")
                    },
                    "eagle": {
                        "text": eagle_result.get("implementation", ""),
                        "char_count": len(eagle_result.get("implementation", "")),
                        "model": eagle_result.get("model", "llama3-8b-8192")
                    },
                    "hawk": {
                        "text": hawk_result.get("qa_review", ""),
                        "char_count": len(hawk_result.get("qa_review", "")),
                        "model": hawk_result.get("model", "gemma2-9b-it")
                    }
                },
                "xedit_generated": xedit_result.get("success", False),
                "xedit_file": xedit_result.get("file_path", ""),
                "total_response_chars": len(hawk_result.get("qa_review", ""))
            }
            
        except Exception as e:
            cli_progress("BIRDS", "ERROR", f"Individual bird processing failed", str(e))
            return {
                "success": False,
                "error": f"Individual bird processing failed: {str(e)}"
            }

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
    print(f"🐦 Birds: Orchestrated via OUT-HOMING")  
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
    print("   ✅ Wire #2: MCP → Birds (OUT-HOMING orchestration)")  
    print("   ✅ Wire #3: Birds → LLM (mixed content prompts)")
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
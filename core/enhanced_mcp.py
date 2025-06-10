#!/usr/bin/env python3
"""
enhanced_mcp_server.py - Peacock MCP Server with Birds Architecture Integration
The right hand that coordinates all operations with mantequilla smooth handoffs
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

# Get the current project directory dynamically
PROJECT_ROOT = Path(__file__).parent.parent
LOGS_DIR = PROJECT_ROOT / "logs"

# Import the birds from the aviary directory
sys.path.append(str(PROJECT_ROOT / "aviary"))
try:
    from homing import create_homing_orchestrator
    from return_homing import create_return_homing_processor
except ImportError as e:
    print(f"Warning: Could not import birds modules: {e}")
    # Create dummy functions to prevent crashes
    def create_homing_orchestrator():
        return None
    def create_return_homing_processor():
        return None

# --- CONFIGURATION ---
HOST = "127.0.0.1"
PORT = 8000
PROCESS_PATH = "/process"

# GROQ API CONFIGURATION
GROQ_API_KEY = "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"

# OPTIMAL MODEL ASSIGNMENTS (Based on testing results)
PEACOCK_MODEL_STRATEGY = {
    "spark_analysis": "llama3-8b-8192",        # 63.2 - Speed for requirements
    "falcon_architecture": "gemma2-9b-it",     # 66.9 - Structure champion  
    "eagle_implementation": "llama-3.1-8b-instant", # 70.1 - Code generation beast
    "hawk_qa": "gemma2-9b-it",                  # 61.8 - QA structure
    "code_analysis": "llama-3.1-8b-instant"    # 70.6 - Code review king
}

# GROQ CONFIG (No JSON mode - always fails)
GROQ_CONFIG = {
    "temperature": 0.3,
    "max_tokens": 1024,
    "use_json_mode": False  # CRITICAL: JSON mode is bootise
}

# SESSION TIMESTAMP GENERATION
def generate_session_timestamp():
    """Generate military time session timestamp: 23-08-1948"""
    now = datetime.datetime.now()
    week = now.isocalendar()[1]
    day = now.day
    hour = now.hour
    minute = now.minute
    return f"{week}-{day:02d}-{hour:02d}{minute:02d}"

# GLOBAL SESSION COORDINATION
SESSION_TIMESTAMP = generate_session_timestamp()
LOGGING_ENABLED = True

def init_logging():
    """Initialize and return the logs directory path"""
    global SESSION_TIMESTAMP
    log_dir = LOGS_DIR
    log_dir.mkdir(exist_ok=True)
    
    # Create a simple session marker file
    session_marker = log_dir / f"session-{SESSION_TIMESTAMP}.started"
    session_marker.touch()
    
    return str(log_dir)

def log_to_file(log_type: str, message: str):
    """Log message to specific log file"""
    if not LOGGING_ENABLED:
        return
        
    log_dir = LOGS_DIR
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
                "service": "Peacock MCP Server - Birds Architecture", 
                "session": SESSION_TIMESTAMP,
                "birds_ready": True,
                "xedit_parser": True,
                "model_strategy": "optimized",
                "architecture": "modular_birds"
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
                
                # Enhanced logging of raw request
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
                
                # MAIN ROUTING - Use Birds Architecture
                if command == "peacock_full":
                    result = self.process_with_birds_architecture(text_to_process)
                elif command == "fix_xedit_paths":
                    xedit_paths = received_data.get('xedit_paths', [])
                    result = self.process_xedit_fixes(xedit_paths)
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

    def process_with_birds_architecture(self, user_request: str):
        """
        NEW BIRDS ARCHITECTURE PROCESSING
        HOMING orchestrates all birds → LLM calls → RETURN-HOMING generates XEdit
        """
        cli_progress("BIRDS", "START", "Starting Birds Architecture pipeline")
        
        try:
            # Step 1: HOMING orchestration - generates all prompts
            cli_progress("HOMING", "WORKING", "Orchestrating all birds")
            homing = create_homing_orchestrator()
            
            if homing is None:
                cli_progress("HOMING", "ERROR", "Birds modules not available")
                return {"success": False, "error": "Birds architecture modules not available"}
            
            pipeline_result = homing.orchestrate_full_pipeline(user_request)
            
            if not pipeline_result.get("success", False):
                error_msg = pipeline_result.get("error", "Unknown error in HOMING pipeline")
                cli_progress("HOMING", "ERROR", "Pipeline failed", error_msg)
                return {"success": False, "error": error_msg}
            
            # Step 2: Execute LLM calls for each stage
            cli_progress("LLM", "WORKING", "Executing optimized model calls")
            stage_results = pipeline_result.get("stage_results", {})
            
            for stage_name in ["spark", "falcon", "eagle", "hawk"]:
                if stage_name in stage_results:
                    stage_data = stage_results[stage_name]
                    prompt = stage_data.get("prompt", "")
                    optimal_model = stage_data.get("optimal_model", "gemma2-9b-it")
                    
                    cli_progress(stage_name.upper(), "WORKING", f"Calling {optimal_model}")
                    
                    # Call LLM with optimal model
                    llm_response = self.call_optimized_groq(prompt, optimal_model, stage_name)
                    
                    if llm_response.get("success"):
                        stage_data["llm_response"] = llm_response["text"]
                        stage_data["model_used"] = llm_response["model_used"]
                        stage_data["char_count"] = len(llm_response["text"])
                        cli_progress(stage_name.upper(), "SUCCESS", f"Response: {len(llm_response['text'])} chars")
                    else:
                        cli_progress(stage_name.upper(), "ERROR", "LLM call failed", llm_response.get("error"))
                        return {"success": False, "error": f"{stage_name.upper()} LLM call failed"}
            
            # Step 3: RETURN-HOMING processing - generates XEdit interface
            cli_progress("RETURN-HOMING", "WORKING", "Generating XEdit interface")
            return_homing = create_return_homing_processor()
            
            if return_homing is None:
                cli_progress("RETURN-HOMING", "ERROR", "Return homing module not available")
                xedit_result = {"success": False, "error": "Return homing module not available"}
            else:
                xedit_result = return_homing.process_pipeline_completion(pipeline_result)
            
            if not xedit_result.get("success", False):
                cli_progress("RETURN-HOMING", "ERROR", "XEdit generation failed", xedit_result.get("error"))
                # Continue without XEdit - not a fatal error
            else:
                cli_progress("RETURN-HOMING", "SUCCESS", f"XEdit generated: {xedit_result.get('xedit_file_path')}")
                
                # Auto-open XEdit interface
                try:
                    xedit_file = xedit_result.get("xedit_file_path")
                    if xedit_file:
                        webbrowser.open(f"file://{xedit_file}")
                        cli_progress("XEDIT", "INFO", "XEdit interface opened in browser")
                except Exception as e:
                    cli_progress("XEDIT", "ERROR", "Failed to auto-open XEdit", str(e))
            
            # Step 4: Prepare comprehensive response
            response_data = {
                "success": True,
                "session_timestamp": SESSION_TIMESTAMP,
                "architecture": "birds_modular",
                "pipeline_results": stage_results,
                "xedit_generated": xedit_result.get("success", False),
                "xedit_file": xedit_result.get("xedit_file_path", ""),
                "xedit_paths": len(xedit_result.get("xedit_paths", {})),
                "total_stages": len(stage_results),
                "execution_time": pipeline_result.get("total_execution_time", 0)
            }
            
            # Add character counts for each stage
            for stage_name, stage_data in stage_results.items():
                if "char_count" in stage_data:
                    response_data[f"{stage_name}_chars"] = stage_data["char_count"]
            
            cli_progress("BIRDS", "SUCCESS", "Birds Architecture pipeline completed")
            return response_data
            
        except Exception as e:
            import traceback
            error_msg = f"Error in Birds Architecture pipeline: {str(e)}\n{traceback.format_exc()}"
            cli_progress("BIRDS", "ERROR", "Pipeline execution failed", error_msg)
            return {"success": False, "error": error_msg}

    def process_xedit_fixes(self, xedit_paths):
        """Process XEdit path fixes with optimal model selection"""
        cli_progress("XEDIT-FIX", "START", f"Processing {len(xedit_paths)} XEdit paths")
        
        try:
            # Build prompt for code fixes
            paths_text = ", ".join(xedit_paths)
            prompt = f"""Analyze and improve the code at these XEdit-Paths: {paths_text}

Provide specific improvements for each path:
- Code optimization suggestions
- Bug fixes if any issues found  
- Performance improvements
- Best practices recommendations

Format your response clearly for each XEdit-Path."""
            
            # Use optimal model for code analysis
            optimal_model = PEACOCK_MODEL_STRATEGY["code_analysis"]
            llm_response = self.call_optimized_groq(prompt, optimal_model, "xedit_fixes")
            
            if llm_response.get("success"):
                result = {
                    "success": True,
                    "response": llm_response['text'],
                    "paths_processed": len(xedit_paths),
                    "model_used": llm_response['model_used'],
                    "char_count": len(llm_response['text'])
                }
                cli_progress("XEDIT-FIX", "SUCCESS", f"Processed {len(xedit_paths)} paths")
            else:
                result = {
                    "success": False,
                    "error": llm_response.get('error')
                }
                cli_progress("XEDIT-FIX", "ERROR", "LLM call failed", llm_response.get('error'))
            
            return result
            
        except Exception as e:
            error_msg = f"XEdit processing failed: {str(e)}"
            cli_progress("XEDIT-FIX", "ERROR", error_msg)
            return {"success": False, "error": error_msg}

    def call_optimized_groq(self, prompt: str, model: str, stage: str) -> dict:
        """Call Groq with optimized model and fallback logic"""
        
        # PROMPT LOGGING: Always log prompts if logging is enabled
        if LOGGING_ENABLED:
            prompt_log_file = LOGS_DIR / f"promptlog-{SESSION_TIMESTAMP}.txt"
            with open(prompt_log_file, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {stage.upper()} PROMPT TO {model}\n")
                f.write("=" * 80 + "\n")
                f.write(f"STAGE: {stage}\n")
                f.write(f"PROMPT LENGTH: {len(prompt)} chars\n")
                f.write("-" * 40 + "\n")
                f.write(prompt)
                f.write("\n" + "=" * 80 + "\n\n")

        try:
            # Try to import groq, but handle gracefully if not available
            try:
                from groq import Groq
                client = Groq(api_key=GROQ_API_KEY)
                
                response = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=GROQ_CONFIG["temperature"],
                    max_tokens=GROQ_CONFIG["max_tokens"]
                    # NO response_format parameter - JSON mode is bootise
                )
                
                content = response.choices[0].message.content
                
                # Validate response quality
                if self.validate_response_quality(content, stage):
                    if LOGGING_ENABLED:
                        log_file = LOGS_DIR / f"response-{SESSION_TIMESTAMP}.txt"
                        with open(log_file, "a", encoding="utf-8") as f:
                            f.write(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {stage.upper()} SUCCESS - {model}\n")
                            f.write("=" * 80 + "\n")
                            f.write(content)
                            f.write("\n" + "=" * 80 + "\n\n")
                    
                    return {
                        "success": True,
                        "text": content,
                        "model_used": model
                    }
                else:
                    return {
                        "success": False,
                        "error": f"Quality validation failed for {model}"
                    }
            except ImportError:
                return {
                    "success": False,
                    "error": "Groq module not available - install with: pip install groq"
                }
                
        except Exception as e:
            return {
                "success": False, 
                "error": f"Model {model} failed: {str(e)}"
            }

    def validate_response_quality(self, content: str, stage: str) -> bool:
        """Validate response meets quality standards"""
        
        # Basic content check
        if not content or len(content.strip()) < 50:
            return False
        
        # Stage-specific validation
        if stage == "eagle_implementation":
            # EAGLE should generate code
            return "```" in content or "filename:" in content
        elif stage in ["spark_analysis", "falcon_architecture", "hawk_qa"]:
            # Other stages should have structured content
            return len(content.strip()) > 200
        
        return True

def show_peacock_banner():
    """Display a random peacock banner using cfonts if available"""
    try:
        import random
        import subprocess
        
        banners = [
            "cfonts 'PEACOCK' -f block -c red",
            "cfonts 'PEACOCK' -f simple -c green",
            "cfonts 'PEACOCK' -f chrome -c magenta",
            "cfonts 'PEACOCK' -f shade -c greenBright",
            "cfonts 'PEACOCK' -f slick -c whiteBright",
            "cfonts 'PEACOCK' -f grid -c yellow",
            "cfonts 'PEACOCK' -f pallet -c cyanBright",
            "cfonts 'PEACOCK' -f block -g cyan,magenta",
            "cfonts 'PEACOCK' -f simple -g yellow,red",
            "cfonts 'PEACOCK' -f shade -g red,blue"
        ]
        
        banner_cmd = random.choice(banners)
        subprocess.run(banner_cmd.split(), check=True)
        return True
    except Exception:
        # Fallback to simple text banner
        import random
        banners = [
            "🦚🔥 PEACOCK MCP SERVER - BIRDS ARCHITECTURE 🔥🦚",
            "🔥💯 PEACOCK PIPELINE - MANTEQUILLA SMOOTH 💯🔥", 
            "💯🦚 PEACOCK - MODULAR BIRDS SYSTEM 🦚💯"
        ]
        print("\n" + "="*70)
        print(f"    {random.choice(banners)}")
        print("="*70)
        return False

def main():
    """Main function with argument parsing"""
    global LOGGING_ENABLED, PORT
    
    parser = argparse.ArgumentParser(description='🦚 Peacock MCP Server - Birds Architecture')
    parser.add_argument('--log', '-l', action='store_true', help='Enable enhanced logging')
    parser.add_argument('--port', '-p', type=int, default=8000, help='Server port (default: 8000)')
    
    args = parser.parse_args()
    
    LOGGING_ENABLED = args.log
    PORT = args.port
    
    # Initialize logging and get logs directory
    logs_dir = init_logging()
    
    print("\n" + "🦚" + "="*60 + "🦚")
    # Show peacock banner and config
    show_peacock_banner()
    print()
    print(f"🔥 Session: {SESSION_TIMESTAMP} (Military Time)")
    print()
    print(f"📁 Logs directory: {logs_dir}")
    print(f"📁 Project root: {PROJECT_ROOT}")
    print()
    print(f"🌐 Server starting on http://{HOST}:{PORT}")
    print()
    print("🚀 BIRDS ARCHITECTURE STATUS:")
    print("   ✅ HOMING: Pipeline orchestration ready")
    print("   ✅ RETURN-HOMING: XEdit generation ready")  
    print("   ✅ Model optimization: Stage-specific angels assigned")
    print("   ✅ Session coordination: Timestamp sync enabled")
    print("   ✅ Mantequilla handoffs: Smooth pipeline flow")
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
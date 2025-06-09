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
from out_homing import create_homing_orchestrator
from in_homing import create_return_homing_processor
from spark import create_spark_analyst
from falcon import create_falcon_architect
from eagle import create_eagle_implementer
from hawk import create_hawk_qa_specialist

# Import XEdit parser from core directory
sys.path.append(str(Path(__file__).parent))
from xedit import PeacockResponseParser, XEditPathGenerator, XEditInterfaceGenerator

# --- CONFIGURATION ---
HOST = "127.0.0.1"
PORT = 8000
PROCESS_PATH = "/process"

# Model configuration
PEACOCK_MODEL_STRATEGY = {
    "primary_model": "gemma2-9b-it",        # Best overall mixed content
    "speed_model": "llama3-8b-8192",        # When speed is critical  
    "explanation_model": "llama3-8b-8192",  # When detailed explanations needed
    "json_model": "llama3-8b-8192",         # Most reliable JSON parsing
    "fallback_model": "llama-3.1-8b-instant"
}

# Stage-specific model assignments
PEACOCK_STAGE_MODELS = {
    "spark_analysis": "gemma2-9b-it",      # Structure + requirements
    "falcon_architecture": "gemma2-9b-it", # Won architecture tests
    "eagle_implementation": "llama3-8b-8192", # Speed + explanations  
    "hawk_qa": "gemma2-9b-it",             # Structure + organization
    "code_analysis": "llama3-8b-8192"      # Speed + perfect JSON
}

# Groq API configuration
GROQ_CONFIG = {
    "temperature": 0.3,  # Optimized for consistency
    "max_tokens": 1024,  # Sufficient for most tasks
    "use_json_mode": False,  # CRITICAL: Don't use JSON mode
    "prompt_style": "request_json_in_prompt"  # Request JSON in prompt text
}

# GROQ API CONFIGURATION
GROQ_API_KEY = "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"

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

# PEACOCK BANNER STYLES
PEACOCK_BANNERS = [
    # Block font with red
    "cfonts 'PEACOCK' -f block -c red",
    # Simple font with green  
    "cfonts 'PEACOCK' -f simple -c green",
    # Chrome style with magenta
    "cfonts 'PEACOCK' -f chrome -c magenta",
    # Shade style with bright green
    "cfonts 'PEACOCK' -f shade -c greenBright",
    # Slick style with white
    "cfonts 'PEACOCK' -f slick -c whiteBright",
    # Grid style with yellow
    "cfonts 'PEACOCK' -f grid -c yellow",
    # Pallet style with cyan
    "cfonts 'PEACOCK' -f pallet -c cyanBright",
    # Cyan to Magenta gradient
    "cfonts 'PEACOCK' -f block -g cyan,magenta",
    # Yellow to Red gradient
    "cfonts 'PEACOCK' -f simple -g yellow,red",
    # Red to Blue gradient  
    "cfonts 'PEACOCK' -f shade -g red,blue",
    # Red to Yellow gradient
    "cfonts 'PEACOCK' -f slick -g red,yellow",
    # Magenta to Yellow gradient
    "cfonts 'PEACOCK' -f grid -g magenta,yellow",
    # Green to Cyan gradient
    "cfonts 'PEACOCK' -f pallet -g green,cyan",
    # Red to Blue gradient (tiny font)
    "cfonts 'PEACOCK' -f tiny -g red,blue",
    # Red to Blue transition
    "cfonts 'PEACOCK' -f block -t red,blue",
    # Yellow to Red transition
    "cfonts 'PEACOCK' -f simple -t yellow,red",
    # Green to Red transition
    "cfonts 'PEACOCK' -f shade -t green,red"
]

def init_logging():
    """Initialize and return the logs directory path"""
    global SESSION_TIMESTAMP
    log_dir = Path("/home/flintx/peacock/logs")
    log_dir.mkdir(exist_ok=True)
    
    # Create a simple session marker file
    session_marker = log_dir / f"session-{SESSION_TIMESTAMP}.started"
    session_marker.touch()
    
    return str(log_dir)  # Return just the logs directory path

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

def validate_response_quality(content: str, command: str) -> bool:
    """Validate response meets quality standards"""
    
    # Check for basic content
    if not content or len(content.strip()) < 50:
        return False
    
    # For structured commands, require JSON
    structured_commands = ["spark_analysis", "falcon_architecture", 
                         "eagle_implementation", "hawk_qa"]
    
    if command in structured_commands:
        # Must contain valid JSON
        json_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
        json_matches = re.findall(json_pattern, content, re.DOTALL)
        
        for match in json_matches:
            try:
                json.loads(match)
                return True
            except:
                continue
        return False
    
    return True

def parse_mixed_response(response_text: str) -> dict:
    """Parse responses containing multiple content types"""
    
    parsed_data = {
        "explanation": "",
        "structured_data": {},
        "code_blocks": [],
        "success": False
    }
    
    try:
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
    except Exception as e:
        print(f"Error parsing response: {e}")
    
    return parsed_data

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

    def select_optimal_model(self, command: str, priority: str = "balanced") -> str:
        """Select best model based on task and priority"""
        if priority == "speed":
            return PEACOCK_MODEL_STRATEGY["speed_model"]
        elif priority == "structure":
            return PEACOCK_MODEL_STRATEGY["primary_model"]
        elif priority == "explanation":
            return PEACOCK_MODEL_STRATEGY["explanation_model"]
        
        # Default to stage-specific model or primary model
        return PEACOCK_STAGE_MODELS.get(command, PEACOCK_MODEL_STRATEGY["primary_model"])
    
    def call_optimized_groq(self, prompt: str, stage: str) -> dict:
        """Call Groq with optimized model selection and fallback"""
        import requests
        
        primary_model = self.select_optimal_model(stage)
        fallback_models = [
            PEACOCK_MODEL_STRATEGY["json_model"],
            PEACOCK_MODEL_STRATEGY["fallback_model"]
        ]
        
        # Remove primary model from fallbacks if present
        fallback_models = [m for m in fallback_models if m != primary_model]
        models_to_try = [primary_model] + fallback_models
        
        for model in models_to_try:
            try:
                headers = {
                    "Authorization": f"Bearer {GROQ_API_KEY}",
                    "Content-Type": "application/json"
                }
                
                data = {
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": GROQ_CONFIG["temperature"],
                    "max_tokens": GROQ_CONFIG["max_tokens"]
                    # Note: No response_format parameter as per guide
                }
                
                response = requests.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers=headers,
                    json=data,
                    timeout=30
                )
                response.raise_for_status()
                
                content = response.json()['choices'][0]['message']['content']
                
                # Validate response quality
                if validate_response_quality(content, stage):
                    return {
                        "success": True,
                        "text": content,
                        "model_used": model,
                        "parsed": parse_mixed_response(content)
                    }
                
                print(f"Model {model} produced invalid response, trying next...")
                
            except Exception as e:
                print(f"Model {model} failed: {e}")
                continue
        
        return {
            "success": False,
            "error": "All models failed to produce valid response",
            "models_tried": models_to_try
        }

    def process_with_birds(self, user_request: str):
        """
        Use OUT-HOMING orchestrator to run the full bird pipeline
        """
        cli_progress("BIRDS", "START", "Starting OUT-HOMING orchestration")
        
        try:
            # Initialize OUT-HOMING orchestrator
            homing = create_homing_orchestrator()
            
            # Run the full pipeline
            cli_progress("OUT-HOMING", "WORKING", "Starting full pipeline execution")
            result = homing.orchestrate_full_pipeline(user_request)
            
            if not result.get("success", False):
                error_msg = result.get("error", "Unknown error in OUT-HOMING pipeline")
                cli_progress("OUT-HOMING", "ERROR", "Pipeline failed", error_msg)
                return {"success": False, "error": error_msg}
            
            # Get stage results and final response
            stage_results = result.get("stage_results", {})
            final_response = result.get("final_response", "")
            
            # Calculate character counts
            character_counts = {
                "prompts": {},
                "responses": {},
                "total_prompt_chars": 0,
                "total_response_chars": 0
            }
            
            for stage in ["spark", "falcon", "eagle", "hawk"]:
                if stage in stage_results:
                    prompt_len = len(stage_results[stage].get("prompt", ""))
                    resp_len = len(stage_results[stage].get("response", ""))
                    
                    character_counts["prompts"][stage] = prompt_len
                    character_counts["responses"][stage] = resp_len
                    character_counts["total_prompt_chars"] += prompt_len
                    character_counts["total_response_chars"] += resp_len
            
            # Print character count summary
            print("\n📊 CHARACTER COUNT SUMMARY")
            print("=" * 25)
            print("STAGE          PROMPT CHARS  RESPONSE CHARS  TOTAL CHARS")
            print("-" * 60)
            
            for stage in ["spark", "falcon", "eagle", "hawk"]:
                prompt_len = character_counts["prompts"].get(stage, 0)
                resp_len = character_counts["responses"].get(stage, 0)
                total = prompt_len + resp_len
                print(f"{stage.upper():<14} {prompt_len:>11,}  {resp_len:>14,}  {total:>11,}")
            
            print("-" * 60)
            print(f"{'TOTAL':<14} {character_counts['total_prompt_chars']:>11,}  {character_counts['total_response_chars']:>14,}  {character_counts['total_prompt_chars'] + character_counts['total_response_chars']:>11,}")
            print("=" * 50 + "\n")
            
            # Generate XEdit interface with the final response
            xedit_result = self.generate_xedit_interface(
                final_response, 
                user_request, 
                stage_results
            )
            
            # Prepare response with all stage results and character counts
            response_data = {
                "success": True,
                "session_timestamp": SESSION_TIMESTAMP,
                "character_counts": character_counts,
                "pipeline_results": {},
                "xedit_generated": xedit_result.get("success", False),
                "xedit_file": xedit_result.get("file_path", ""),
                "total_response_chars": len(final_response),
                "final_response": final_response
            }
            
            # Add stage results to response
            for stage in ["spark", "falcon", "eagle", "hawk"]:
                if stage in stage_results:
                    response_data["pipeline_results"][stage] = {
                        "text": stage_results[stage].get("response", ""),
                        "char_count": len(stage_results[stage].get("response", "")),
                        "model": stage_results[stage].get("model", "unknown"),
                        "prompt_chars": len(stage_results[stage].get("prompt", ""))
                    }
            
            cli_progress("OUT-HOMING", "SUCCESS", "Pipeline completed successfully")
            return response_data
            
        except Exception as e:
            import traceback
            error_msg = f"Error in OUT-HOMING pipeline: {str(e)}\n{traceback.format_exc()}"
            cli_progress("OUT-HOMING", "ERROR", "Pipeline execution failed", error_msg)
            return {"success": False, "error": error_msg}

    def generate_xedit_interface(self, llm_response: str, project_name: str, pipeline_results: dict):
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

def show_peacock_banner():
    """Display a random peacock banner using cfonts if available"""
    try:
        import random
        import subprocess
        
        # Try to use cfonts if available
        banner_cmd = random.choice(PEACOCK_BANNERS)
        subprocess.run(banner_cmd.split(), check=True)
        return True
    except Exception:
        # Fallback to simple text banner
        banners = [
            "🦚🔥 PEACOCK MCP SERVER - FIRE EDITION 🔥🦚",
            "🔥💯 PEACOCK PIPELINE - ALL WIRES CONNECTED 💯🔥", 
            "💯🦚 PEACOCK - MANTEQUILLA SMOOTH OPERATION 🦚💯"
        ]
        print("\n" + "="*70)
        print(f"    {random.choice(banners)}")
        print("="*70)
        return False

def display_config():
    """Display current configuration with peacock banner"""
    try:
        # Show peacock banner
        show_peacock_banner()
        
        # Get terminal width for centering
        try:
            cols = int(subprocess.check_output(['tput', 'cols']))
        except:
            cols = 80
            
    except Exception as e:
        print("⚠️  Could not display peacock banner:", str(e))

def main():
    """Main function with argument parsing"""
    global LOGGING_ENABLED, PORT
    
    parser = argparse.ArgumentParser(description='🦚 Peacock MCP Server - ALL WIRES FIXED')
    parser.add_argument('--log', '-l', action='store_true', help='Enable enhanced logging')
    parser.add_argument('--port', '-p', type=int, default=8000, help='Server port (default: 8000)')
    
    args = parser.parse_args()
    
    LOGGING_ENABLED = args.log
    PORT = args.port
    
    # Initialize logging and get logs directory
    logs_dir = init_logging()
    
    print("\n" + "🦚" + "="*60 + "🦚")
    # Show peacock banner and config
    display_config()
    print()
    print(f"🔥 Session: {SESSION_TIMESTAMP} (Military Time)")
    print()
    print(f"📁 Logs directory: {logs_dir}")
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

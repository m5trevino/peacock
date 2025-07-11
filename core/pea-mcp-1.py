#!/usr/bin/env python3
"""
🦚 PEACOCK MCP SERVER - CYBERPUNK EDITION (UNIFORM SICK BORDERS)
Real API integration with multiple keys, proxy support, and SICK terminal styling
"""

import os
from dotenv import load_dotenv
load_dotenv()

import http.server
import socketserver
import json
import sys
import argparse
import datetime
import re
import random
import subprocess
import webbrowser
import time
import requests
from pathlib import Path

# Add aviary to path for bird imports
sys.path.insert(0, str(Path(__file__).parent.parent / "aviary"))
from out_homing import create_homing_orchestrator
from enhanced_xedit_parser import create_enhanced_xedit_parser
from in_homing import InHomingProcessor

# --- CYBERPUNK CONFIGURATION ---
HOST = "127.0.0.1"
PORT = 8000
PROCESS_PATH = "/process"
DEPLOY_PATH = "/deploy" # New endpoint for deployment
LOG_INPUT_PATH = "/log_input" # New endpoint for input logging
LOGGING_ENABLED = False

# CHAMPION MODEL STRATEGY (Championship Configuration)
PEACOCK_MODEL_STRATEGY = {
    "scout_model": "meta-llama/llama-4-scout-17b-16e-instruct",      # Spark/Falcon
    "maverick_model": "meta-llama/llama-4-maverick-17b-128e-instruct", # Eagle/Hawk
    "final_model": "qwen/qwen3-32b",                                 # Final generation
    "fallback_model": "llama-3.3-70b-versatile"                     # Emergency fallback
}

# API KEY ROTATION CONFIGURATION
GROQ_API_KEYS = [
    os.getenv("GROQ_API_KEY"),
    os.getenv("GROQ_API_KEY_1"),
    os.getenv("GROQ_API_KEY_3"),
    os.getenv("GROQ_API_KEY_4"),
    os.getenv("GROQ_API_KEY_6"),
    os.getenv("GROQ_API_KEY_7"),
    os.getenv("GROQ_API_KEY_8"),
    os.getenv("GROQ_API_KEY_9"),
    os.getenv("GROQ_API_KEY_10")
]

# Filter out None values and track current key
GROQ_API_KEYS = [key for key in GROQ_API_KEYS if key]
CURRENT_KEY_INDEX = 0

# STANDARDIZED MODEL PARAMETERS (per championship guide)
STANDARD_MODEL_PARAMS = {
    "temperature": 0.7,
    "top_p": 0.8,
    "top_k": 20,
    "min_p": 0,
    "max_tokens": 4096
}

# SESSION MANAGEMENT
def generate_session_timestamp():
    """Generate session timestamp in week-day-hourminute format"""
    now = datetime.datetime.now()
    week = now.isocalendar()[1]
    day = now.day
    hour_minute = now.strftime("%H%M")
    return f"{week}-{day}-{hour_minute}"

SESSION_TIMESTAMP = generate_session_timestamp()

# CYBERPUNK STYLING SYSTEM
class CyberStyle:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    # CYBERPUNK COLORS
    NEON_GREEN = '\033[92m'
    NEON_CYAN = '\033[96m'
    NEON_PURPLE = '\033[95m'
    NEON_YELLOW = '\033[93m'
    NEON_RED = '\033[91m'
    MATRIX_GREEN = '\033[32m'
    ELECTRIC_BLUE = '\033[94m'
    HOT_PINK = '\033[35m'

# CYBERPUNK CFONTS ARSENAL
CYBERPUNK_CFONTS = [
    # Gradient combinations (the sickest ones)
    "cfonts 'PEACOCK' -f pallet -g yellow,red",
    "cfonts 'PEACOCK' -f slick -g green,cyan", 
    "cfonts 'PEACOCK' -f shade -g red,magenta",
    "cfonts 'PEACOCK' -f simple3d -g cyan,magenta",
    "cfonts 'PEACOCK' -f simple -g blue,magenta",
    "cfonts 'PEACOCK' -f shade -g green,red",
    "cfonts 'PEACOCK' -f block -g red,blue",
    "cfonts 'PEACOCK' -f grid -g red,blue",
    "cfonts 'PEACOCK' -f slick -g yellow,red",
    "cfonts 'PEACOCK' -f shade -g green,cyan",
    "cfonts 'PEACOCK' -f chrome -g green,cyan",
    "cfonts 'PEACOCK' -f simple -g green,cyan",
    "cfonts 'PEACOCK' -f block -g red,yellow",
    "cfonts 'PEACOCK' -f block -g cyan,magenta",
    "cfonts 'PEACOCK' -f simple -g yellow,red",
    "cfonts 'PEACOCK' -f shade -g red,blue",
    "cfonts 'PEACOCK' -f slick -g red,yellow",
    "cfonts 'PEACOCK' -f grid -g magenta,yellow",
    "cfonts 'PEACOCK' -f pallet -g green,cyan",
    "cfonts 'PEACOCK' -f tiny -g red,blue",
    "cfonts 'PEACOCK' -f chrome -g red,yellow",
    "cfonts 'PEACOCK' -f simple3d -g blue,red",
    "cfonts 'PEACOCK' -f pallet -g magenta,cyan",
    "cfonts 'PEACOCK' -f grid -g green,yellow",
    "cfonts 'PEACOCK' -f slick -g blue,magenta",
    "cfonts 'PEACOCK' -f shade -g cyan,red",
    "cfonts 'PEACOCK' -f block -g green,blue",
    "cfonts 'PEACOCK' -f simple -g red,cyan",
    "cfonts 'PEACOCK' -f chrome -g yellow,magenta",
    "cfonts 'PEACOCK' -f tiny -g green,red"
]

def show_cyberpunk_ascii():
    """Show the sick ASCII art section"""
    chess_border = f"{CyberStyle.NEON_CYAN}♞▀▄▀▄♝▀▄ ♞▀▄▀▄♝▀▄‍‌♞▀▄▀▄♝▀▄ ♞▀▄▀▄♝▀▄‍‌♞▀▄▀▄♝▀▄{CyberStyle.RESET}"
    
    print(f"{chess_border}")
    print("░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░")
    print("░░█░░░███░░████░░██░░████░░██░░████░█░░█░░█░░")
    print("░░ ░░░█  █░█   ░█  █░█   ░█  █░█   ░█░░█░░ ░░")
    print("░░░░░░███ ░███░░████░█░░░░█░░█░█░░░░███ ░░░░░")
    print("░░░░░░█  ░░█  ░░█  █░█░░░░█░░█░█░░░░█  █░░░░░")
    print("░░░░░░█░░░░████░█░░█░████░ ██ ░████░█░░█░░░░░")
    print("░░░░░░ ░░░░    ░ ░░ ░    ░░  ░░    ░ ░░ ░░░░░")
    print("░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░")
    print(f"{chess_border}\n")

def show_uniform_box(message: str, icon: str = ""):
    """Show uniform cyberpunk box"""
    print(f"╔═══════════════════════════════════════════════╗")
    print(f"{icon} {message}")
    print(f"╚═══════════════════════════════════════════════╝")

def show_init_box():
    """Show initialization box"""
    print(f"╔════════════════════════════════════╗")
    print(f"⚡ Initializing Peacock MCP Server...")
    print(f"╚════════════════════════════════════╝")

def show_config_box():
    """Show configuration box"""
    print(f"╔═════════════════════════════════════════════════════════════╗")
    print(f"   ♔ Scout Model: {PEACOCK_MODEL_STRATEGY['scout_model']}")
    print(f"   ♖ Maverick Model: {PEACOCK_MODEL_STRATEGY['maverick_model']}")
    print(f"   📊 Logging: {'Enabled' if LOGGING_ENABLED else 'Disabled'}")
    print(f"   👉 Session: {SESSION_TIMESTAMP}")
    print(f"╚═════════════════════════════════════════════════════════════╝")

def show_stage_box(stage_name: str, message: str, icon: str = ""):
    """Show stage progress box"""
    print(f"┌──═━┈━═─────────┐")
    print(f"{icon} {stage_name}: {message}")
    print(f"└──═━┈━═─────────┘")

def show_result_box(stage_name: str, message: str, icon: str = ""):
    """Show result box"""
    print(f"┌──═━┈━═──┐")
    print(f"{icon} {stage_name} - {message}")
    print(f"└──═━┈━═──┘")

def show_character_count_summary(stage_results: dict):
    """Show character count summary with sick formatting"""
    print(f"\nSTAGE CHARACTER COUNTS:")
    print(f"┍━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━»•» 🌺 «•«━━━━┑")
    
    stage_icons = {"spark": "⚡", "falcon": "👉", "eagle": "🐦", "hawk": "♔"}
    
    for stage_name, stage_data in stage_results.items():
        char_count = stage_data.get("char_count", stage_data.get("chars", 0))
        model = stage_data.get("model", "unknown")
        icon = stage_icons.get(stage_name.lower(), "🔥")
        print(f"{icon}  {stage_name.upper():7}: {char_count:4} chars {model}")
    
    print(f"┕━━━━━»•» 🌺 «•«━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┙")

def log_to_file(log_type: str, content: str, force_log: bool = False):
    """Enhanced logging with cyberpunk timestamps"""
    global LOGGING_ENABLED
    if not LOGGING_ENABLED and not force_log:
        return
    
    timestamp = datetime.datetime.now().isoformat()
    log_dir = Path("/home/flintx/peacock/core/logs")
    
    if not log_dir.exists():
        log_dir.mkdir(parents=True, exist_ok=True)
    
    log_file = log_dir / f"{log_type}log-{SESSION_TIMESTAMP}.txt"
    
    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {content}\n")
    except Exception as e:
        print(f"{CyberStyle.NEON_RED}❌ Logging error: {e}{CyberStyle.RESET}")

# HTTP SERVER WITH CYBERPUNK STYLING
class CyberpunkRequestHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        """Custom logging with cyberpunk colors"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"┏━━━━━━━━━━━━━━━━━━━━━•❅•°•❈•°•❅•━━━━━━━━━━━━━━━━━━━━┓")
        print(f"✅ [{timestamp}] {format % args}")
        print(f"┗━━━━━━━━━━━━━━━━━━━━━•❅•°•❈•°•❅•━━━━━━━━━━━━━━━━━━━━┛")
        log_to_file('mcp', f"HTTP: {format % args}")

    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        """Handle GET requests - health check and file serving"""
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            
            health_data = {
                "status": "healthy",
                "service": "Peacock MCP Server - Cyberpunk Edition", 
                "session": SESSION_TIMESTAMP,
                "birds_ready": True,
                "cyberpunk_mode": True
            }
            self.wfile.write(json.dumps(health_data).encode("utf-8"))
        elif self.path.startswith("/xedit/"):
            # Serve XEdit HTML files
            filename = self.path[7:]  # Remove '/xedit/' prefix
            filepath = Path("/home/flintx/peacock/html") / filename
            
            if filepath.exists() and filepath.suffix == '.html':
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                
                with open(filepath, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        """Handle POST requests - main processing"""
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        received_data = json.loads(post_data.decode('utf-8'))

        if self.path == PROCESS_PATH:
            command = received_data.get('command', 'unknown')
            text_to_process = received_data.get('text', '')
            timestamp = received_data.get('timestamp', SESSION_TIMESTAMP)
            final_model_choice = received_data.get('final_model_choice', 'qwen-32b-instruct')
            enable_logging = received_data.get('enable_logging', True)

            show_uniform_box(f"Processing command: {command} with model {final_model_choice}", "🚀")
            log_to_file('prompt', f"Command: {command}\nInput: {text_to_process}\nModel: {final_model_choice}\n{'-'*40}", force_log=enable_logging)
            log_to_file('mcp', f"Processing command: {command} for session: {timestamp}", force_log=enable_logging)

            if command == "peacock_full":
                result = self.process_with_birds(text_to_process, timestamp, final_model_choice, enable_logging)
            else:
                result = {"success": False, "error": f"Unknown command: {command}"}

        elif self.path == DEPLOY_PATH:
            project_name = received_data.get('project_name', f"pcock-app-{SESSION_TIMESTAMP}")
            project_files = received_data.get('project_files', [])
            show_uniform_box(f"Deploying project: {project_name}", "🦚")
            result = self.deploy_pcock_project(project_name, project_files)

        elif self.path == LOG_INPUT_PATH:
            prompt = received_data.get('prompt', '')
            session = received_data.get('session', SESSION_TIMESTAMP)
            model_choice = received_data.get('model_choice', 'unknown')
            
            show_uniform_box(f"Logging user input for session: {session}", "📝")
            
            # Force log user input regardless of LOGGING_ENABLED
            timestamp = datetime.datetime.now().isoformat()
            log_to_file('prompt', f"[{timestamp}] USER INPUT: {prompt}", force_log=True)
            log_to_file('prompt', f"[{timestamp}] MODEL CHOICE: {model_choice}", force_log=True)
            log_to_file('prompt', f"[{timestamp}] SESSION: {session}", force_log=True)
            
            result = {"success": True, "message": "Input logged successfully"}

        else:
            result = {"success": False, "error": f"Unknown endpoint: {self.path}"}

        # Send response
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        
        response_data = json.dumps(result, indent=2)
        self.wfile.write(response_data.encode("utf-8"))
        
        if result.get("success"):
            show_uniform_box(f"SUCCESS: Request to {self.path} completed", "✅")
        else:
            show_uniform_box(f"ERROR: Request to {self.path} failed", "❌")
            
        # Always log responses for debugging
        log_to_file('response', response_data, force_log=True)
    
    def process_with_birds(self, user_request: str, session_timestamp: str, final_model_choice: str, enable_logging: bool = True):
        show_uniform_box(f"Starting Championship Pipeline for: {user_request[:50]}...", "🏆")
        try:
            homing = create_homing_orchestrator()
            pipeline_result = homing.orchestrate_full_pipeline(user_request)

            if not pipeline_result.get("success"):
                return {"success": False, "error": pipeline_result.get("error", "Unknown pipeline error")}

            raw_code_output = pipeline_result.get("final_response")
            session_id = pipeline_result.get("session_id", session_timestamp)

            if not raw_code_output or raw_code_output.startswith("# API CALL FAILED"):
                return {"success": False, "error": f"Code generation failed: {raw_code_output}"}

            parser = create_enhanced_xedit_parser()
            parsed_data = parser.parse_llm_response(raw_code_output)
            xedit_file_path = parser.generate_xedit_html(parsed_data, session_id, user_request[:50])

            return {
                "success": True,
                "xedit_file_path": xedit_file_path,
                "session_id": session_id,
                "project_files": [{"name": cf.filename, "content": cf.content} for cf in parsed_data.code_files]
            }
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"success": False, "error": f"MCP error: {str(e)}"}

    def deploy_pcock_project(self, project_name: str, project_files: list):
        """Handles the deployment of a PCOCK project."""
        try:
            in_homing_processor = InHomingProcessor()
            deploy_result = in_homing_processor.deploy_and_run(project_files, project_name)
            return deploy_result
        except Exception as e:
            error_msg = f"Peacock Build error: {str(e)}"
            print(f"{CyberStyle.NEON_RED}❌ {error_msg}{CyberStyle.RESET}")
            log_to_file('mcp', error_msg, force_log=True)
            return {"success": False, "error": error_msg}

def log_enhanced_response(response_payload, parsing_result):
    """Log enhanced response details"""
    if LOGGING_ENABLED:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            "timestamp": timestamp,
            "command": response_payload.get("command"),
            "parsing_method": parsing_result.method.value,
            "confidence": parsing_result.confidence,
            "success": parsing_result.success,
            "data_keys": list(response_payload.get("structured_data", {}).keys())
        }
        
        log_file = f"/home/flintx/peacock/logs/enhanced-{SESSION_TIMESTAMP}.txt"
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"ENHANCED: {json.dumps(log_entry)}\n")


def main():
    """Main server startup with UNIFORM CYBERPUNK LAYOUT"""
    global LOGGING_ENABLED, PORT
    
    # Hardcode logging to TRUE for development. No more forgetting the flag.
    LOGGING_ENABLED = True
    PORT = 8000
    
    # Create logs directory
    if LOGGING_ENABLED:
        Path("/home/flintx/peacock/core/logs").mkdir(parents=True, exist_ok=True)
    
    # PERFECT STARTUP SEQUENCE WITH UNIFORM BORDERS
    
    # 1. Initialization box
    show_init_box()
    
    # 2. Configuration box
    show_config_box()
    
    # 3. Ready status line
    print(f"✅ Peacock MCP Server ready for requests...")
    
    try:
        with socketserver.TCPServer((HOST, PORT), CyberpunkRequestHandler) as httpd:
            
            # 4. Server started box
            show_uniform_box(f"MCP: Server started on {HOST}:{PORT}", "✅")
            
            # 5. THE SICK ASCII ART SECTION
            show_cyberpunk_ascii()
            
            # 6. Birds loaded box
            show_uniform_box("BIRDS: All bird modules loaded successfully", "🐦")
            
            # 7. Commands box
            show_uniform_box("Commands: peacock_full, deploy_pcock, xedit_fix", "👉")
            
            # 8. Final status
            print(f"🚀")
            print(f"⚡ Press Ctrl+C to stop")
            print()
            
            httpd.serve_forever()
            
    except KeyboardInterrupt:
        print(f"\n🛑 Server stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Server error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
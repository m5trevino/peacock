#!/usr/bin/env python3
"""
🦚 PEACOCK MCP SERVER - CYBERPUNK EDITION (UNIFORM SICK BORDERS)
Real API integration with multiple keys, proxy support, and SICK terminal styling
"""

import http.server
import socketserver
import json
import os
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
sys.path.insert(0, "/home/flintx/peacock/aviary")
sys.path.append(str(Path(__file__).parent.parent / "aviary"))
from out_homing import create_homing_orchestrator
from robust_parser import RobustParser, ParseResult

# --- CYBERPUNK CONFIGURATION ---
HOST = "127.0.0.1"
PORT = 8000
PROCESS_PATH = "/process"
LOGGING_ENABLED = False

# BIRD-SPECIFIC API KEYS
BIRD_API_KEYS = {
    "spark": "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",
    "falcon": "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",
    "eagle": "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",
    "hawk": "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"
}

# CHAMPION MODEL STRATEGY
PEACOCK_MODEL_STRATEGY = {
    "primary_model": "meta-llama/llama-4-scout-17b-16e-instruct",
    "detailed_model": "meta-llama/llama-4-maverick-17b-128e-instruct", 
    "speed_model": "llama-3.1-8b-instant",
    "fallback_model": "llama-3.3-70b-versatile"
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



    # MASSIVE CYBERPUNK CFONTS ARSENAL - THE FULL EXPERIENCE!
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
    "cfonts 'PEACOCK' -f tiny -g green,red",
    
    # Transition combinations (smooth flows)
    "cfonts 'PEACOCK' -f pallet -t yellow,red,magenta",
    "cfonts 'PEACOCK' -f slick -t green,cyan,blue", 
    "cfonts 'PEACOCK' -f shade -t red,magenta,blue",
    "cfonts 'PEACOCK' -f simple3d -t cyan,magenta,red",
    "cfonts 'PEACOCK' -f block -t blue,cyan,green",
    "cfonts 'PEACOCK' -f chrome -t green,yellow,red",
    "cfonts 'PEACOCK' -f grid -t red,yellow,magenta",
    "cfonts 'PEACOCK' -f simple -t magenta,cyan,blue",
    "cfonts 'PEACOCK' -f shade -t yellow,green,cyan",
    "cfonts 'PEACOCK' -f slick -t blue,magenta,red",
    
    # Single color classics (when you want clean)
    "cfonts 'PEACOCK' -f pallet -c cyan",
    "cfonts 'PEACOCK' -f slick -c blueBright",
    "cfonts 'PEACOCK' -f simple -c yellowBright",
    "cfonts 'PEACOCK' -f simple -c blue",
    "cfonts 'PEACOCK' -f simple -c green",
    "cfonts 'PEACOCK' -f block -c whiteBright",
    "cfonts 'PEACOCK' -f block -c blue",
    "cfonts 'PEACOCK' -f pallet -c cyanBright",
    "cfonts 'PEACOCK' -f grid -c yellow",
    "cfonts 'PEACOCK' -f slick -c whiteBright",
    "cfonts 'PEACOCK' -f chrome -c magenta",
    "cfonts 'PEACOCK' -f simple -c green",
    "cfonts 'PEACOCK' -f block -c red",
    "cfonts 'PEACOCK' -f shade -c cyan",
    "cfonts 'PEACOCK' -f simple3d -c blue",
    "cfonts 'PEACOCK' -f tiny -c green",
    "cfonts 'PEACOCK' -f chrome -c red",
    "cfonts 'PEACOCK' -f grid -c magenta",
    "cfonts 'PEACOCK' -f pallet -c yellow",
    "cfonts 'PEACOCK' -f slick -c green",
    
    # Background combinations (the fire ones)
    "cfonts 'PEACOCK' -f block -c white -b blue",
    "cfonts 'PEACOCK' -f simple -c yellow -b black",
    "cfonts 'PEACOCK' -f pallet -c cyan -b magenta",
    "cfonts 'PEACOCK' -f grid -c green -b red",
    "cfonts 'PEACOCK' -f chrome -c white -b cyan",
    "cfonts 'PEACOCK' -f shade -c blue -b yellow",
    "cfonts 'PEACOCK' -f slick -c red -b blue",
    "cfonts 'PEACOCK' -f simple3d -c magenta -b green",
    
    # Size variations (huge impact)
    "cfonts 'PEACOCK' -f huge -c cyan",
    "cfonts 'PEACOCK' -f massive -c red",
    "cfonts 'PEACOCK' -f tiny -c green",
    
    # Special effects (the wild ones)
    "cfonts 'PEACOCK' -f chrome -c rainbow",
    "cfonts 'PEACOCK' -f block -c candy",
    "cfonts 'PEACOCK' -f simple3d -c system",
    
    # More gradient madness
    "cfonts 'PEACOCK' -f pallet -g blue,cyan,green",
    "cfonts 'PEACOCK' -f slick -g red,yellow,green",
    "cfonts 'PEACOCK' -f shade -g magenta,blue,cyan",
    "cfonts 'PEACOCK' -f chrome -g yellow,red,magenta",
    "cfonts 'PEACOCK' -f grid -g green,blue,magenta",
    "cfonts 'PEACOCK' -f block -g cyan,yellow,red"
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
    print(f"   ♔ Primary Model: {PEACOCK_MODEL_STRATEGY['primary_model']}")
    print(f"   ♖ Speed Model: {PEACOCK_MODEL_STRATEGY['speed_model']}")
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
        char_count = stage_data.get("char_count", 0)
        model = stage_data.get("model", "unknown")
        icon = stage_icons.get(stage_name.lower(), "🔥")
        print(f"{icon}  {stage_name.upper():7}: {char_count:4} chars {model}")
    
    print(f"┕━━━━━»•» 🌺 «•«━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┙")

def log_to_file(log_type: str, content: str):
    """Enhanced logging with cyberpunk timestamps"""
    global LOGGING_ENABLED
    if not LOGGING_ENABLED:
        return
    
    timestamp = datetime.datetime.now().isoformat()
    log_dir = Path.cwd() / "logs"
    
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
        """Handle GET requests - health check"""
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
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        """Handle POST requests - main processing"""
        if self.path == PROCESS_PATH:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)

            try:
                received_data = json.loads(post_data.decode('utf-8'))
                
                command = received_data.get('command', 'unknown')
                text_to_process = received_data.get('text', '')
                timestamp = received_data.get('timestamp', SESSION_TIMESTAMP)
                
                show_uniform_box(f"Processing command: {command}", "🚀")
                log_to_file('prompt', f"Command: {command}\nInput: {text_to_process}\n{'-'*40}")
                
                # COMMAND ROUTING
                if command == "peacock_full":
                    result = self.process_with_birds(text_to_process, timestamp)
                elif command == "deploy_pcock":
                    result = {"success": True, "message": "PCOCK deployment not yet implemented"}
                else:
                    result = {"success": False, "error": f"Unknown command: {command}"}

                # Send response
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                
                response_data = json.dumps(result, indent=2)
                self.wfile.write(response_data.encode("utf-8"))
                
                if result.get("success"):
                    show_uniform_box(f"SUCCESS: Command {command} completed", "✅")
                else:
                    show_uniform_box(f"ERROR: Command {command} failed", "❌")
                    
                log_to_file('response', response_data)

            except Exception as e:
                error_response = {
                    "success": False,
                    "error": f"Server error: {str(e)}",
                    "command": command if 'command' in locals() else 'unknown'
                }
                
                self.send_response(500)
                self.send_header("Content-type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps(error_response).encode("utf-8"))
                
                print(f"{CyberStyle.NEON_RED}❌ Server error: {str(e)}{CyberStyle.RESET}")
                log_to_file('mcp', f"ERROR: {str(e)}")
    
    def process_with_birds(self, user_request: str, session_timestamp: str):
        """Process using OUT-HOMING bird orchestration"""
        
        show_uniform_box("Starting OUT-HOMING orchestration", "🐦")
        log_to_file('mcp', f"Starting bird orchestration for: {user_request[:100]}...")
        
        try:
            # Create orchestrator and run pipeline
            homing = create_homing_orchestrator()
            pipeline_result = homing.orchestrate_full_pipeline(user_request)
            
            if not pipeline_result.get("success"):
                error_msg = f"Pipeline failed: {pipeline_result.get('error', 'Unknown error')}"
                log_to_file('mcp', f"Pipeline failed: {error_msg}")
                return {"success": False, "error": error_msg}
            
            # FIXED: Extract character counts properly
            stage_results = pipeline_result.get("stage_results", {})
            
            # Build the response data that matches what the web UI expects
            response_stage_data = {}
            
            for stage_name, stage_data in stage_results.items():
                # Get character count from multiple possible sources
                char_count = (
                    stage_data.get("char_count") or 
                    stage_data.get("response_length") or 
                    len(stage_data.get("response", "")) or 
                    0
                )
                
                response_stage_data[stage_name] = {
                    "chars": char_count,  # This is what the web UI looks for
                    "char_count": char_count,  # Backup field
                    "model": stage_data.get("model", "unknown"),
                    "success": stage_data.get("success", False),
                    "response": stage_data.get("response", "")
                }
            
            # Show the character count summary in terminal
            show_character_count_summary(response_stage_data)
            
            log_to_file('mcp', f"Pipeline completed successfully with counts: {response_stage_data}")
            
            # CRITICAL: Return data in the exact format the web UI expects
            return {
                "success": True,
                "pipeline_result": {
                    "stage_results": response_stage_data,  # This is what the JS looks for
                    "total_chars": sum(data["chars"] for data in response_stage_data.values()),
                    "session": session_timestamp
                },
                "stage_results": response_stage_data,  # Also include at top level
                "message": "Peacock pipeline completed with real API calls"
            }
            
        except Exception as e:
            error_msg = f"Birds error: {str(e)}"
            print(f"{CyberStyle.NEON_RED}❌ {error_msg}{CyberStyle.RESET}")
            log_to_file('mcp', error_msg)
            return {"success": False, "error": error_msg}
            
            # Show success with character counts - FIXED DATA EXTRACTION
            stage_results = pipeline_result.get("stage_results", {})
            
            # Fix the character count extraction
            fixed_stage_results = {}
            for stage, data in stage_results.items():
                fixed_stage_results[stage] = {
                    "char_count": data.get("char_count", len(data.get("response", ""))),
                    "model": data.get("model", "unknown"),
                    "success": data.get("success", False)
                }
            
            show_character_count_summary(fixed_stage_results)
            
            log_to_file('mcp', f"Pipeline completed successfully")
            
            return {
                "success": True,
                "pipeline_result": pipeline_result,
                "stage_results": fixed_stage_results,
                "message": "Peacock pipeline completed with real API calls"
            }
            
        except Exception as e:
            error_msg = f"Birds error: {str(e)}"
            print(f"{CyberStyle.NEON_RED}❌ {error_msg}{CyberStyle.RESET}")
            log_to_file('mcp', error_msg)
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
    
    parser = argparse.ArgumentParser(description="Peacock MCP Server - Cyberpunk Edition")
    parser.add_argument("--log", action="store_true", help="Enable comprehensive logging")
    parser.add_argument("--port", type=int, default=8000, help="Server port (default: 8000)")
    
    args = parser.parse_args()
    
    LOGGING_ENABLED = args.log
    PORT = args.port
    
    # Create logs directory
    if LOGGING_ENABLED:
        (Path.cwd() / "logs").mkdir(parents=True, exist_ok=True)
    
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

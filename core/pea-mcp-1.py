#!/usr/bin/env python3
"""
🦚 PEACOCK MCP SERVER - PIGEON FLEET EDITION
Real API integration with new pigeon handlers and synthesis stages
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
import threading
import queue

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

def show_init_box():
    """Show initialization box"""
    print(f"{CyberStyle.NEON_CYAN}╔════════════════════════════════════╗{CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_GREEN}⚡ Initializing Peacock MCP Server...{CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_CYAN}╚════════════════════════════════════╝{CyberStyle.RESET}")

def show_config_box():
    """Show configuration box"""
    print(f"{CyberStyle.NEON_CYAN}╔═════════════════════════════════════════════════════════════╗{CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_GREEN}   ♔ Scout Model: {MODEL_CONFIG['scout_model']}{CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_GREEN}   ♖ Maverick Model: {MODEL_CONFIG['maverick_model']}{CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_GREEN}   ♗ Synthesis Model: {MODEL_CONFIG['synth_model']}{CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_GREEN}   ♘ Synthesis 2 Model: {MODEL_CONFIG['synth2_model']}{CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_GREEN}   ♙ Final Code Model: {MODEL_CONFIG['final_model']}{CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_GREEN}   ♟ XEdit Model: {MODEL_CONFIG['xedit_model']}{CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_GREEN}   📊 Logging: {'Enabled' if LOGGING_ENABLED else 'Disabled'}{CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_GREEN}   👉 Session: {SESSION_TIMESTAMP}{CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_CYAN}╚═════════════════════════════════════════════════════════════╝{CyberStyle.RESET}")

def show_stage_box(stage_name: str, message: str, icon: str = ""):
    """Show stage progress box"""
    print(f"{CyberStyle.NEON_CYAN}┌──═━┈━═─────────┐{CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_GREEN}{icon} {stage_name}: {message}{CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_CYAN}└──═━┈━═─────────┘{CyberStyle.RESET}")

def show_result_box(stage_name: str, message: str, icon: str = ""):
    """Show result box"""
    print(f"{CyberStyle.NEON_CYAN}┌──═━┈━═──┐{CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_GREEN}{icon} {stage_name} - {message}{CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_CYAN}└──═━┈━═──┘{CyberStyle.RESET}")

def show_character_count_summary(stage_results: dict):
    """Show character count summary with sick formatting"""
    print(f"\n{CyberStyle.NEON_PURPLE}STAGE CHARACTER COUNTS:{CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_CYAN}┍━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━»•» 🌺 «•«━━━━┑{CyberStyle.RESET}")
    
    stage_icons = {"spark": "⚡", "falcon": "👉", "eagle": "🐦", "hawk": "♔", "synthesis_1": "🦉", "synthesis_2": "🦉", "codegen": "🦚"}
    
    for stage_name, stage_data in stage_results.items():
        char_count = stage_data.get("char_count", stage_data.get("chars", 0))
        model = stage_data.get("model", "unknown")
        icon = stage_icons.get(stage_name.lower(), "🔥")
        print(f"{CyberStyle.NEON_GREEN}{icon}  {stage_name.upper():7}: {char_count:4} chars {model}{CyberStyle.RESET}")
    
    print(f"{CyberStyle.NEON_CYAN}┕━━━━━»•» 🌺 «•«━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┙{CyberStyle.RESET}")

# Add aviary to path for pigeon imports
import importlib.util
aviary_path = Path(__file__).parent.parent / "aviary"
sys.path.insert(0, str(aviary_path))

# Import modules with hyphens using importlib
def load_module(module_name, file_name):
    spec = importlib.util.spec_from_file_location(module_name, aviary_path / file_name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

carrier_pigeon = load_module('carrier_pigeon', 'carrier-pigeon.py')
racing_pigeon = load_module('racing_pigeon', 'racing-pigeon.py')
war_pigeon = load_module('war_pigeon', 'war-pigeon.py')
homing_pigeon = load_module('homing_pigeon', 'homing-pigeon.py')
snow_owl = load_module('snow_owl', 'snow-owl.py')
great_owl = load_module('great_owl', 'great-owl.py')
xedit_generator = load_module('xedit_generator', 'xedit_generator.py')
project_builder = load_module('project_builder', 'project-builder.py')

# Regular imports for files without hyphens
from peacock import create_peacock_generator as create_code_generator
from schemas import CodeFile, FinalCodeOutput

# Global message queue for SSE
message_queue = queue.Queue()

class Broadcaster:
    def __init__(self, message_queue):
        self.message_queue = message_queue

    def send(self, data):
        json_data = json.dumps(data)
        self.message_queue.put(json_data)

# Create factory functions
create_spark_handler = carrier_pigeon.create_spark_handler
create_falcon_handler = racing_pigeon.create_falcon_handler
create_eagle_handler = war_pigeon.create_eagle_handler
create_hawk_handler = homing_pigeon.create_hawk_handler
create_blueprint_synthesizer = snow_owl.create_blueprint_synthesizer
create_build_plan_synthesizer = great_owl.create_great_owl_synthesizer
create_xedit_generator = xedit_generator.create_xedit_generator
create_project_builder = project_builder.create_project_builder

# Create master parser function
def create_enhanced_xedit_parser():
    sys.path.insert(0, str(Path(__file__).parent))
    from master_parser import MasterParser
    return MasterParser()

# --- CYBERPUNK CONFIGURATION ---
HOST = "127.0.0.1"
PORT = 8000
PROCESS_PATH = "/process"
DEPLOY_PATH = "/deploy"
LOG_INPUT_PATH = "/log_input"
LOGGING_ENABLED = False

# MODEL CONFIGURATION
MODEL_CONFIG = {
    "scout_model": "meta-llama/llama-4-scout-17b-16e-instruct",      # Spark/Falcon
    "maverick_model": "meta-llama/llama-4-maverick-17b-128e-instruct", # Eagle/Hawk
    "synth_model": "deepseek-r1-distill-llama-70b",                  # SnowOwl
    "synth2_model": "deepseek-r1-distill-llama-70b",                 # GreatOwl
    "final_model": "qwen/qwen3-32b",                                 # Peacock codegen
    "xedit_model": "qwen/qwen3-32b"                                  # XEdit generation
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

def log_to_file(log_type, message, force_log=False):
    """Log messages to file with cyberpunk styling"""
    if LOGGING_ENABLED or force_log:
        log_dir = Path("/home/flintx/peacock/logs")
        log_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.datetime.now().isoformat()
        log_file = log_dir / f"{log_type}-{SESSION_TIMESTAMP}.log"
        
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {message}\n")

class PeacockHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """Cyberpunk HTTP request handler with pigeon fleet integration"""
    
    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
    
    def do_GET(self):
        """Handle GET requests, including SSE stream"""
        if self.path == '/stream':
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type')
            self.end_headers()
            
            while True:
                try:
                    message = message_queue.get(timeout=1)
                    self.wfile.write(f"data: {message}\n\n".encode('utf-8'))
                    self.wfile.flush()
                except queue.Empty:
                    try:
                        self.wfile.write(f"data: {json.dumps({'heartbeat': True})}\n\n".encode('utf-8'))
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        break
                except Exception as e:
                    print(f"{CyberStyle.NEON_RED}Error in SSE stream: {e}{CyberStyle.RESET}")
                    break
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")

    def do_POST(self):
        """Handle POST requests with pigeon fleet orchestration"""
        content_length = int(self.headers.get("Content-Length", 0))
        received_data = json.loads(self.rfile.read(content_length).decode("utf-8"))
        
        show_stage_box("REQUEST", f"Incoming request to {self.path}", "📡")
        
        if self.path == PROCESS_PATH:
            user_request = received_data.get('text', received_data.get('prompt', ''))
            session = received_data.get('session', SESSION_TIMESTAMP)
            
            broadcaster = Broadcaster(message_queue)
            
            thread = threading.Thread(target=self.process_with_pigeon_fleet, args=(user_request, session, broadcaster))
            thread.start()
            
            result = {"success": True, "message": "Pipeline initiated. Listening for events."}
            
        elif self.path == DEPLOY_PATH:
            project_name = received_data.get('project_name', 'Untitled Project')
            project_files = received_data.get('project_files', [])
            session_id = received_data.get('session_id', SESSION_TIMESTAMP)
            
            result = self.deploy_pcock_project(project_name, project_files)
            
        elif self.path == LOG_INPUT_PATH:
            prompt = received_data.get('prompt', '')
            session = received_data.get('session', SESSION_TIMESTAMP)
            model_choice = received_data.get('model_choice', 'unknown')
            
            show_stage_box("LOGGING", f"Logging user input for session: {session}", "📝")
            
            timestamp = datetime.datetime.now().isoformat()
            log_to_file('prompt', f"[{timestamp}] USER INPUT: {prompt}", force_log=True)
            log_to_file('prompt', f"[{timestamp}] MODEL CHOICE: {model_choice}", force_log=True)
            log_to_file('prompt', f"[{timestamp}] SESSION: {session}", force_log=True)
            
            result = {"success": True, "message": "Input logged successfully"}

        else:
            result = {"success": False, "error": f"Unknown endpoint: {self.path}"}

        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        
        response_data = json.dumps(result, indent=2)
        self.wfile.write(response_data.encode("utf-8"))
        
        if result.get("success"):
            show_result_box("RESPONSE", f"Request to {self.path} completed", "✅")
        else:
            show_result_box("RESPONSE", f"Request to {self.path} failed", "❌")
            
        log_to_file('response', response_data, force_log=True)
    
    def process_with_pigeon_fleet(self, user_request: str, session_timestamp: str, broadcaster):
        """Process request using phase-based pigeon fleet pipeline"""
        show_stage_box("PIPELINE", "Starting Phase-Based Pipeline", "🚀")
        
        try:
            session_id = session_timestamp
            stage_results = {}
            
            # PHASE 1: BIRDS (SPARK → FALCON → EAGLE → HAWK)
            broadcaster.send({"phase": "BIRDS", "status": "ACTIVE"})
            birds_result = self._execute_birds_phase(user_request, session_id, broadcaster)
            
            if not birds_result["success"]:
                broadcaster.send({"phase": "BIRDS", "status": "FAILED", "failed_stage": birds_result.get("failed_stage")})
                return birds_result
            stage_results.update({
                "spark": {"char_count": len(birds_result["data"]["spark_response"]), "model": MODEL_CONFIG["scout_model"]},
                "falcon": {"char_count": len(birds_result["data"]["falcon_response"]), "model": MODEL_CONFIG["scout_model"]},
                "eagle": {"char_count": len(birds_result["data"]["eagle_response"]), "model": MODEL_CONFIG["maverick_model"]},
                "hawk": {"char_count": len(birds_result["data"]["hawk_response"]), "model": MODEL_CONFIG["maverick_model"]}
            })
            
            # PHASE 2: OWLS (SYNTHESIS_1 → SYNTHESIS_2)
            broadcaster.send({"phase": "OWLS", "status": "ACTIVE"})
            owls_result = self._execute_owls_phase(birds_result["data"], session_id, broadcaster)
            
            if not owls_result["success"]:
                broadcaster.send({"phase": "OWLS", "status": "FAILED", "failed_stage": owls_result.get("failed_stage")})
                return owls_result
            stage_results.update({
                "synthesis_1": {"char_count": len(owls_result["data"]["project_blueprint"]), "model": MODEL_CONFIG["synth_model"]},
                "synthesis_2": {"char_count": len(owls_result["data"]["build_plan"]), "model": MODEL_CONFIG["synth2_model"]}
            })
            
            # PHASE 3: PEACOCK (Final Code Generation)
            broadcaster.send({"phase": "PEACOCK", "status": "ACTIVE"})
            peacock_result = self._execute_peacock_phase(owls_result["data"], session_id, broadcaster)
            
            if not peacock_result["success"]:
                broadcaster.send({"phase": "PEACOCK", "status": "FAILED", "failed_stage": "CODEGEN"})
                return peacock_result
            
            # Add CODEGEN to stage results
            stage_results.update({
                "codegen": {"char_count": peacock_result.get("char_count", 0), "model": MODEL_CONFIG["final_model"]}
            })
            
            show_result_box("PIPELINE", "All phases completed successfully!", "🏆")
            show_character_count_summary(stage_results)
            
            final_result = {
                "success": True,
                "xedit_file_path": peacock_result["data"]["xedit_file_path"],
                "session_id": session_id,
                "project_files": peacock_result["data"]["project_files"],
                "stages_completed": 7,
                "pipeline_type": "pigeon_fleet"
            }
            broadcaster.send({"stage": "PIPELINE", "status": "COMPLETED", "result": final_result})
            
            return final_result
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            show_result_box("PIPELINE", f"Error: {str(e)}", "💥")
            broadcaster.send({"stage": "PIPELINE", "status": "FAILED", "error": str(e)})
            return {"success": False, "error": f"Pigeon fleet error: {str(e)}"}
    
    def _execute_birds_phase(self, user_request: str, session_id: str, broadcaster):
        """Execute BIRDS phase: SPARK → FALCON → EAGLE → HAWK"""
        show_stage_box("PHASE 1", "BIRDS - Requirements & Architecture", "🦅")
        
        # STAGE 1: SPARK Analysis (Carrier Pigeon)
        broadcaster.send({"stage": "SPARK", "status": "ACTIVE"})
        show_stage_box("STAGE 1", "SPARK Requirements Analysis", "⚡")
        spark_handler = create_spark_handler(broadcaster=broadcaster)
        spark_response = spark_handler.get_analysis(user_request, session_id)
        
        if spark_response.startswith("# API CALL FAILED"):
            show_result_box("SPARK", "Failed", "❌")
            broadcaster.send({"stage": "SPARK", "status": "FAILED"})
            return {"success": False, "error": f"SPARK stage failed: {spark_response}", "failed_stage": "SPARK"}
        show_result_box("SPARK", "Completed", "✅")
        
        # STAGE 2: FALCON Architecture (Racing Pigeon)
        broadcaster.send({"stage": "FALCON", "status": "ACTIVE"})
        show_stage_box("STAGE 2", "FALCON Architecture Design", "🏎️")
        falcon_handler = create_falcon_handler(broadcaster=broadcaster)
        falcon_response = falcon_handler.get_architecture(spark_response, session_id)
        
        if falcon_response.startswith("# API CALL FAILED"):
            show_result_box("FALCON", "Failed", "❌")
            broadcaster.send({"stage": "FALCON", "status": "FAILED"})
            return {"success": False, "error": f"FALCON stage failed: {falcon_response}", "failed_stage": "FALCON"}
        show_result_box("FALCON", "Completed", "✅")
        
        # STAGE 3: EAGLE Implementation (War Pigeon)
        broadcaster.send({"stage": "EAGLE", "status": "ACTIVE"})
        show_stage_box("STAGE 3", "EAGLE Code Implementation", "⚔️")
        eagle_handler = create_eagle_handler(broadcaster=broadcaster)
        eagle_response = eagle_handler.get_implementation_plan(falcon_response, session_id)
        
        if eagle_response.startswith("# API CALL FAILED"):
            show_result_box("EAGLE", "Failed", "❌")
            broadcaster.send({"stage": "EAGLE", "status": "FAILED"})
            return {"success": False, "error": f"EAGLE stage failed: {eagle_response}", "failed_stage": "EAGLE"}
        show_result_box("EAGLE", "Completed", "✅")
        
        # STAGE 4: HAWK QA Analysis (Homing Pigeon)
        broadcaster.send({"stage": "HAWK", "status": "ACTIVE"})
        show_stage_box("STAGE 4", "HAWK Quality Assurance", "🏠")
        hawk_handler = create_hawk_handler(broadcaster=broadcaster)
        hawk_response = hawk_handler.get_qa_plan(eagle_response, session_id)
        
        if hawk_response.startswith("# API CALL FAILED"):
            show_result_box("HAWK", "Failed", "❌")
            broadcaster.send({"stage": "HAWK", "status": "FAILED"})
            return {"success": False, "error": f"HAWK stage failed: {hawk_response}", "failed_stage": "HAWK"}
        show_result_box("HAWK", "Completed", "✅")
        
        broadcaster.send({"phase": "BIRDS", "status": "COMPLETED"})
        return {
            "success": True,
            "data": {
                "spark_response": spark_response,
                "falcon_response": falcon_response,
                "eagle_response": eagle_response,
                "hawk_response": hawk_response
            }
        }
    
    def _execute_owls_phase(self, birds_data: dict, session_id: str, broadcaster):
        """Execute OWLS phase: SYNTHESIS_1 → SYNTHESIS_2"""
        show_stage_box("PHASE 2", "OWLS - Blueprint & Build Plan", "🦉")
        
        # STAGE 5: Blueprint Synthesis (Snow Owl)
        broadcaster.send({"stage": "SYNTHESIS_1", "status": "ACTIVE"})
        show_stage_box("STAGE 5", "Blueprint Synthesis", "🦉")
        blueprint_synthesizer = create_blueprint_synthesizer(broadcaster=broadcaster)
        project_blueprint = blueprint_synthesizer.create_blueprint(
            birds_data["spark_response"], 
            birds_data["falcon_response"], 
            session_id
        )
        
        try:
            blueprint_json = json.loads(project_blueprint)
            if "error" in blueprint_json and len(blueprint_json) == 1:
                error_msg = f"Blueprint synthesis failed: {blueprint_json['error']}"
                show_result_box("SYNTHESIS_1", "Failed", "❌")
                broadcaster.send({"stage": "SYNTHESIS_1", "status": "FAILED", "error": error_msg})
                return {"success": False, "error": error_msg, "failed_stage": "SYNTHESIS_1"}
        except json.JSONDecodeError as e:
            error_msg = f"Blueprint synthesis failed: Invalid JSON - {str(e)}"
            show_result_box("SYNTHESIS_1", "Failed", "❌")
            broadcaster.send({"stage": "SYNTHESIS_1", "status": "FAILED", "error": error_msg})
            return {"success": False, "error": error_msg, "failed_stage": "SYNTHESIS_1"}
        show_result_box("SYNTHESIS_1", "Completed", "✅")
        
        # STAGE 6: Build Plan Synthesis (Great Owl)
        broadcaster.send({"stage": "SYNTHESIS_2", "status": "ACTIVE"})
        show_stage_box("STAGE 6", "Build Plan Synthesis", "🦉")
        build_plan_synthesizer = create_build_plan_synthesizer(broadcaster=broadcaster)
        build_plan = build_plan_synthesizer.create_build_plan(
            birds_data["eagle_response"], 
            birds_data["hawk_response"], 
            session_id
        )
        
        try:
            build_plan_json = json.loads(build_plan)
            if "build_plan" not in build_plan_json:
                error_msg = f"Build plan synthesis failed: Missing 'build_plan' key - {build_plan[:1000]}..."
                show_result_box("SYNTHESIS_2", "Failed", "❌")
                broadcaster.send({"stage": "SYNTHESIS_2", "status": "FAILED", "error": error_msg})
                return {"success": False, "error": error_msg, "failed_stage": "SYNTHESIS_2"}
        except json.JSONDecodeError as e:
            error_msg = f"Build plan synthesis failed: Invalid JSON - {str(e)} - {build_plan[:1000]}..."
            show_result_box("SYNTHESIS_2", "Failed", "❌")
            broadcaster.send({"stage": "SYNTHESIS_2", "status": "FAILED", "error": error_msg})
            return {"success": False, "error": error_msg, "failed_stage": "SYNTHESIS_2"}
        show_result_box("SYNTHESIS_2", "Completed", "✅")
        
        broadcaster.send({"phase": "OWLS", "status": "COMPLETED"})
        return {
            "success": True,
            "data": {
                "project_blueprint": project_blueprint,
                "build_plan": build_plan
            }
        }
    
    def _execute_peacock_phase(self, owls_data: dict, session_id: str, broadcaster):
        """Execute PEACOCK phase: Final Code Generation"""
        show_stage_box("PHASE 3", "PEACOCK - Final Code Generation", "🦚")
        
        # STAGE 7: Final Code Generation (Peacock)
        broadcaster.send({"stage": "CODEGEN", "status": "ACTIVE"})
        show_stage_box("STAGE 7", "Final Code Generation", "🦚")
        code_generator = create_code_generator(broadcaster=broadcaster)
        final_code = code_generator.generate_code(
            owls_data["project_blueprint"], 
            owls_data["build_plan"], 
            session_id
        )
        
        if final_code.startswith("# CODE GENERATION FAILED"):
            show_result_box("CODEGEN", "Failed", "❌")
            broadcaster.send({"stage": "CODEGEN", "status": "FAILED"})
            return {"success": False, "error": f"Final code generation failed: {final_code}", "failed_stage": "CODEGEN"}
        show_result_box("CODEGEN", "Completed", "✅")
        
        # Parse final code with master parser
        show_stage_box("PARSING", "Parsing Final Code", "🔍")
        parser = create_enhanced_xedit_parser()
        parse_result = parser.parse(final_code)
        
        if not parse_result.success:
            show_result_box("PARSING", "Failed", "❌")
            broadcaster.send({"stage": "PARSING", "status": "FAILED"})
            return {"success": False, "error": f"Code parsing failed: {parse_result.errors}", "failed_stage": "PARSING"}
        show_result_box("PARSING", "Completed", "✅")
        
        # Generate XEdit interface
        show_stage_box("XEDIT", "Generating XEdit Interface", "🎨")
        xedit_generator = create_xedit_generator()
        pipeline_metadata = {
            "session_timestamp": session_id,
            "stages_completed": ["SPARK", "FALCON", "EAGLE", "HAWK", "SYNTHESIS1", "SYNTHESIS2", "CODEGEN"]
        }
        
        xedit_result = xedit_generator.generate_xedit_interface(parse_result.data, session_id, pipeline_metadata)
        
        if not xedit_result.get("success"):
            show_result_box("XEDIT", "Failed", "❌")
            broadcaster.send({"stage": "XEDIT", "status": "FAILED"})
            return {"success": False, "error": f"XEdit generation failed: {xedit_result.get('error')}", "failed_stage": "XEDIT"}
        show_result_box("XEDIT", "Completed", "✅")
        
        broadcaster.send({"phase": "PEACOCK", "status": "COMPLETED"})
        return {
            "success": True,
            "char_count": len(final_code),
            "data": {
                "xedit_file_path": xedit_result.get("xedit_file_path"),
                "project_files": xedit_result.get("project_files", [])
            }
        }

    def deploy_pcock_project(self, project_name: str, project_files: list):
        """Handles the deployment of a PCOCK project."""
        show_stage_box("DEPLOY", f"Deploying project: {project_name}", "🚀")
        try:
            project_builder = create_project_builder()
            deploy_result = project_builder.deploy_and_run(project_files, project_name)
            show_result_box("DEPLOY", "Completed", "✅")
            return deploy_result
        except Exception as e:
            error_msg = f"Peacock Build error: {str(e)}"
            show_result_box("DEPLOY", f"Error: {str(e)}", "❌")
            log_to_file('mcp', error_msg, force_log=True)
            return {"success": False, "error": error_msg}

def main():
    """Main server startup with PIGEON FLEET"""
    global LOGGING_ENABLED, PORT, HOST
    
    LOGGING_ENABLED = True  # Always enable logging
    
    parser = argparse.ArgumentParser(description="🦚 Peacock MCP Server - Pigeon Fleet Edition")
    parser.add_argument("--port", type=int, default=PORT, help=f"Port to run server on (default: {PORT})")
    parser.add_argument("--host", type=str, default=HOST, help=f"Host to bind to (default: {HOST})")
    parser.add_argument("--logging", action="store_true", help="Enable detailed logging")
    args = parser.parse_args()
    
    PORT = args.port
    HOST = args.host
    if args.logging:
        LOGGING_ENABLED = True
    
    # Display random cfonts banner
    cfont_command = random.choice(CYBERPUNK_CFONTS)
    try:
        subprocess.run(cfont_command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"{CyberStyle.NEON_RED}Failed to display cfonts: {e}{CyberStyle.RESET}")
    
    # Cyberpunk startup banner
    show_cyberpunk_ascii()
    show_init_box()
    show_config_box()
    
    try:
        with socketserver.TCPServer((HOST, PORT), PeacockHTTPRequestHandler) as httpd:
            show_stage_box("SERVER", f"PIGEON FLEET SERVER ONLINE: {HOST}:{PORT}", "🚀")
            httpd.serve_forever()
    except KeyboardInterrupt:
        show_result_box("SERVER", "PIGEON FLEET SERVER SHUTDOWN", "👋")
    except Exception as e:
        show_result_box("SERVER", f"Error: {str(e)}", "💥")

if __name__ == "__main__":
    main()
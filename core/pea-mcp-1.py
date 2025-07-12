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
from peacock import create_code_generator
from schemas import CodeFile, FinalCodeOutput

# Create factory functions
create_spark_handler = carrier_pigeon.create_spark_handler
create_falcon_handler = racing_pigeon.create_falcon_handler
create_eagle_handler = war_pigeon.create_eagle_handler
create_hawk_handler = homing_pigeon.create_hawk_handler
create_blueprint_synthesizer = snow_owl.create_blueprint_synthesizer
create_build_plan_synthesizer = great_owl.create_build_plan_synthesizer
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

# CHAMPION MODEL STRATEGY (Championship Configuration)
PEACOCK_MODEL_STRATEGY = {
    "scout_model": "meta-llama/llama-4-scout-17b-16e-instruct",      # Spark/Falcon
    "maverick_model": "meta-llama/llama-4-maverick-17b-128e-instruct", # Eagle/Hawk
    "synthesis_model": "deepseek-r1-distill-llama-70b",             # Snow/Great Owl
    "final_model": "qwen/qwen3-32b",                                 # Peacock
    "fallback_model": "llama-3.3-70b-versatile"                     # Emergency fallback
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

def show_uniform_box(message, icon="🦚"):
    """Show uniform cyberpunk-style message box"""
    border_char = "═"
    width = 60
    
    print(f"{CyberStyle.NEON_CYAN}{border_char * width}{CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_GREEN}{icon} {message}{CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_CYAN}{border_char * width}{CyberStyle.RESET}")

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
    
    def do_POST(self):
        """Handle POST requests with pigeon fleet orchestration"""
        content_length = int(self.headers.get("Content-Length", 0))
        received_data = json.loads(self.rfile.read(content_length).decode("utf-8"))
        
        show_uniform_box(f"Incoming request to {self.path}", "📡")
        
        if self.path == PROCESS_PATH:
            # Main processing endpoint with pigeon fleet
            user_request = received_data.get('text', received_data.get('prompt', ''))
            session = received_data.get('session', SESSION_TIMESTAMP)
            
            result = self.process_with_pigeon_fleet(user_request, session)
            
        elif self.path == DEPLOY_PATH:
            # Deployment endpoint
            project_name = received_data.get('project_name', 'Untitled Project')
            project_files = received_data.get('project_files', [])
            session_id = received_data.get('session_id', SESSION_TIMESTAMP)
            
            result = self.deploy_pcock_project(project_name, project_files)
            
        elif self.path == LOG_INPUT_PATH:
            # Input logging endpoint
            prompt = received_data.get('prompt', '')
            session = received_data.get('session', SESSION_TIMESTAMP)
            model_choice = received_data.get('model_choice', 'unknown')
            
            show_uniform_box(f"Logging user input for session: {session}", "📝")
            
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
            
        log_to_file('response', response_data, force_log=True)
    
    def process_with_pigeon_fleet(self, user_request: str, session_timestamp: str):
        """Process request using the new 7-stage pigeon fleet pipeline"""
        show_uniform_box(f"🦚 PIGEON FLEET: Starting 7-stage pipeline", "🚀")
        
        try:
            session_id = session_timestamp
            
            # STAGE 1: SPARK Analysis (Carrier Pigeon)
            show_uniform_box("STAGE 1: SPARK Requirements Analysis", "🕊️")
            spark_handler = create_spark_handler()
            spark_response = spark_handler.get_analysis(user_request, session_id)
            
            if spark_response.startswith("# API CALL FAILED"):
                return {"success": False, "error": f"SPARK stage failed: {spark_response}"}
            
            # STAGE 2: FALCON Architecture (Racing Pigeon)
            show_uniform_box("STAGE 2: FALCON Architecture Design", "🏎️")
            falcon_handler = create_falcon_handler()
            falcon_response = falcon_handler.get_architecture(spark_response, session_id)
            
            if falcon_response.startswith("# API CALL FAILED"):
                return {"success": False, "error": f"FALCON stage failed: {falcon_response}"}
            
            # STAGE 3: EAGLE Implementation (War Pigeon)
            show_uniform_box("STAGE 3: EAGLE Code Implementation", "⚔️")
            eagle_handler = create_eagle_handler()
            eagle_response = eagle_handler.get_implementation_plan(falcon_response, session_id)
            
            if eagle_response.startswith("# API CALL FAILED"):
                return {"success": False, "error": f"EAGLE stage failed: {eagle_response}"}
            
            # STAGE 4: HAWK QA Analysis (Homing Pigeon)
            show_uniform_box("STAGE 4: HAWK Quality Assurance", "🏠")
            hawk_handler = create_hawk_handler()
            hawk_response = hawk_handler.get_qa_plan(eagle_response, session_id)
            
            if hawk_response.startswith("# API CALL FAILED"):
                return {"success": False, "error": f"HAWK stage failed: {hawk_response}"}
            
            # STAGE 5: Blueprint Synthesis (Snow Owl)
            show_uniform_box("STAGE 5: Blueprint Synthesis", "🦉")
            blueprint_synthesizer = create_blueprint_synthesizer()
            project_blueprint = blueprint_synthesizer.create_blueprint(spark_response, falcon_response, session_id)
            
            # Check if project_blueprint is actually an error (starts with {"error": ...)
            try:
                blueprint_json = json.loads(project_blueprint)
                if isinstance(blueprint_json, dict) and "error" in blueprint_json and len(blueprint_json) == 1:
                    return {"success": False, "error": f"Blueprint synthesis failed: {project_blueprint}"}
            except json.JSONDecodeError:
                return {"success": False, "error": f"Blueprint synthesis failed: {project_blueprint}"}
            
            # STAGE 6: Build Plan Synthesis (Great Owl)
            show_uniform_box("STAGE 6: Build Plan Synthesis", "🦉")
            build_plan_synthesizer = create_build_plan_synthesizer()
            build_plan = build_plan_synthesizer.create_build_plan(eagle_response, hawk_response, session_id)
            
            # Check if build_plan is actually an error (starts with {"error": ...)
            try:
                build_plan_json = json.loads(build_plan)
                if isinstance(build_plan_json, dict) and "error" in build_plan_json and len(build_plan_json) == 1:
                    return {"success": False, "error": f"Build plan synthesis failed: {build_plan}"}
            except json.JSONDecodeError:
                return {"success": False, "error": f"Build plan synthesis failed: {build_plan}"}
            
            # STAGE 7: Final Code Generation (Peacock)
            show_uniform_box("STAGE 7: Final Code Generation", "🦚")
            code_generator = create_code_generator()
            final_code = code_generator.generate_code(project_blueprint, build_plan, session_id)
            
            if final_code.startswith("# CODE GENERATION FAILED"):
                return {"success": False, "error": f"Final code generation failed: {final_code}"}
            
            # Parse final code with master parser
            show_uniform_box("Parsing Final Code", "🔍")
            parser = create_enhanced_xedit_parser()
            parse_result = parser.parse(final_code)
            
            if not parse_result.success:
                return {"success": False, "error": f"Code parsing failed: {parse_result.errors}"}
            
            # Generate XEdit interface
            show_uniform_box("Generating XEdit Interface", "🎨")
            xedit_generator = create_xedit_generator()
            pipeline_metadata = {
                "session_timestamp": session_id,
                "stages_completed": ["SPARK", "FALCON", "EAGLE", "HAWK", "SYNTHESIS1", "SYNTHESIS2", "CODEGEN"]
            }
            
            xedit_result = xedit_generator.generate_xedit_interface(parse_result.data, session_id, pipeline_metadata)
            
            if not xedit_result.get("success"):
                return {"success": False, "error": f"XEdit generation failed: {xedit_result.get('error')}"}
            
            show_uniform_box("🦚 PIGEON FLEET: Pipeline completed successfully!", "🏆")
            
            return {
                "success": True,
                "xedit_file_path": xedit_result.get("xedit_file_path"),
                "session_id": session_id,
                "project_files": xedit_result.get("project_files", []),
                "stages_completed": 7,
                "pipeline_type": "pigeon_fleet"
            }
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            show_uniform_box(f"PIPELINE ERROR: {str(e)}", "💥")
            return {"success": False, "error": f"Pigeon fleet error: {str(e)}"}

    def deploy_pcock_project(self, project_name: str, project_files: list):
        """Handles the deployment of a PCOCK project."""
        try:
            project_builder = create_project_builder()
            deploy_result = project_builder.deploy_and_run(project_files, project_name)
            return deploy_result
        except Exception as e:
            error_msg = f"Peacock Build error: {str(e)}"
            print(f"{CyberStyle.NEON_RED}❌ {error_msg}{CyberStyle.RESET}")
            log_to_file('mcp', error_msg, force_log=True)
            return {"success": False, "error": error_msg}

def main():
    """Main server startup with PIGEON FLEET"""
    global LOGGING_ENABLED, PORT, HOST
    
    LOGGING_ENABLED = True  # Enable logging for development
    
    parser = argparse.ArgumentParser(description="🦚 Peacock MCP Server - Pigeon Fleet Edition")
    parser.add_argument("--port", type=int, default=PORT, help=f"Port to run server on (default: {PORT})")
    parser.add_argument("--host", type=str, default=HOST, help=f"Host to bind to (default: {HOST})")
    parser.add_argument("--logging", action="store_true", help="Enable detailed logging")
    args = parser.parse_args()
    
    PORT = args.port
    HOST = args.host
    if args.logging:
        LOGGING_ENABLED = True
    
    # Cyberpunk startup banner
    print(f"\n{CyberStyle.NEON_CYAN}{'═' * 80}{CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_GREEN}🦚 PEACOCK MCP SERVER - PIGEON FLEET EDITION{CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_PURPLE}7-Stage Championship Pipeline: SPARK → FALCON → EAGLE → HAWK → SYNTHESIS → CODEGEN{CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_CYAN}{'═' * 80}{CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_YELLOW}🕊️ Carrier Pigeon: SPARK Requirements (SCOUT){CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_YELLOW}🏎️ Racing Pigeon: FALCON Architecture (SCOUT){CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_YELLOW}⚔️ War Pigeon: EAGLE Implementation (MAVERICK){CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_YELLOW}🏠 Homing Pigeon: HAWK QA Analysis (MAVERICK){CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_YELLOW}🦉 Snow Owl: Blueprint Synthesis (DeepSeek){CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_YELLOW}🦉 Great Owl: Build Plan Synthesis (DeepSeek){CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_YELLOW}🦚 Peacock: Final Code Generation (QWEN){CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_CYAN}{'═' * 80}{CyberStyle.RESET}")
    print(f"{CyberStyle.ELECTRIC_BLUE}Server: {HOST}:{PORT}{CyberStyle.RESET}")
    print(f"{CyberStyle.ELECTRIC_BLUE}Session: {SESSION_TIMESTAMP}{CyberStyle.RESET}")
    print(f"{CyberStyle.ELECTRIC_BLUE}Logging: {'ENABLED' if LOGGING_ENABLED else 'DISABLED'}{CyberStyle.RESET}")
    print(f"{CyberStyle.NEON_CYAN}{'═' * 80}{CyberStyle.RESET}\n")
    
    try:
        with socketserver.TCPServer((HOST, PORT), PeacockHTTPRequestHandler) as httpd:
            show_uniform_box(f"🦚 PIGEON FLEET SERVER ONLINE: {HOST}:{PORT}", "🚀")
            httpd.serve_forever()
    except KeyboardInterrupt:
        show_uniform_box("🦚 PIGEON FLEET SERVER SHUTDOWN", "👋")
    except Exception as e:
        show_uniform_box(f"SERVER ERROR: {str(e)}", "💥")

if __name__ == "__main__":
    main()
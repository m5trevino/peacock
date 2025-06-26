#!/usr/bin/env python3
import os
import re
from pathlib import Path

def read_base_file():

import asyncio
import json
import logging
import sys
import datetime
import argparse
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import threading

# Add aviary to path for bird imports
sys.path.append(str(Path(__file__).parent.parent / \"aviary\"))
from out_homing import create_homing_orchestrator

# --- CORE CONFIGURATION ---
HOST = \"127.0.0.1\"
PORT = 8000
PROCESS_PATH = \"/process\"
LOGGING_ENABLED = False

# BIRD-SPECIFIC API KEYS
BIRD_API_KEYS = {
    \"spark\": \"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\",
    \"falcon\": \"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\",
    \"eagle\": \"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\",
    \"hawk\": \"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\"
}

# CHAMPION MODEL STRATEGY
PEACOCK_MODEL_STRATEGY = {
    \"primary_model\": \"meta-llama/llama-4-scout-17b-16e-instruct\",
    \"detailed_model\": \"meta-llama/llama-4-maverick-17b-128e-instruct\", 
    \"speed_model\": \"llama-3.1-8b-instant\",
    \"fallback_model\": \"llama-3.3-70b-versatile\"
}

# SESSION MANAGEMENT
def generate_session_timestamp():
    \"\"\"Generate session timestamp in week-day-hourminute format\"\"\"
    now = datetime.datetime.now()
    week = now.isocalendar()[1]
    day = now.day
    hour_minute = now.strftime(\"%H%M\")
    return f\"{week}-{day}-{hour_minute}\"

SESSION_TIMESTAMP = generate_session_timestamp()

# DISPLAY_BLOCK_PLACEHOLDER

# LOGGING SETUP
def setup_logging():
    \"\"\"Setup logging configuration\"\"\"
    global LOGGING_ENABLED
    
    if LOGGING_ENABLED:
        log_dir = Path(__file__).parent.parent / \"logs\"
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / f\"mcplog-{SESSION_TIMESTAMP}.txt\"
        
        logging.basicConfig(
            level=logging.INFO,
            format='[%(asctime)s] %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
    else:
        logging.basicConfig(level=logging.WARNING)

# HTTP REQUEST HANDLER
class PeacockHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        \"\"\"Override to use our display system\"\"\"
        if LOGGING_ENABLED:
            logging.info(format % args)
        display_request_log(self.command, self.path, args[1] if len(args) > 1 else \"200\")

    def do_OPTIONS(self):
        \"\"\"Handle CORS preflight requests\"\"\"
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_POST(self):
        \"\"\"Handle POST requests\"\"\"
        if self.path == PROCESS_PATH:
            self.handle_process_request()
        else:
            self.send_error(404, \"Not Found\")

    def handle_process_request(self):
        \"\"\"Handle the main process request\"\"\"
        try:
            # Parse request body
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            request_data = json.loads(post_data.decode('utf-8'))
            
            user_input = request_data.get('input', '')
            command = request_data.get('command', 'peacock_full')
            
            display_processing_start(command)
            
            if command == \"peacock_full\":
                result = self.execute_peacock_pipeline(user_input)
            else:
                result = {\"success\": False, \"message\": f\"Unknown command: {command}\"}
            
            # Send response
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            response_json = json.dumps(result, indent=2)
            self.wfile.write(response_json.encode('utf-8'))
            
            display_completion(result.get(\"success\", False), command)
            
        except Exception as e:
            self.send_error(500, f\"Internal Server Error: {str(e)}\")
            logging.error(f\"Request handling error: {e}\")

    def execute_peacock_pipeline(self, user_input):
        \"\"\"Execute the full peacock pipeline\"\"\"
        try:
            display_orchestration_start()
            display_session_info()
            
            # Create orchestrator
            orchestrator = create_homing_orchestrator(
                api_keys=BIRD_API_KEYS,
                model_strategy=PEACOCK_MODEL_STRATEGY,
                session_timestamp=SESSION_TIMESTAMP
            )
            
            # Execute pipeline
            display_separator()
            
            # SPARK Stage
            display_stage_start(\"SPARK\", \"Requirements Analysis\")
            spark_result = orchestrator.execute_spark(user_input)
            display_stage_result(\"SPARK\", spark_result.get(\"success\", False), 
                                spark_result.get(\"char_count\", 0),
                                spark_result.get(\"model\", \"\"),
                                spark_result.get(\"api_key_used\", \"\")[-8:] if spark_result.get(\"api_key_used\") else \"\")
            
            display_separator()
            
            # FALCON Stage  
            display_stage_start(\"FALCON\", \"Architecture Design\")
            falcon_result = orchestrator.execute_falcon(spark_result.get(\"response\", \"\"))
            display_stage_result(\"FALCON\", falcon_result.get(\"success\", False),
                                falcon_result.get(\"char_count\", 0),
                                falcon_result.get(\"model\", \"\"),
                                falcon_result.get(\"api_key_used\", \"\")[-8:] if falcon_result.get(\"api_key_used\") else \"\")
            
            display_separator()
            
            # EAGLE Stage
            display_stage_start(\"EAGLE\", \"Code Implementation\")
            eagle_result = orchestrator.execute_eagle(falcon_result.get(\"response\", \"\"))
            display_stage_result(\"EAGLE\", eagle_result.get(\"success\", False),
                                eagle_result.get(\"char_count\", 0),
                                eagle_result.get(\"model\", \"\"),
                                eagle_result.get(\"api_key_used\", \"\")[-8:] if eagle_result.get(\"api_key_used\") else \"\")
            
            display_separator()
            
            # HAWK Stage
            display_stage_start(\"HAWK\", \"QA & Testing\")
            hawk_result = orchestrator.execute_hawk(user_input, eagle_result.get(\"response\", \"\"))
            display_stage_result(\"HAWK\", hawk_result.get(\"success\", False),
                                hawk_result.get(\"char_count\", 0),
                                hawk_result.get(\"model\", \"\"),
                                hawk_result.get(\"api_key_used\", \"\")[-8:] if hawk_result.get(\"api_key_used\") else \"\")
            
            display_separator()
            
            # Compile results
            stage_results = {
                \"spark\": spark_result,
                \"falcon\": falcon_result, 
                \"eagle\": eagle_result,
                \"hawk\": hawk_result
            }
            
            display_character_summary(stage_results)
            
            # Generate final response
            final_response = orchestrator.compile_final_response(stage_results)
            
            return {
                \"success\": True,
                \"pipeline_result\": {
                    \"success\": True,
                    \"session_timestamp\": SESSION_TIMESTAMP,
                    \"stage_results\": stage_results,
                    \"final_response\": final_response,
                    \"total_birds\": 4,
                    \"pipeline_type\": \"full_orchestration\",
                    \"api_calls_made\": sum(1 for result in stage_results.values() if result.get(\"success\"))
                },
                \"stage_results\": {name: {\"char_count\": result.get(\"char_count\", 0), 
                                       \"model\": result.get(\"model\", \"\"), 
                                       \"success\": result.get(\"success\", False)}
                                for name, result in stage_results.items()},
                \"message\": \"Peacock pipeline completed with real API calls\"
            }
            
        except Exception as e:
            logging.error(f\"Pipeline execution error: {e}\")
            return {
                \"success\": False,
                \"error\": str(e),
                \"message\": \"Pipeline execution failed\"
            }

def start_server():
    \"\"\"Start the HTTP server\"\"\"
    display_server_start()
    
    server = HTTPServer((HOST, PORT), PeacockHandler)
    
    def run_server():
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print(\"\\\
Shutting down server...\")
            server.shutdown()
    
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    
    return server

def main():
    \"\"\"Main server function\"\"\"
    global LOGGING_ENABLED
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Peacock MCP Server')
    parser.add_argument('--log', action='store_true', help='Enable logging')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    args = parser.parse_args()
    
    if args.log:
        LOGGING_ENABLED = True
    
    # Setup logging
    setup_logging()
    
    # Display initialization
    display_init()
    display_config()
    display_birds_loaded()
    display_commands()
    
    # Start server
    server = start_server()
    
    try:
        print(\"⚡ Press Ctrl+C to stop\")
        
        # Keep main thread alive
        while True:
            import time
            time.sleep(1)
            
    except KeyboardInterrupt:
        print(\"\\\
Shutting down Peacock MCP Server...\")
        server.shutdown()

if __name__ == \"__main__\":
    main()
'''
    return base_content

def get_debug_block():
    \"\"\"Get the debug block content\"\"\"
    return '''
# 🔧 DEBUG BLOCK - ENHANCED DEBUGGING SYSTEM
import traceback
import inspect
import json
import time
from datetime import datetime
import psutil
import os

# DEBUG CONFIGURATION
DEBUG_CONFIG = {
    \"verbose\": True,
    \"show_stack\": True,
    \"show_memory\": True,
    \"show_timing\": True,
    \"show_api_details\": True,
    \"show_function_calls\": True,
    \"log_to_file\": True,
    \"debug_level\": \"FULL\"  # MINIMAL, STANDARD, FULL
}

class DebugLogger:
    def __init__(self):
        self.start_time = time.time()
        self.stage_timings = {}
        self.memory_baseline = psutil.Process().memory_info().rss / 1024 / 1024
        
    def log(self, level, message, **kwargs):
        timestamp = datetime.now().strftime(\"%H:%M:%S.%f\")[:-3]
        memory_mb = psutil.Process().memory_info().rss / 1024 / 1024
        memory_delta = memory_mb - self.memory_baseline
        
        output = f\"[{timestamp}] [{level}] {message}\"
        
        if DEBUG_CONFIG[\"show_memory\"]:
            output += f\" | MEM: {memory_mb:.1f}MB (+{memory_delta:+.1f}MB)\"
            
        if DEBUG_CONFIG[\"show_timing\"]:
            elapsed = time.time() - self.start_time
            output += f\" | TIME: {elapsed:.2f}s\"
            
        if kwargs:
            output += f\" | DATA: {json.dumps(kwargs, default=str)}\"
            
        print(output)
        
        if DEBUG_CONFIG[\"log_to_file\"]:
            with open(f\"/home/flintx/peacock/logs/debug-{SESSION_TIMESTAMP}.log\", \"a\") as f:
                f.write(output + \"\\\
\")

# Global debug logger
debug = DebugLogger()

def display_init():
    debug.log(\"INIT\", \"Peacock MCP Server Starting...\")

def display_config():
    debug.log(\"CONFIG\", \"Loading configuration\")
    debug.log(\"CONFIG\", \"Model Strategy\", **PEACOCK_MODEL_STRATEGY)

def display_server_start():
    debug.log(\"SERVER\", f\"MCP: Server started on {HOST}:{PORT}\")

def display_birds_loaded():
    debug.log(\"INIT\", \"BIRDS: All bird modules loaded successfully\")

def display_commands():
    debug.log(\"INIT\", \"Commands: peacock_full, deploy_pcock, xedit_fix\")

def display_processing_start(command):
    debug.log(\"REQUEST\", f\"Processing command: {command}\")

def display_orchestration_start():
    debug.log(\"PIPELINE\", \"Starting OUT-HOMING orchestration\")

def display_session_info():
    debug.log(\"PIPELINE\", f\"Session: {SESSION_TIMESTAMP}\")
    debug.log(\"PIPELINE\", f\"API Keys: {len(BIRD_API_KEYS)} available\")

def display_stage_start(stage_name, message):
    debug.log(\"STAGE\", f\"STAGE: {stage_name} - {message}\")

def display_stage_result(stage_name, success, char_count=0, model=\"\", key_hint=\"\"):
    status = \"SUCCESS\" if success else \"FAILED\"
    debug.log(\"STAGE\", f\"{stage_name} - {status}\", chars=char_count, model=model, key=key_hint)

def display_separator():
    debug.log(\"STAGE\", \"Stage separator\")

def display_character_summary(stage_results):
    debug.log(\"SUMMARY\", \"Stage Results Summary\")
    total_chars = 0
    for stage_name, stage_data in stage_results.items():
        char_count = stage_data.get(\"char_count\", 0)
        model = stage_data.get(\"model\", \"unknown\")
        total_chars += char_count
        debug.log(\"SUMMARY\", f\"{stage_name.upper()}\", chars=char_count, model=model)
    debug.log(\"SUMMARY\", \"Pipeline Totals\", total_characters=total_chars)

def display_request_log(method, path, status):
    debug.log(\"REQUEST\", f\"{method} {path} HTTP/1.1\", status=status)

def display_completion(success, command):
    status = \"SUCCESS\" if success else \"FAILED\"
    debug.log(\"REQUEST\", f\"{status}: Command {command} completed\")
'''

def get_visual_block():
    \"\"\"Get the visual block content\"\"\"
    return '''
# 🎨 VISUAL BLOCK - CYBERPUNK STYLING SYSTEM
class CyberStyle:
    RESET = '\\\\033[0m'
    BOLD = '\\\\033[1m'
    DIM = '\\\\033[2m'
    NEON_GREEN = '\\\\033[92m'
    NEON_CYAN = '\\\\033[96m'
    NEON_PURPLE = '\\\\033[95m'
    NEON_YELLOW = '\\\\033[93m'
    NEON_RED = '\\\\033[91m'
    MATRIX_GREEN = '\\\\033[32m'
    ELECTRIC_BLUE = '\\\\033[94m'
    HOT_PINK = '\\\\033[35m'

def show_cyberpunk_ascii():
    \"\"\"Show the sick ASCII art section\"\"\"
    chess_border = f\"{CyberStyle.NEON_CYAN}♞▀▄▀▄♝▀▄ ♞▀▄▀▄♝▀▄‍‌♞▀▄▀▄♝▀▄ ♞▀▄▀▄♝▀▄‍‌♞▀▄▀▄♝▀▄{CyberStyle.RESET}\"
    
    print(f\"{chess_border}\")
    print(\"░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░\")
    print(\"░░█░░░███░░████░░██░░████░░██░░████░█░░█░░█░░\")
    print(\"░░ ░░░█  █░█   ░█  █░█   ░█  █░█   ░█░░█░░ ░░\")
    print(\"░░░░░░███ ░███░░████░█░░░░█░░█░█░░░░███ ░░░░░\")
    print(\"░░░░░░█  ░░█  ░░█  █░█░░░░█░░█░█░░░░█  █░░░░░\")
    print(\"░░░░░░█░░░░████░█░░█░████░ ██ ░████░█░░█░░░░░\")
    print(\"░░░░░░ ░░░░    ░ ░░ ░    ░░  ░░    ░ ░░ ░░░░░\")
    print(\"░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░\")
    print(f\"{chess_border}\\\
\")

def display_init():
    print(f\"╔════════════════════════════════════╗\")
    print(f\"⚡ Initializing Peacock MCP Server...\")
    print(f\"╚════════════════════════════════════╝\")

def display_config():
    print(f\"╔═════════════════════════════════════════════════════════════╗\")
    print(f\"   ♔ Primary Model: {PEACOCK_MODEL_STRATEGY['primary_model']}\")
    print(f\"   ♖ Speed Model: {PEACOCK_MODEL_STRATEGY['speed_model']}\")
    print(f\"   📊 Logging: {'Enabled' if LOGGING_ENABLED else 'Disabled'}\")
    print(f\"   👉 Session: {SESSION_TIMESTAMP}\")
    print(f\"╚═════════════════════════════════════════════════════════════╝\")

def display_server_start():
    print(f\"╔═════════════════════════════════════════╗\")
    print(f\"✅  MCP: Server started on {HOST}:{PORT}\")
    print(f\"╚═════════════════════════════════════════╝\")

def display_birds_loaded():
    print(f\"╔═════════════════════════════════════════════╗\")
    print(f\"🐦 BIRDS: All bird modules loaded successfully\")
    print(f\"╚═════════════════════════════════════════════╝\")

def display_commands():
    print(f\"╔═════════════════════════════════════════════════╗\")
    print(f\"👉 Commands: peacock_full, deploy_pcock, xedit_fix\")
    print(f\"╚═════════════════════════════════════════════════╝\")

def display_processing_start(command):
    print(f\"╔════════════════════════════════════════════╗🚀\")
    print(f\"⚡ Processing command: {command}\")
    print(f\"╚════════════════════════════════════════════╝\")

def display_orchestration_start():
    print(f\"╔═══════════════════════════════════╗🚀\")
    print(f\"🐦 Starting OUT-HOMING orchestration\")
    print(f\"╚═══════════════════════════════════╝\")

def display_session_info():
    print(f\"╔════════════════════════╗🚀\")
    print(f\"♖  Session: {SESSION_TIMESTAMP}\")
    print(f\"🔑 API Keys: {len(BIRD_API_KEYS)} available\")
    print(f\"╚════════════════════════╝\")

def display_stage_start(stage_name, message):
    print(f\"┌──═━┈━═─────────┐\")
    print(f\"⚡ STAGE: {stage_name} - {message}\")
    print(f\"└──═━┈━═─────────┘\")

def display_stage_result(stage_name, success, char_count=0, model=\"\", key_hint=\"\"):
    status = \"SUCCESS\" if success else \"FAILED\"
    print(f\"┌──═━┈━═──┐\")
    print(f\"✅ {stage_name} - {status} - {char_count} chars - Key: {key_hint}\")
    print(f\"└──═━┈━═──┘\")

def display_separator():
    print(\"♞▀▄▀▄♝▀▄ ♞▀▄▀▄♝▀▄‍‌♞▀▄▀▄♝▀▄ ♞▀▄▀▄♝▀▄‍‌♞▀▄▀▄♝▀▄\")

def display_character_summary(stage_results):
    print(f\"\\\
STAGE CHARACTER COUNTS:\")
    print(f\"┍━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━»•» 🌺 «•«━━━━┑\")
    stage_icons = {\"spark\": \"⚡\", \"falcon\": \"👉\", \"eagle\": \"🐦\", \"hawk\": \"♔\"}
    for stage_name, stage_data in stage_results.items():
        char_count = stage_data.get(\"char_count\", 0)
        model = stage_data.get(\"model\", \"unknown\")
        icon = stage_icons.get(stage_name.lower(), \"🔥\")
        print(f\"{icon}  {stage_name.upper():7}: {char_count:4} chars {model}\")
    print(f\"┕━━━━━»•» 🌺 «•«━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┙\")

def display_request_log(method, path, status):
    timestamp = datetime.datetime.now().strftime(\"%H:%M:%S\")
    print(f\"┏━━━━━━━━━━━━━━━━━━━━━•❅•°•❈•°•❅•━━━━━━━━━━━━━━━━━━━━┓\")
    print(f\"✅ [{timestamp}] \\\\\"{method} {path} HTTP/1.1\\\\\" {status} -\")
    print(f\"┗━━━━━━━━━━━━━━━━━━━━━•❅•°•❈•°•❅•━━━━━━━━━━━━━━━━━━━━┛\")

def display_completion(success, command):
    status = \"SUCCESS\" if success else \"FAILED\"
    print(f\"┏━━━━━━━━━━━━━━━━━━━━━•❅•°•❈•°•❅•━━━━━━━━━━━━━━━━━━━━┓\")
    print(f\"✅ {status}: Command {command} completed\")
    print(f\"┗━━━━━━━━━━━━━━━━━━━━━•❅•°•❈•°•❅•━━━━━━━━━━━━━━━━━━━━┛\")
'''

def build_debug_version():
    \"\"\"Build the debug version\"\"\"
    base_content = read_base_file()
    debug_block = get_debug_block()
    
    # Replace the placeholder with debug block
    content = base_content.replace(\"# DISPLAY_BLOCK_PLACEHOLDER\", debug_block)
    
    return content

def build_visual_version():
    \"\"\"Build the visual version\"\"\"
    base_content = read_base_file()
    visual_block = get_visual_block()
    
    # Replace the placeholder with visual block
    content = base_content.replace(\"# DISPLAY_BLOCK_PLACEHOLDER\", visual_block)
    
    return content

def main():
    \"\"\"Main builder function\"\"\"
    print(\"🔧 Building Peacock MCP versions...\")
    
    # Build debug version
    debug_content = build_debug_version()
    with open(\"pea-mcp-debug.py\", \"w\") as f:
        f.write(debug_content)
    print(\"✅ Built: pea-mcp-debug.py\")
    
    # Build visual version
    visual_content = build_visual_version()
    with open(\"pea-mcp-visual.py\", \"w\") as f:
        f.write(visual_content)
    print(\"✅ Built: pea-mcp-visual.py\")
    
    print(\"\\\
🚀 Ready to deploy!\")
    print(\"   pea-mcp-debug.py  - For debugging/troubleshooting\")
    print(\"   pea-mcp-visual.py - For cyberpunk styling\")

if __name__ == \"__main__\":
    main()`
}
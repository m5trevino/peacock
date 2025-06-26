{
  `title`: `pea-mcp.py - MODULAR DISPLAY VERSION`,
  `folder`: `peacock-core`,
  `content`: `# 🦚 PEA-MCP.PY - MODULAR DISPLAY SYSTEM
# Clean pea-mcp.py that can use either DEBUG or VISUAL blocks
# ================================================================================

#!/usr/bin/env python3
\"\"\"
Peacock MCP Server - Modular Display Version
Supports both DEBUG and VISUAL display modes via swappable blocks
\"\"\"

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

# ================================================================================
# DISPLAY BLOCK INSERTION POINT - PASTE DEBUG OR VISUAL BLOCK HERE
# ================================================================================

# PLACEHOLDER FUNCTIONS - REPLACE THESE WITH DEBUG OR VISUAL BLOCKS
def display_init():
    print(\"[PLACEHOLDER] Peacock MCP Server Starting...\")

def display_config():
    print(f\"[PLACEHOLDER] Primary Model: {PEACOCK_MODEL_STRATEGY['primary_model']}\")
    print(f\"[PLACEHOLDER] Session: {SESSION_TIMESTAMP}\")
    print(f\"[PLACEHOLDER] Logging: {'Enabled' if LOGGING_ENABLED else 'Disabled'}\")

def display_server_start():
    print(f\"[PLACEHOLDER] MCP: Server started on {HOST}:{PORT}\")

def display_birds_loaded():
    print(\"[PLACEHOLDER] BIRDS: All bird modules loaded successfully\")

def display_commands():
    print(\"[PLACEHOLDER] Commands: peacock_full, deploy_pcock, xedit_fix\")

def display_processing_start(command):
    print(f\"[PLACEHOLDER] Processing command: {command}\")

def display_orchestration_start():
    print(\"[PLACEHOLDER] Starting OUT-HOMING orchestration\")

def display_session_info():
    print(f\"[PLACEHOLDER] Session: {SESSION_TIMESTAMP}\")
    print(f\"[PLACEHOLDER] API Keys: {len(BIRD_API_KEYS)} available\")

def display_stage_start(stage_name, message):
    print(f\"[PLACEHOLDER] STAGE: {stage_name} - {message}\")

def display_stage_progress(stage_name, message):
    print(f\"[PLACEHOLDER] {stage_name} - {message}\")

def display_stage_result(stage_name, success, char_count=0, model=\"\", key_hint=\"\"):
    status = \"SUCCESS\" if success else \"FAILED\"
    print(f\"[PLACEHOLDER] {stage_name} - {status} - {char_count} chars - {model} - Key: {key_hint}\")

def display_separator():
    print(\"-\" * 50)

def display_character_summary(stage_results):
    print(\"[PLACEHOLDER] STAGE CHARACTER COUNTS:\")
    for stage_name, stage_data in stage_results.items():
        char_count = stage_data.get(\"char_count\", 0)
        model = stage_data.get(\"model\", \"unknown\")
        print(f\"[PLACEHOLDER] {stage_name.upper()}: {char_count} chars {model}\")

def display_request_log(method, path, status):
    timestamp = datetime.datetime.now().strftime(\"%H:%M:%S\")
    print(f\"[PLACEHOLDER] [{timestamp}] \\\"{method} {path} HTTP/1.1\\\" {status} -\")

def display_completion(success, command):
    status = \"SUCCESS\" if success else \"FAILED\"
    print(f\"[PLACEHOLDER] {status}: Command {command} completed\")

# ================================================================================
# END DISPLAY BLOCK INSERTION POINT
# ================================================================================

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
            print(\"\
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
        print(\"\
Shutting down Peacock MCP Server...\")
        server.shutdown()

if __name__ == \"__main__\":
    main()

# ================================================================================
# USAGE INSTRUCTIONS:
# 
# 1. For DEBUG mode:
#    - Delete the PLACEHOLDER functions (lines after \"DISPLAY BLOCK INSERTION POINT\")
#    - Paste the DEBUG BLOCK from the debug note
#    - Replace display_* calls with debug_* calls
#
# 2. For VISUAL mode:
#    - Delete the PLACEHOLDER functions  
#    - Paste the VISUAL BLOCK from the styling note
#    - Replace display_* calls with show_* calls
#
# 3. The core server logic remains unchanged
# ================================================================================`
}
Response

# Created note
file_path: peacock-core/pea-mcp.py - MODULAR DISPLAY VERSION.md
permalink: peacock-core/pea-mcp-py-modular-display-version
checksum: a743fc25

## Observations
- note: 1
Bet! There's your modular pea-mcp.py, big dawg. Here's how t
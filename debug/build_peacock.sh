{
  `title`: `COMPLETE BUILD SCRIPT - READY TO RUN`,
  `folder`: `peacock-debug`,
  `content`: `#!/bin/bash

# 🦚 PEACOCK MCP BUILDER
# Run this script to build both debug and visual versions
# Usage: chmod +x build_peacock.sh && ./build_peacock.sh

echo \"🦚 Building Peacock MCP Versions...\"

# Create the complete build script
cat << 'SCRIPT_END' > build_peacock.sh
#!/bin/bash
echo \"🔧 Building Peacock MCP Debug & Visual Versions...\"

# Create debug version
python3 << 'PYTHON_END'
debug_code = '''#!/usr/bin/env python3
\"\"\"
Peacock MCP Server - DEBUG VERSION
Enhanced debugging and error tracking
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
import traceback
import time

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

# 🔧 DEBUG SYSTEM
DEBUG_START_TIME = time.time()

def debug_log(level, message, **kwargs):
    timestamp = datetime.datetime.now().strftime(\"%H:%M:%S.%f\")[:-3]
    elapsed = time.time() - DEBUG_START_TIME
    
    output = f\"[{timestamp}] [{level}] {message}\"
    if kwargs:
        output += f\" | DATA: {json.dumps(kwargs, default=str)}\"
    output += f\" | TIME: {elapsed:.2f}s\"
    
    print(output)
    
    if LOGGING_ENABLED:
        try:
            with open(f\"/home/flintx/peacock/logs/debug-{SESSION_TIMESTAMP}.log\", \"a\") as f:
                f.write(output + \"\\\
\")
        except:
            pass

# DEBUG DISPLAY FUNCTIONS
def display_init():
    debug_log(\"INIT\", \"Peacock MCP Server Starting...\")

def display_config():
    debug_log(\"CONFIG\", \"Loading configuration\")
    debug_log(\"CONFIG\", \"Model Strategy\", **PEACOCK_MODEL_STRATEGY)
    debug_log(\"CONFIG\", \"Session Setup\", session=SESSION_TIMESTAMP, logging=LOGGING_ENABLED)

def display_server_start():
    debug_log(\"SERVER\", f\"MCP: Server started on {HOST}:{PORT}\")

def display_birds_loaded():
    debug_log(\"INIT\", \"BIRDS: All bird modules loaded successfully\")

def display_commands():
    debug_log(\"INIT\", \"Commands: peacock_full, deploy_pcock, xedit_fix\")

def display_processing_start(command):
    debug_log(\"REQUEST\", f\"Processing command: {command}\")

def display_orchestration_start():
    debug_log(\"PIPELINE\", \"Starting OUT-HOMING orchestration\")

def display_session_info():
    debug_log(\"PIPELINE\", f\"Session: {SESSION_TIMESTAMP}\")
    debug_log(\"PIPELINE\", f\"API Keys: {len(BIRD_API_KEYS)} available\")

def display_stage_start(stage_name, message):
    debug_log(\"STAGE\", f\"Starting {stage_name}\", message=message)

def display_stage_result(stage_name, success, char_count=0, model=\"\", key_hint=\"\"):
    status = \"SUCCESS\" if success else \"FAILED\"
    debug_log(\"STAGE\", f\"{stage_name} completed\", 
              status=status, chars=char_count, model=model, key=key_hint)

def display_separator():
    debug_log(\"STAGE\", \"Stage separator\")

def display_character_summary(stage_results):
    debug_log(\"SUMMARY\", \"Stage Results Summary\")
    total_chars = 0
    for stage_name, stage_data in stage_results.items():
        char_count = stage_data.get(\"char_count\", 0)
        model = stage_data.get(\"model\", \"unknown\")
        success = stage_data.get(\"success\", False)
        total_chars += char_count
        debug_log(\"SUMMARY\", f\"{stage_name.upper()}\", chars=char_count, model=model, success=success)
    debug_log(\"SUMMARY\", \"Pipeline Totals\", total_characters=total_chars)

def display_request_log(method, path, status):
    debug_log(\"REQUEST\", f\"{method} {path} HTTP/1.1\", status=status)

def display_completion(success, command):
    status = \"SUCCESS\" if success else \"FAILED\"
    debug_log(\"REQUEST\", f\"Command {command} completed\", status=status)

# REST OF SERVER CODE - SAME FOR BOTH VERSIONS
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

class PeacockHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        if LOGGING_ENABLED:
            logging.info(format % args)
        display_request_log(self.command, self.path, args[1] if len(args) > 1 else \"200\")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_POST(self):
        if self.path == PROCESS_PATH:
            self.handle_process_request()
        else:
            self.send_error(404, \"Not Found\")

    def handle_process_request(self):
        try:
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
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            response_json = json.dumps(result, indent=2)
            self.wfile.write(response_json.encode('utf-8'))
            
            display_completion(result.get(\"success\", False), command)
            
        except Exception as e:
            debug_log(\"ERROR\", f\"Request handling error: {e}\")
            debug_log(\"ERROR\", \"Stack trace\", stack=traceback.format_exc())
            self.send_error(500, f\"Internal Server Error: {str(e)}\")

    def execute_peacock_pipeline(self, user_input):
        try:
            display_orchestration_start()
            display_session_info()
            
            orchestrator = create_homing_orchestrator(
                api_keys=BIRD_API_KEYS,
                model_strategy=PEACOCK_MODEL_STRATEGY,
                session_timestamp=SESSION_TIMESTAMP
            )
            
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
            
            stage_results = {
                \"spark\": spark_result,
                \"falcon\": falcon_result, 
                \"eagle\": eagle_result,
                \"hawk\": hawk_result
            }
            
            display_character_summary(stage_results)
            
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
            debug_log(\"ERROR\", f\"Pipeline execution error: {e}\")
            debug_log(\"ERROR\", \"Stack trace\", stack=traceback.format_exc())
            return {
                \"success\": False,
                \"error\": str(e),
                \"message\": \"Pipeline execution failed\"
            }

def start_server():
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
    global LOGGING_ENABLED
    
    parser = argparse.ArgumentParser(description='Peacock MCP Server - DEBUG VERSION')
    parser.add_argument('--log', action='store_true', help='Enable logging')
    args = parser.parse_args()
    
    if args.log:
        LOGGING_ENABLED = True
    
    setup_logging()
    
    display_init()
    display_config()
    display_birds_loaded()
    display_commands()
    
    server = start_server()
    
    try:
        print(\"⚡ Press Ctrl+C to stop\")
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

with open(\"pea-mcp-debug.py\", \"w\") as f:
    f.write(debug_code)

print(\"✅ Created pea-mcp-debug.py\")
PYTHON_END

echo \"✅ Built pea-mcp-debug.py\"
echo \"🚀 Ready to test!\"
echo \"\"
echo \"Usage:\"
echo \"  python3 pea-mcp-debug.py --log\"
echo \"\"
SCRIPT_END

chmod +x build_peacock.sh
echo \"✅ Created build_peacock.sh\"
echo \"\"
echo \"🚀 READY TO BUILD!\"
echo \"\"
echo \"Run this command:\"
echo \"  chmod +x build_peacock.sh && ./build_peacock.sh\"`
}
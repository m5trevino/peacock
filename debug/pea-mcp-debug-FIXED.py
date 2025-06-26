#!/usr/bin/env python3
"""
Peacock MCP Server - DEBUG VERSION (FIXED)
Clean debug output for troubleshooting
"""

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
import time

# Add aviary to path for bird imports
sys.path.append(str(Path(__file__).parent.parent / "aviary"))
from out_homing import OutHomingOrchestrator

# --- CORE CONFIGURATION ---
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

# 🔧 DEBUG DISPLAY SYSTEM
START_TIME = time.time()

def debug_log(level, message, **data):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    elapsed = time.time() - START_TIME
    
    log_line = f"[{timestamp}] [{level}] {message}"
    if data:
        log_line += f" | {data}"
    log_line += f" | +{elapsed:.1f}s"
    
    print(log_line)

def display_init():
    debug_log("INIT", "Peacock MCP Server Starting")

def display_config():
    debug_log("CONFIG", "Configuration loaded", model=PEACOCK_MODEL_STRATEGY['primary_model'])

def display_server_start():
    debug_log("SERVER", f"Server started on {HOST}:{PORT}")

def display_birds_loaded():
    debug_log("INIT", "All bird modules loaded successfully")

def display_commands():
    debug_log("INIT", "Available commands: peacock_full, deploy_pcock, xedit_fix")

def display_processing_start(command):
    debug_log("REQUEST", f"Processing command: {command}")

def display_orchestration_start():
    debug_log("PIPELINE", "Starting OUT-HOMING orchestration")

def display_session_info():
    debug_log("PIPELINE", f"Session {SESSION_TIMESTAMP} with {len(BIRD_API_KEYS)} API keys")

def display_separator():
    debug_log("STAGE", "=== EXECUTING FULL 4-BIRD PIPELINE ===")

def display_character_summary(stage_results):
    debug_log("SUMMARY", "CHARACTER COUNT RESULTS:")
    total = 0
    for stage, data in stage_results.items():
        chars = data.get("char_count", 0)
        model = data.get("model", "unknown")
        success = data.get("success", False)
        total += chars
        debug_log("SUMMARY", f"  {stage.upper()}: {chars} chars, model: {model}, success: {success}")
    debug_log("SUMMARY", f"TOTAL CHARACTERS: {total}")

def display_request_log(method, path, status):
    debug_log("HTTP", f"{method} {path} -> {status}")

def display_completion(success, command):
    status = "COMPLETED" if success else "FAILED"
    debug_log("REQUEST", f"Command {command} {status}")

# LOGGING SETUP
def setup_logging():
    """Setup logging configuration"""
    global LOGGING_ENABLED
    
    if LOGGING_ENABLED:
        log_dir = Path(__file__).parent.parent / "logs"
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / f"mcplog-{SESSION_TIMESTAMP}.txt"
        
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
        """Override to use our display system"""
        if LOGGING_ENABLED:
            logging.info(format % args)
        display_request_log(self.command, self.path, args[1] if len(args) > 1 else "200")

    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_POST(self):
        """Handle POST requests"""
        if self.path == PROCESS_PATH:
            self.handle_process_request()
        else:
            self.send_error(404, "Not Found")

    def handle_process_request(self):
        """Handle the main process request"""
        try:
            # Parse request body
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            request_data = json.loads(post_data.decode('utf-8'))
            
            user_input = request_data.get('input', '')
            command = request_data.get('command', 'peacock_full')
            
            display_processing_start(command)
            
            if command == "peacock_full":
                result = self.execute_peacock_pipeline(user_input)
            else:
                result = {"success": False, "message": f"Unknown command: {command}"}
            
            # Send response
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            response_json = json.dumps(result, indent=2)
            self.wfile.write(response_json.encode('utf-8'))
            
            display_completion(result.get("success", False), command)
            
        except Exception as e:
            debug_log("ERROR", f"Request handling error: {e}")
            self.send_error(500, f"Internal Server Error: {str(e)}")
            logging.error(f"Request handling error: {e}")

    def execute_peacock_pipeline(self, user_input):
        """Execute the full peacock pipeline using OutHomingOrchestrator"""
        try:
            display_orchestration_start()
            display_session_info()
            display_separator()
            
            # Create the orchestrator (class-based, not function)
            debug_log("PIPELINE", "Creating OutHomingOrchestrator instance")
            orchestrator = OutHomingOrchestrator()
            
            # Execute the ENTIRE pipeline in ONE call
            debug_log("PIPELINE", "Executing orchestrate_full_pipeline...")
            result = orchestrator.orchestrate_full_pipeline(user_input)
            
            # Display results
            if result.get("success"):
                stage_results = result.get("stage_results", {})
                display_character_summary(stage_results)
                debug_log("PIPELINE", "Pipeline completed successfully!")
            else:
                debug_log("ERROR", f"Pipeline failed: {result.get('error', 'Unknown error')}")
            
            return result
            
        except Exception as e:
            debug_log("ERROR", f"Pipeline execution error: {e}")
            logging.error(f"Pipeline execution error: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": "Pipeline execution failed"
            }

def start_server():
    """Start the HTTP server"""
    display_server_start()
    
    server = HTTPServer((HOST, PORT), PeacockHandler)
    
    def run_server():
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server...")
            server.shutdown()
    
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    
    return server

def main():
    """Main server function"""
    global LOGGING_ENABLED
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Peacock MCP Server - DEBUG VERSION (FIXED)')
    parser.add_argument('--log', action='store_true', help='Enable logging')
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
        print("⚡ Press Ctrl+C to stop")
        
        # Keep main thread alive
        while True:
            import time
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nShutting down Peacock MCP Server...")
        server.shutdown()

if __name__ == "__main__":
    main()

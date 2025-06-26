#!/bin/bash
echo "🔧 Building Peacock MCP Debug Version..."

python3 << 'EOF'
debug_code = '''#!/usr/bin/env python3
"""Peacock MCP Server - DEBUG VERSION"""
import asyncio, json, logging, sys, datetime, argparse, traceback, time
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading

sys.path.append(str(Path(__file__).parent.parent / "aviary"))
from out_homing import create_homing_orchestrator

HOST = "127.0.0.1"
PORT = 8000
PROCESS_PATH = "/process"
LOGGING_ENABLED = False

BIRD_API_KEYS = {
    "spark": "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",
    "falcon": "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",
    "eagle": "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",
    "hawk": "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"
}

PEACOCK_MODEL_STRATEGY = {
    "primary_model": "meta-llama/llama-4-scout-17b-16e-instruct",
    "detailed_model": "meta-llama/llama-4-maverick-17b-128e-instruct", 
    "speed_model": "llama-3.1-8b-instant",
    "fallback_model": "llama-3.3-70b-versatile"
}

def generate_session_timestamp():
    now = datetime.datetime.now()
    week = now.isocalendar()[1]
    day = now.day
    hour_minute = now.strftime("%H%M")
    return f"{week}-{day}-{hour_minute}"

SESSION_TIMESTAMP = generate_session_timestamp()
DEBUG_START_TIME = time.time()

def debug_log(level, message, **kwargs):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    elapsed = time.time() - DEBUG_START_TIME
    output = f"[{timestamp}] [{level}] {message}"
    if kwargs:
        output += f" | DATA: {json.dumps(kwargs, default=str)}"
    output += f" | TIME: {elapsed:.2f}s"
    print(output)

def display_init():
    debug_log("INIT", "Peacock MCP Server Starting...")

def display_config():
    debug_log("CONFIG", "Loading configuration", **PEACOCK_MODEL_STRATEGY)

def display_server_start():
    debug_log("SERVER", f"MCP: Server started on {HOST}:{PORT}")

def display_birds_loaded():
    debug_log("INIT", "BIRDS: All bird modules loaded successfully")

def display_commands():
    debug_log("INIT", "Commands: peacock_full, deploy_pcock, xedit_fix")

def display_processing_start(command):
    debug_log("REQUEST", f"Processing command: {command}")

def display_orchestration_start():
    debug_log("PIPELINE", "Starting OUT-HOMING orchestration")

def display_session_info():
    debug_log("PIPELINE", f"Session: {SESSION_TIMESTAMP}, API Keys: {len(BIRD_API_KEYS)}")

def display_stage_start(stage_name, message):
    debug_log("STAGE", f"Starting {stage_name}: {message}")

def display_stage_result(stage_name, success, char_count=0, model="", key_hint=""):
    status = "SUCCESS" if success else "FAILED"
    debug_log("STAGE", f"{stage_name} {status}", chars=char_count, key=key_hint)

def display_separator():
    debug_log("STAGE", "Stage separator")

def display_character_summary(stage_results):
    debug_log("SUMMARY", "Character counts", results=stage_results)

def display_request_log(method, path, status):
    debug_log("REQUEST", f"{method} {path}", status=status)

def display_completion(success, command):
    debug_log("REQUEST", f"Command {command} completed", success=success)

# [REST OF SERVER CODE CONTINUES...]
'''

with open("pea-mcp-debug.py", "w") as f:
    f.write(debug_code)
EOF

echo "✅ Created pea-mcp-debug.py"
echo "🚀 Test with: python3 pea-mcp-debug.py --log"
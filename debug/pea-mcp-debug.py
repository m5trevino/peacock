#!/usr/bin/env python3

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

# 🔧 DEBUG BLOCK - ENHANCED DEBUGGING SYSTEM
import traceback
import inspect
import time
try:
    import psutil
except ImportError:
    print(\"[WARNING] psutil not installed - memory tracking disabled\")
    psutil = None

# DEBUG CONFIGURATION
DEBUG_CONFIG = {
    \"verbose\": True,
    \"show_memory\": True if psutil else False,
    \"show_timing\": True,
    \"log_to_file\": True,
    \"debug_level\": \"STANDARD\"  # MINIMAL, STANDARD, FULL
}

class DebugLogger:
    def __init__(self):
        self.start_time = time.time()
        self.stage_timings = {}
        if ps`
}
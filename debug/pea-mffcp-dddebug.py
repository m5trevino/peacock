{
  `title`: `DEBUG BLOCK - FULL DEBUGGING SYSTEM`,
  `folder`: `peacock-debug`,
  `content`: `# 🔧 DEBUG BLOCK - ENHANCED DEBUGGING SYSTEM
# This entire block can be removed when plugging back in visuals
# START DEBUG BLOCK - SAFE TO DELETE
# ================================================================================

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
                f.write(output + \"\
\")
    
    def start_timer(self, name):
        self.stage_timings[name] = time.time()
        self.log(\"TIMER\", f\"Started timer: {name}\")
    
    def end_timer(self, name):
        if name in self.stage_timings:
            elapsed = time.time() - self.stage_timings[name]
            self.log(\"TIMER\", f\"Ended timer: {name}\", elapsed_seconds=elapsed)
            return elapsed
        return 0
    
    def function_entry(self, func_name, args=None, kwargs=None):
        if DEBUG_CONFIG[\"show_function_calls\"]:
            caller = inspect.stack()[1].function
            self.log(\"FUNC\", f\"ENTER: {func_name}() called from {caller}()\", 
                    args=args, kwargs=kwargs)
    
    def function_exit(self, func_name, result=None, error=None):
        if DEBUG_CONFIG[\"show_function_calls\"]:
            if error:
                self.log(\"FUNC\", f\"EXIT: {func_name}() with ERROR\", error=str(error))
            else:
                self.log(\"FUNC\", f\"EXIT: {func_name}() success\", result_type=type(result).__name__)

# Global debug logger
debug = DebugLogger()

def debug_init():
    debug.log(\"INIT\", \"Peacock MCP Server Starting...\")
    debug.log(\"INIT\", \"System Info\", 
              cpu_count=psutil.cpu_count(),
              memory_total=f\"{psutil.virtual_memory().total / 1024**3:.1f}GB\",
              python_version=sys.version.split()[0])

def debug_config():
    debug.log(\"CONFIG\", \"Loading configuration\")
    debug.log(\"CONFIG\", \"Model Strategy\", **PEACOCK_MODEL_STRATEGY)
    debug.log(\"CONFIG\", \"Session Setup\", 
              session=SESSION_TIMESTAMP,
              logging_enabled=LOGGING_ENABLED,
              api_keys_count=len(BIRD_API_KEYS))
    debug.log(\"CONFIG\", \"Debug Settings\", **DEBUG_CONFIG)

def debug_server_start(host, port):
    debug.log(\"SERVER\", f\"Starting server on {host}:{port}\")
    debug.log(\"SERVER\", \"Checking port availability\")
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            debug.log(\"SERVER\", \"WARNING: Port already in use!\", port=port)
        else:
            debug.log(\"SERVER\", \"Port available\", port=port)
    except Exception as e:
        debug.log(\"SERVER\", \"Port check failed\", error=str(e))

def debug_request_start(method, path, headers=None):
    debug.start_timer(f\"request_{path}\")
    debug.log(\"REQUEST\", f\"Incoming: {method} {path}\")
    if headers and DEBUG_CONFIG[\"verbose\"]:
        debug.log(\"REQUEST\", \"Headers\", headers=dict(headers))

def debug_request_end(method, path, status_code, response_size=0):
    timer_name = f\"request_{path}\"
    elapsed = debug.end_timer(timer_name)
    debug.log(\"REQUEST\", f\"Completed: {method} {path}\", 
              status=status_code, 
              response_bytes=response_size,
              elapsed_ms=f\"{elapsed*1000:.1f}ms\")

def debug_pipeline_start(user_input):
    debug.log(\"PIPELINE\", \"Starting bird orchestration\")
    debug.start_timer(\"full_pipeline\")
    debug.log(\"PIPELINE\", \"User Input\", 
              input_length=len(user_input),
              input_preview=user_input[:100] + \"...\" if len(user_input) > 100 else user_input)

def debug_stage_start(stage_name, stage_data=None):
    debug.start_timer(f\"stage_{stage_name}\")
    debug.log(\"STAGE\", f\"Starting {stage_name.upper()}\")
    if stage_data and DEBUG_CONFIG[\"verbose\"]:
        debug.log(\"STAGE\", f\"{stage_name} config\", **stage_data)

def debug_stage_prompt(stage_name, prompt, char_count):
    debug.log(\"STAGE\", f\"{stage_name} prompt generated\", char_count=char_count)
    if DEBUG_CONFIG[\"debug_level\"] == \"FULL\":
        debug.log(\"STAGE\", f\"{stage_name} prompt content\", 
                  prompt_preview=prompt[:200] + \"...\" if len(prompt) > 200 else prompt)

def debug_api_call_start(stage_name, model, api_key_hint, attempt):
    debug.start_timer(f\"api_{stage_name}_attempt_{attempt}\")
    debug.log(\"API\", f\"{stage_name} API call starting\", 
              model=model, 
              key_hint=api_key_hint[-8:] if api_key_hint else \"none\",
              attempt=attempt)

def debug_api_call_end(stage_name, success, response_chars=0, error=None, attempt=1):
    timer_name = f\"api_{stage_name}_attempt_{attempt}\"
    elapsed = debug.end_timer(timer_name)
    
    if success:
        debug.log(\"API\", f\"{stage_name} API call SUCCESS\", 
                  response_chars=response_chars,
                  elapsed_ms=f\"{elapsed*1000:.1f}ms\")
    else:
        debug.log(\"API\", f\"{stage_name} API call FAILED\", 
                  error=str(error),
                  elapsed_ms=f\"{elapsed*1000:.1f}ms\")

def debug_stage_end(stage_name, success, result_data=None):
    timer_name = f\"stage_{stage_name}\"
    elapsed = debug.end_timer(timer_name)
    
    if success:
        debug.log(\"STAGE\", f\"{stage_name.upper()} completed\", 
                  elapsed_seconds=f\"{elapsed:.2f}s\")
        if result_data and DEBUG_CONFIG[\"verbose\"]:
            debug.log(\"STAGE\", f\"{stage_name} results\", **result_data)
    else:
        debug.log(\"STAGE\", f\"{stage_name.upper()} FAILED\", 
                  elapsed_seconds=f\"{elapsed:.2f}s\")

def debug_pipeline_end(success, stage_results=None):
    elapsed = debug.end_timer(\"full_pipeline\")
    
    if success:
        debug.log(\"PIPELINE\", \"Pipeline completed successfully\", 
                  total_elapsed=f\"{elapsed:.2f}s\")
    else:
        debug.log(\"PIPELINE\", \"Pipeline FAILED\", 
                  total_elapsed=f\"{elapsed:.2f}s\")

def debug_summary(stage_results):
    debug.log(\"SUMMARY\", \"Stage Results Summary\")
    total_chars = 0
    
    for stage_name, stage_data in stage_results.items():
        char_count = stage_data.get(\"char_count\", 0)
        model = stage_data.get(\"model\", \"unknown\")
        success = stage_data.get(\"success\", False)
        total_chars += char_count
        
        debug.log(\"SUMMARY\", f\"{stage_name.upper()}\", 
                  chars=char_count,
                  model=model,
                  success=success)
    
    debug.log(\"SUMMARY\", \"Pipeline Totals\", 
              total_characters=total_chars,
              stages_completed=len(stage_results),
              api_calls_made=sum(1 for s in stage_results.values() if s.get(\"success\")))

def debug_error(location, error, context=None):
    debug.log(\"ERROR\", f\"Exception in {location}\", 
              error_type=type(error).__name__,
              error_message=str(error))
    
    if DEBUG_CONFIG[\"show_stack\"]:
        debug.log(\"ERROR\", \"Stack trace\", stack=traceback.format_exc())
    
    if context:
        debug.log(\"ERROR\", \"Error context\", **context)

def debug_file_operation(operation, file_path, success, details=None):
    debug.log(\"FILE\", f\"{operation}: {file_path}\", 
              success=success,
              details=details)

def debug_memory_check(location):
    process = psutil.Process()
    memory_info = process.memory_info()
    debug.log(\"MEMORY\", f\"Memory check at {location}\",
              rss_mb=f\"{memory_info.rss / 1024 / 1024:.1f}MB\",
              vms_mb=f\"{memory_info.vms / 1024 / 1024:.1f}MB\",
              percent=f\"{process.memory_percent():.1f}%\")

def debug_toggle_level(level):
    \"\"\"Toggle debug level: MINIMAL, STANDARD, FULL\"\"\"
    old_level = DEBUG_CONFIG[\"debug_level\"]
    DEBUG_CONFIG[\"debug_level\"] = level
    debug.log(\"DEBUG\", f\"Debug level changed: {old_level} -> {level}\")
    
    if level == \"MINIMAL\":
        DEBUG_CONFIG.update({
            \"verbose\": False,
            \"show_stack\": False,
            \"show_memory\": False,
            \"show_function_calls\": False
        })
    elif level == \"STANDARD\":
        DEBUG_CONFIG.update({
            \"verbose\": True,
            \"show_stack\": False,
            \"show_memory\": True,
            \"show_function_calls\": False
        })
    elif level == \"FULL\":
        DEBUG_CONFIG.update({
            \"verbose\": True,
            \"show_stack\": True,
            \"show_memory\": True,
            \"show_function_calls\": True
        })

def debug_status():
    \"\"\"Show current debug status\"\"\"
    debug.log(\"STATUS\", \"Debug Configuration\", **DEBUG_CONFIG)
    debug_memory_check(\"status_check\")

# Function call decorator for automatic entry/exit logging
def debug_trace(func):
    def wrapper(*args, **kwargs):
        debug.function_entry(func.__name__, args, kwargs)
        try:
            result = func(*args, **kwargs)
            debug.function_exit(func.__name__, result)
            return result
        except Exception as e:
            debug.function_exit(func.__name__, error=e)
            raise
    return wrapper

# END DEBUG BLOCK - SAFE TO DELETE
# ================================================================================`
}
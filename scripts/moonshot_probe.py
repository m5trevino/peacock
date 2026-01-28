import os
import json
import time
from groq import Groq

# --- CONFIG ---
MODEL = "moonshotai/kimi-k2-instruct-0905"
LOG_FILE = "moonshot_probe_raw.log"
ENV_PATH = "/home/flintx/ai-handler/.env"

def get_api_key():
    try:
        if not os.path.exists(ENV_PATH):
            return None
        with open(ENV_PATH, "r") as f:
            for line in f:
                if line.startswith("GROQ_KEYS="):
                    raw = line.strip().split("=", 1)[1]
                    # Key format: label:key1,label:key2
                    first_entry = raw.split(",")[0]
                    if ":" in first_entry:
                        return first_entry.split(":")[1]
                    return first_entry
    except Exception as e:
        print(f"Error reading .env: {e}")
    return None

KEY = get_api_key()
if not KEY:
    print(f"FATAL: Could not find GROQ_KEYS in {ENV_PATH}")
    # Fallback to local .env just in case
    KEY = os.getenv("GROQ_API_KEY")
    if not KEY:
        exit(1)

client = Groq(api_key=KEY)

def log(header, content):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    entry = f"\n{'='*80}\n[{timestamp}] {header}\n{'='*80}\n{content}\n"
    print(entry)
    with open(LOG_FILE, "a") as f:
        f.write(entry)

def run_test(name, messages, **kwargs):
    print(f"Running Test: {name}...")
    try:
        start = time.time()
        completion = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            **kwargs
        )
        duration = time.time() - start
        
        content = completion.choices[0].message.content
        log(f"TEST: {name} (Duration: {duration:.2f}s)", f"PROMPT SUMMARY: {messages[-1]['content'][:100]}...\nPARAMS: {kwargs}\n\nRAW_OUTPUT:\n{content}")
        return content
    except Exception as e:
        log(f"TEST FAILED: {name}", f"ERROR: {str(e)}")
        return None

# --- MISSION SCENARIOS ---

# 1. EAGLE SKELETON PROBE
# We want to see how it formats the "directives" and "skeletons" it hands to OWL.
EAGLE_CONTEXT = """
SYSTEM: Act as EAGLE. Output a file tree and skeleton code for a 'Vite/React/Tailwind' dashboard.
USER: Create a project named 'Peacock HUD'.
"""
run_test("EAGLE_SKELETON_RAW", 
    [{"role": "user", "content": EAGLE_CONTEXT}],
    temperature=0.3
)

# 2. OWL JSON ENFORCEMENT PROBE
# Testing the strict JSON schema for individual files.
OWL_JSON_PROMPT = """
SYSTEM: Act as OWL. Output ONLY valid JSON.
SCHEMA: {"path": "src/App.tsx", "code": "PURE_STRING_CODE"}
USER: Flesh out a React App component with a basic HUD layout.
"""
run_test("OWL_JSON_STRICT",
    [{"role": "user", "content": OWL_JSON_PROMPT}],
    response_format={"type": "json_object"},
    temperature=0.1
)

# 3. OWL RAW EOF PROBE (No JSON)
# Seeing if it behaves when asked for direct EOF blocks.
OWL_EOF_PROMPT = """
SYSTEM: Act as OWL. 
TASK: Output a bash EOF block to create 'src/App.tsx'.
FORMAT:
cat << 'PEACOCK_EOF' > src/App.tsx
[CODE]
PEACOCK_EOF
"""
run_test("OWL_RAW_EOF_BEHAVIOR",
    [{"role": "user", "content": OWL_EOF_PROMPT}],
    temperature=0.3
)

# 4. PROJECT_NAME EXTRACTION PROBE
# Testing how it reacts to messy Spark inputs.
SPARK_INPUT = """
# Mission: Ghost Stream HUD
# Author: Trevino
Architecture: Persistent CLI background...
"""
run_test("PROJECT_NAME_EXTRACTION",
    [{"role": "user", "content": f"Extract a clean, sanitized linux directory name from this input. Output ONLY the name:\n\n{SPARK_INPUT}"}],
    temperature=0.1
)

print(f"\nPROBE COMPLETE. RESULTS SAVED TO: {os.path.abspath(LOG_FILE)}")

import os
import json
import time
from groq import Groq

# --- TACTICAL CONFIG ---
MODEL = "moonshotai/kimi-k2-instruct-0905"
LOG_FILE = "owl_batch_raw.log"

def get_api_key():
    try:
        if os.path.exists(".env"):
            with open(".env", "r") as f:
                for line in f:
                    if "GROQ_KEYS=" in line:
                        raw = line.strip().split("=", 1)[1]
                        first_entry = raw.split(",")[0]
                        return first_entry.split(":")[1] if ":" in first_entry else first_entry
        return os.getenv("GROQ_API_KEY")
    except Exception as e:
        print(f"Error reading keys: {e}")
        return None

KEY = get_api_key()
if not KEY:
    print("FATAL: No API Key found in .env or environment.")
    exit(1)

client = Groq(api_key=KEY)

def run_batch_probe():
    print(f"[*] Initializing Multi-File Probe on {MODEL}...")
    
    # Mock Eagle-to-Owl handoff - 3 files to test connective tissue
    test_files = [
        {
            "path": "src/utils/logger.ts",
            "skeleton": "export const log = (msg: string) => { // TODO }",
            "directives": "Implement with timestamp, color coding, and log levels (info, warn, error)."
        },
        {
            "path": "src/components/Button.tsx",
            "skeleton": "export const Button = () => <button>Click</button>",
            "directives": "Add Tailwind hover effects, loading state, disabled prop, and generic onClick handler."
        },
        {
            "path": "config/settings.json",
            "skeleton": "{}",
            "directives": "Add default production API endpoints, env-based toggles, and theme config."
        }
    ]

    prompt = f"""
ACT AS "OWL", THE OPTIMIZER.
Refine the following files into complete, production-ready code.

YOU MUST USE THIS EXACT DELIMITER SYSTEM FOR EVERY FILE - NO EXCEPTIONS:

[[START_FILE:exact/path/here]]
[Full refined code here - no markdown, no extra text]
[[END_FILE:exact/path/here]]

Do not add explanations, headers, or any text outside the delimiters.
Do not use ``` code blocks or any markdown.
Output only the delimited files, nothing else.

FILES TO REFINE:
{json.dumps(test_files, indent=2)}
"""

    try:
        print("[*] Striking API...")
        start_time = time.time()
        completion = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=4096
        )
        duration = time.time() - start_time
        raw_output = completion.choices[0].message.content

        with open(LOG_FILE, "w") as f:
            f.write(f"PROBE METRICS\n")
            f.write(f"MODEL: {MODEL}\n")
            f.write(f"LATENCY: {duration:.2f}s\n")
            f.write(f"USAGE: {completion.usage}\n")
            f.write("="*80 + "\n")
            f.write("RAW OUTPUT BEGINS BELOW\n")
            f.write("="*80 + "\n")
            f.write(raw_output)
        
        print(f"[+] Intelligence Secured: {LOG_FILE}")
        print(f"[*] Latency: {duration:.2f}s")
        
    except Exception as e:
        print(f"[!] STRIKE FAILED: {str(e)}")

if __name__ == "__main__":
    run_batch_probe()

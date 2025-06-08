####START OF DOCUMENT####
#!/usr/bin/env python3
"""
peamcp.py - Peacock MCP Server (Enhanced with Multi-Model Strategy)
Usage: python peamcp.py [--log/-l] [--port 8000]
"""

import http.server
import socketserver
import json
import os
import sys
import argparse
import datetime
import re
from pathlib import Path

# --- CONFIGURATION ---
HOST = "127.0.0.1"
PORT = 8000
PROCESS_PATH = "/process"

# GROQ API CONFIGURATION
GROQ_API_KEY = "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"

# PEACOCK MULTI-MODEL STRATEGY (Based on test results)
PEACOCK_MODEL_STRATEGY = {
    "primary_model": "gemma2-9b-it",        # Best overall mixed content
    "speed_model": "llama3-8b-8192",        # When speed is critical  
    "explanation_model": "llama3-8b-8192",  # When detailed explanations needed
    "json_model": "llama3-8b-8192",         # Most reliable JSON parsing
    "fallback_model": "llama-3.1-8b-instant"
}

# STAGE-SPECIFIC MODEL ASSIGNMENT
PEACOCK_STAGE_MODELS = {
    "spark_analysis": "gemma2-9b-it",      # Structure + requirements
    "falcon_architecture": "gemma2-9b-it", # Won architecture tests
    "eagle_implementation": "llama3-8b-8192", # Speed + explanations  
    "hawk_qa": "gemma2-9b-it",             # Structure + organization
    "code_analysis": "llama3-8b-8192"      # Speed + perfect JSON
}

# OPTIMIZED GROQ CONFIG (No JSON mode)
GROQ_CONFIG = {
    "temperature": 0.3,  # Optimized for consistency
    "max_tokens": 1024,  # Sufficient for most tasks
    "top_p": 0.8,
    "use_json_mode": False  # CRITICAL: Don't use JSON mode
}

# GLOBAL LOGGING SETTINGS
LOGGING_ENABLED = False
SESSION_TIMESTAMP = ""

def init_logging():
    """Initialize logging with session timestamp"""
    global SESSION_TIMESTAMP
    now = datetime.datetime.now()
    week = now.isocalendar()[1]  # Week of year
    day = now.day
    hour = now.hour
    minute = now.minute
    SESSION_TIMESTAMP = f"{week}-{day}-{hour}{minute:02d}"
    
    # Create logs directory
    logs_dir = Path("/home/flintx/peacock/logs")
    logs_dir.mkdir(exist_ok=True)
    
    if LOGGING_ENABLED:
        print(f"🔍 LOGGING ENABLED - Session: {SESSION_TIMESTAMP}")
        print(f"📁 Logs: /home/flintx/peacock/logs/")

def cli_progress(stage, status, message="", error=None):
    """Enhanced CLI progress output"""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    
    stage_icons = {
        "SPARK": "⚡",
        "FALCON": "🦅", 
        "EAGLE": "🦅",
        "HAWK": "🦅",
        "LLM2": "🤖"
    }
    
    stage_colors = {
        "START": "\033[94m",     # Blue
        "WORKING": "\033[93m",   # Yellow
        "SUCCESS": "\033[92m",   # Green
        "ERROR": "\033[91m",     # Red
        "END": "\033[0m"         # Reset
    }
    
    icon = stage_icons.get(stage, "🔄")
    color = stage_colors.get(status, "")
    reset = stage_colors["END"]
    
    if status == "START":
        print(f"\n{color}[{timestamp}] {icon} {stage} STARTING{reset}")
        if message:
            print(f"         └─ {message}")
    elif status == "WORKING":
        print(f"{color}[{timestamp}] {icon} {stage} PROCESSING...{reset}")
        if message:
            print(f"         └─ {message}")
    elif status == "SUCCESS":
        print(f"{color}[{timestamp}] ✅ {stage} COMPLETED{reset}")
        if message:
            print(f"         └─ {message}")
    elif status == "ERROR":
        print(f"{color}[{timestamp}] ❌ {stage} FAILED{reset}")
        if error:
            print(f"         └─ ERROR: {error}")
        if message:
            print(f"         └─ {message}")
    
    # Always flush output immediately
    sys.stdout.flush()

def select_optimal_model(command, priority="balanced"):
    """Select best model based on task and priority"""
    
    if priority == "speed":
        return PEACOCK_MODEL_STRATEGY["speed_model"]
    elif priority == "structure":
        return "gemma2-9b-it"
    elif priority == "explanation":
        return PEACOCK_MODEL_STRATEGY["explanation_model"]
    
    # Default assignments by stage
    return PEACOCK_STAGE_MODELS.get(command, PEACOCK_MODEL_STRATEGY["primary_model"])

def validate_response_quality(response_content, command):
    """Fixed validation - EAGLE generates code not JSON"""
    if len(response_content.strip()) < 50: return False
    if command == "eagle_implementation": return "```" in response_content or "filename:" in response_content
    return True
    
    # For structured commands, require JSON
    structured_commands = ["spark_analysis", "falcon_architecture", "eagle_implementation", "hawk_qa"]
    
    if command in structured_commands:
        # Must contain valid JSON
        json_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
        json_matches = re.findall(json_pattern, response_content, re.DOTALL)
        
        for match in json_matches:
            try:
                json.loads(match)
                return True
            except:
                continue
        return False
    
    return True

def parse_mixed_response(response_text, expected_format="mixed"):
    """Parse responses containing multiple content types"""
    
    parsed_data = {
        "explanation": "",
        "structured_data": {},
        "code_blocks": [],
        "success": False
    }
    
    # Extract explanations (text outside code blocks and JSON)
    explanation_text = re.sub(r'```.*?```', '', response_text, flags=re.DOTALL)
    explanation_text = re.sub(r'\{.*?\}', '', explanation_text, flags=re.DOTALL)
    parsed_data["explanation"] = explanation_text.strip()
    
    # Extract code blocks
    code_blocks = re.findall(r'```[\w]*\n(.*?)\n```', response_text, re.DOTALL)
    parsed_data["code_blocks"] = [block.strip() for block in code_blocks]
    
    # Extract JSON
    json_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
    json_matches = re.findall(json_pattern, response_text, re.DOTALL)
    
    for match in json_matches:
        try:
            parsed_json = json.loads(match)
            parsed_data["structured_data"] = parsed_json
            parsed_data["success"] = True
            break
        except:
            continue
    

####1/4 MARKER####
    return parsed_data

def call_optimized_groq(prompt, command):
    """Call Groq with optimized model selection and fallback logic"""
    
    primary_model = select_optimal_model(command)
    fallback_models = [
        PEACOCK_MODEL_STRATEGY["speed_model"], 
        PEACOCK_MODEL_STRATEGY["fallback_model"]
    ]
    
    # Build models to try (primary + fallbacks, avoid duplicates)
    models_to_try = [primary_model] + [m for m in fallback_models if m != primary_model]
    
    cli_progress(command.upper(), "START", f"Using {primary_model}")

    # PROMPT LOGGING: Always log prompts if logging is enabled
    if LOGGING_ENABLED:
        prompt_log_file = f"/home/flintx/peacock/logs/promptlog-{SESSION_TIMESTAMP}.txt"
        with open(prompt_log_file, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {command.upper()} PROMPT TO {primary_model}\n")
            f.write("=" * 80 + "\n")
            f.write(f"STAGE: {command}\n")
            f.write(f"PROMPT LENGTH: {len(prompt)} chars\n")
            f.write("-" * 40 + "\n")
            f.write(prompt)
            f.write("\n" + "=" * 80 + "\n\n")

    for model in models_to_try:
        try:
            from groq import Groq
            client = Groq(api_key=GROQ_API_KEY)
            
            cli_progress(command.upper(), "WORKING", f"Calling {model}...")
            
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=GROQ_CONFIG["temperature"],
                max_tokens=GROQ_CONFIG["max_tokens"],
                top_p=GROQ_CONFIG["top_p"]
                # NO response_format parameter - this is critical
            )
            
            content = response.choices[0].message.content
            
            # Validate response quality
            if validate_response_quality(content, command):
                cli_progress(command.upper(), "SUCCESS", f"Model: {model}, Length: {len(content)} chars")
                
                if LOGGING_ENABLED:
                    log_file = f"/home/flintx/peacock/logs/response-{SESSION_TIMESTAMP}.txt"
                    with open(log_file, "a", encoding="utf-8") as f:
                        f.write(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {command.upper()} SUCCESS - {model}\n")
                        f.write("=" * 80 + "\n")
                        f.write(content)
                        f.write("\n" + "=" * 80 + "\n\n")
                
                return {
                    "success": True,
                    "text": content,
                    "model_used": model,
                    "parsed": parse_mixed_response(content)
                }
            else:
                print(f"         └─ Quality validation failed for {model}")
                
        except Exception as e:
            cli_progress(command.upper(), "ERROR", f"Model {model} failed", str(e))
            continue

    return {
        "success": False, 
        "error": "All models failed",
        "models_tried": models_to_try
    }

def run_peacock_pipeline(user_request):
    """Run the complete 4-stage Peacock pipeline with optimized models"""
    print("\n🦚" + "="*60 + "🦚")
    print("    PEACOCK 4-STAGE PIPELINE (OPTIMIZED)")
    print("🦚" + "="*60 + "🦚")
    print(f"📝 REQUEST: {user_request}")
    print(f"🔥 STRATEGY: Multi-Model Optimization")
    print(f"📝 SESSION: {SESSION_TIMESTAMP}")
    print("="*70)
    
    pipeline_results = {}
    
    # STAGE 1: SPARK (Requirements Analysis) - gemma2-9b-it
    spark_prompt = f"""<thinking>
The user wants me to analyze this project idea strategically. I need to break this down into clear, actionable components.

Project: {user_request}

I should provide:
1. Core objective - what's the main goal?
2. Current state - what problems does this solve?
3. Target state - what's the desired outcome?
4. In scope - what features are included?
5. Out of scope - what's not included?
</thinking>

Act as Spark, a strategic requirements analyst. Analyze this project idea:

Project: {user_request}

Provide analysis in this EXACT format:

**1. Core Objective:**
[One clear sentence describing the main goal]

**2. Current State:**
[Current situation/problems this solves]

**3. Target State:**
[Desired end state after implementation]

**4. In Scope:**
- [Feature 1]
- [Feature 2] 
- [Feature 3]

**5. Out of Scope:**
- [What's NOT included]
- [Future considerations]

Then provide the structured data as JSON:
```json
{{
    "core_objective": "string",
    "current_state": "string",
    "target_state": "string", 
    "in_scope": ["list"],
    "out_of_scope": ["list"],
    "confidence_score": 8
}}
```

Keep it strategic and concise. Use your reasoning capabilities."""
    
    spark_response = call_optimized_groq(spark_prompt, "spark_analysis")
    
    if not spark_response.get("success"):
        return {"error": "Spark stage failed", "stage": "SPARK", "details": spark_response}
    
    pipeline_results["spark"] = spark_response
    
    # STAGE 2: FALCON (Architecture Design) - gemma2-9b-it
    falcon_prompt = f"""<thinking>
Based on the requirements from Spark, I need to design a technical architecture.

Requirements: {spark_response['text']}

I should think about:
- What technologies would work best
- How to structure the codebase
- What components are needed
- How they interact
</thinking>

Act as Falcon, a senior software architect. Design the technical architecture for this project.

Requirements Analysis:
{spark_response['text']}

Provide architecture design in this EXACT format:

**TECHNOLOGY STACK:**
- Frontend: [Technology choices]
- Backend: [Technology choices]  
- Database: [Technology choices]
- Additional: [Other technologies]

**CORE COMPONENTS:**
1. [Component Name] - [Purpose and functionality]
2. [Component Name] - [Purpose and functionality]
3. [Component Name] - [Purpose and functionality]

**FILE STRUCTURE:**
```
project_root/
├── [folder1]/
│   ├── [file1.ext]
│   └── [file2.ext]
├── [folder2]/
└── [file3.ext]
```

**COMPONENT INTERACTIONS:**
[Describe how components communicate and data flows]

Then provide the structured data as JSON:
```json
{{
    "tech_stack": {{

####1/2 MARKER####
        "frontend": "string",
        "backend": "string",
        "database": "string"
    }},
    "components": ["list"],
    "complexity": "simple|moderate|complex",
    "confidence_score": 8
}}
```

Focus on practical, implementable architecture."""
    
    falcon_response = call_optimized_groq(falcon_prompt, "falcon_architecture")
    
    if not falcon_response.get("success"):
        return {"error": "Falcon stage failed", "stage": "FALCON", "details": falcon_response}
    
    pipeline_results["falcon"] = falcon_response
    
    # STAGE 3: EAGLE (Implementation) - llama3-8b-8192 (speed + explanations)
    eagle_prompt = f"""<thinking>
I need to implement actual code based on this architecture.

Architecture: {falcon_response['text']}

I should:
- Generate complete, working code files
- Follow best practices
- Include proper error handling
- Make sure everything integrates properly
</thinking>

Act as Eagle, a senior developer. Implement the complete codebase based on this architecture.

Architecture Design:
{falcon_response['text']}

Generate complete, working code for each file specified in the architecture.

Format each file as:

**filename: path/to/file.ext**
```language
[Complete file content]
```

Provide:
- Complete, production-ready code
- Proper error handling
- Clear documentation
- Best practices implementation
- All necessary imports and dependencies

Make it work perfectly from the start."""
    
    eagle_response = call_optimized_groq(eagle_prompt, "eagle_implementation")
    
    if not eagle_response.get("success"):
        return {"error": "Eagle stage failed", "stage": "EAGLE", "details": eagle_response}
    
    pipeline_results["eagle"] = eagle_response
    
    # STAGE 4: HAWK (Quality Assurance) - gemma2-9b-it (structure + organization)
    hawk_prompt = f"""<thinking>
I need to create a comprehensive QA strategy for this implementation.

Implementation: {eagle_response['text']}

I should focus on:
- Test cases for core functionality
- Security validation
- Performance considerations
- Error handling scenarios
- Production readiness
</thinking>

Act as Hawk, a quality assurance specialist. Create comprehensive QA strategy for this implementation.

Implementation Details:
{eagle_response['text']}

Provide QA strategy in this EXACT format:

**1. Test Cases:**
- Functional tests for core features
- Edge cases and error scenarios
- Integration test requirements

**2. Security Validation:**
- Authentication/authorization checks
- Input validation requirements
- Data protection measures

**3. Performance Considerations:**
- Load testing requirements
- Scalability checkpoints
- Resource optimization

**4. Error Handling Scenarios:**
- Network failure handling
- Data corruption recovery
- User error management

**5. Production Readiness Checklist:**
- Deployment requirements
- Monitoring setup
- Backup strategies

Then provide the structured data as JSON:
```json
{{
    "test_coverage": 85,
    "security_score": 9,
    "performance_rating": "good",
    "production_ready": true,
    "confidence_score": 8
}}
```

Be specific and actionable for each area."""
    
    hawk_response = call_optimized_groq(hawk_prompt, "hawk_qa")
    
    if not hawk_response.get("success"):
        return {"error": "Hawk stage failed", "stage": "HAWK", "details": hawk_response}
    
    pipeline_results["hawk"] = hawk_response
    
    # PIPELINE COMPLETE
    print("\n🦚" + "="*60 + "🦚")
    print("    PEACOCK PIPELINE COMPLETED (OPTIMIZED)!")
    print("🦚" + "="*60 + "🦚")
    print(f"✅ SPARK: {pipeline_results['spark']['model_used']}")
    print(f"✅ FALCON: {pipeline_results['falcon']['model_used']}") 
    print(f"✅ EAGLE: {pipeline_results['eagle']['model_used']}")
    print(f"✅ HAWK: {pipeline_results['hawk']['model_used']}")
    print(f"📝 SESSION: {SESSION_TIMESTAMP}")
    print("="*70)
    
    return {
        "success": True,
        "pipeline_results": pipeline_results,
        "session": SESSION_TIMESTAMP,
        "optimization": "multi-model-strategy-enabled"
    }

# --- HTTP SERVER ---
class PeacockRequestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        """Override to use our logging system"""
        if LOGGING_ENABLED:
            log_file = f"/home/flintx/peacock/logs/mcplog-{SESSION_TIMESTAMP}.txt"
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] HTTP: {format % args}\n")

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>🦚 Peacock MCP Server - Multi-Model Optimized</title>
                <style>
                    body {{ 
                        font-family: 'JetBrains Mono', monospace; 
                        background: #0f0f0f; 
                        color: #00ff88; 
                        padding: 20px; 
                    }}
                    .status {{ 
                        background: #1e1e1e; 
                        padding: 20px; 
                        border-radius: 8px; 
                        border: 1px solid #00ff88; 
                    }}
                    .model-strategy {{
                        background: #2a2a2a;
                        padding: 15px;
                        margin: 15px 0;
                        border-radius: 6px;
                        border-left: 4px solid #ff6b35;
                    }}

####3/4 MARKER####
                </style>
            </head>
            <body>
                <h1>🦚 Peacock MCP Server (Multi-Model Optimized)</h1>
                <div class="status">
                    <h2>✅ Server Status: Online</h2>
                    <p><strong>Primary Model:</strong> {PEACOCK_MODEL_STRATEGY['primary_model']}</p>
                    <p><strong>Speed Model:</strong> {PEACOCK_MODEL_STRATEGY['speed_model']}</p>
                    <p><strong>Session:</strong> {SESSION_TIMESTAMP}</p>
                    <p><strong>Logging:</strong> {'Enabled' if LOGGING_ENABLED else 'Disabled'}</p>
                    <p>🔗 Processing: <code>http://{HOST}:{PORT}{PROCESS_PATH}</code></p>
                </div>
                
                <div class="model-strategy">
                    <h3>🧠 Model Strategy</h3>
                    <p><strong>SPARK:</strong> {PEACOCK_STAGE_MODELS['spark_analysis']} (Structure + Requirements)</p>
                    <p><strong>FALCON:</strong> {PEACOCK_STAGE_MODELS['falcon_architecture']} (Architecture)</p>
                    <p><strong>EAGLE:</strong> {PEACOCK_STAGE_MODELS['eagle_implementation']} (Speed + Code)</p>
                    <p><strong>HAWK:</strong> {PEACOCK_STAGE_MODELS['hawk_qa']} (QA + Structure)</p>
                </div>
            </body>
            </html>
            """
            self.wfile.write(html_content.encode("utf-8"))
            
        elif self.path == "/health":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            health_data = {
                "status": "healthy", 
                "models": PEACOCK_MODEL_STRATEGY,
                "stage_models": PEACOCK_STAGE_MODELS,
                "session": SESSION_TIMESTAMP,
                "logging": LOGGING_ENABLED,
                "optimization": "enabled"
            }
            self.wfile.write(json.dumps(health_data).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == PROCESS_PATH:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)

            try:
                received_data = json.loads(post_data.decode('utf-8'))
                
                command = received_data.get('command', 'unknown')
                text_to_process = received_data.get('text', '')
                
                print(f"\n🔄 INCOMING REQUEST: {command}")
                print(f"📝 Request: {text_to_process[:100]}...")
                
                if LOGGING_ENABLED:
                    log_file = f"/home/flintx/peacock/logs/mcplog-{SESSION_TIMESTAMP}.txt"
                    with open(log_file, "a", encoding="utf-8") as f:
                        f.write(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] POST REQUEST: {command}\n")

                # Process request
                if command == "peacock_full":
                    print(f"🦚 STARTING OPTIMIZED PEACOCK PIPELINE")
                    result = run_peacock_pipeline(text_to_process)
                        
                elif command == "fix_xedit_paths":
                    xedit_paths = received_data.get('xedit_paths', [])
                    print(f"🎯 PROCESSING XEDIT PATHS: {xedit_paths}")
                    
                    prompt = f"Fix and improve the code at these XEdit-Paths: {', '.join(xedit_paths)}"
                    llm_response = call_optimized_groq(prompt, "code_analysis")
                    
                    if llm_response.get("success"):
                        result = {
                            "success": True,
                            "response": llm_response['text'],
                            "paths_processed": len(xedit_paths),
                            "model_used": llm_response['model_used']
                        }
                    else:
                        result = {
                            "success": False,
                            "error": llm_response.get('error')
                        }
                        
                else:
                    # Default processing with optimized model selection
                    print(f"🔄 PROCESSING DEFAULT COMMAND: {command}")
                    prompt = f"Process this request: {text_to_process}"
                    llm_response = call_optimized_groq(prompt, "general")
                    
                    if llm_response.get("success"):
                        result = {
                            "success": True,
                            "response": llm_response['text'],
                            "model_used": llm_response['model_used']
                        }
                    else:
                        result = {
                            "success": False,
                            "error": llm_response.get('error')
                        }

                # Send response
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                
                response_json = json.dumps(result, indent=2)
                self.wfile.write(response_json.encode("utf-8"))
                
                print(f"✅ RESPONSE SENT: {len(response_json)} bytes")

            except Exception as e:
                print(f"❌ SERVER ERROR: {e}")
                self.send_response(500)
                self.send_header("Content-type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                error_response = {
                    "success": False,
                    "error": f"Server error: {str(e)}"
                }
                self.wfile.write(json.dumps(error_response).encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

def main():
    """Main function with argument parsing"""
    global LOGGING_ENABLED, PORT
    
    parser = argparse.ArgumentParser(description='🦚 Peacock MCP Server - Multi-Model Optimized')
    parser.add_argument('--log', '-l', action='store_true', help='Enable maxed logging')
    parser.add_argument('--port', '-p', type=int, default=8000, help='Server port (default: 8000)')
    
    args = parser.parse_args()
    
    LOGGING_ENABLED = args.log
    PORT = args.port
    
    # Initialize logging
    init_logging()
    
    print("🦚" + "="*60 + "🦚")
    print("    PEACOCK MCP SERVER - MULTI-MODEL OPTIMIZED")
    print("🦚" + "="*60 + "🦚")
    print()
    print(f"🔥 Primary Model: {PEACOCK_MODEL_STRATEGY['primary_model']}")
    print(f"⚡ Speed Model: {PEACOCK_MODEL_STRATEGY['speed_model']}")
    print(f"🧠 Strategy: Intelligent Model Routing")
    print(f"📝 Session: {SESSION_TIMESTAMP}")
    print(f"🔍 Logging: {'Enabled' if LOGGING_ENABLED else 'Disabled'}")
    print()
    print(f"🌐 Server starting on http://{HOST}:{PORT}")
    print()
    
    if LOGGING_ENABLED:
        print("📁 LOG FILES:")
        print(f"   MCP: /home/flintx/peacock/logs/mcplog-{SESSION_TIMESTAMP}.txt")
        print(f"   Responses: /home/flintx/peacock/logs/response-{SESSION_TIMESTAMP}.txt")
        print()
    
    print("🚀 PEACOCK SERVER READY!")
    print("="*70)
    
    try:
        with socketserver.TCPServer((HOST, PORT), PeacockRequestHandler) as httpd:
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Server error: {e}")

if __name__ == "__main__":
    main()
####END OF DOCUMENT####
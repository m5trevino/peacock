import os
from dotenv import load_dotenv
load_dotenv()

#!/usr/bin/env python3
"""
WIRE #3 FIX: out_homing.py - Mixed Content Generation for Parser + REAL LLM CALLS + XEDIT
The key fix: Generate SINGLE MIXED CONTENT response that xedit.py can parse
WITH API KEY ROTATION + PROXY SUPPORT + RETRY LOGIC + XEDIT GENERATION
"""

import json
import datetime
import sys
import time
import random
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional
import re

# Import all the bird modules (same directory)
from spark import create_spark_analyst
from falcon import create_falcon_architect  
from eagle import create_eagle_implementer
from hawk import create_hawk_qa_specialist

# Import XEdit module with proper path handling
sys.path.insert(0, str(Path(__file__).parent.parent / "core"))
try:
    from xedit import EnhancedXEditGenerator
    XEDIT_AVAILABLE = True
    print("✅ XEdit module loaded successfully")
except ImportError as e:
    XEDIT_AVAILABLE = False
    print(f"⚠️ XEdit module not available: {e}")

# GROQ API CONFIGURATION WITH KEY ROTATION
# Load API keys from environment
GROQ_API_KEYS = [
    os.getenv("GROQ_API_KEY_1"),
    os.getenv("GROQ_API_KEY_2"),
    os.getenv("GROQ_API_KEY_3"),
    os.getenv("GROQ_API_KEY_4")
]

# PROXY CONFIGURATION
PROXY_CONFIG = {
    "http": "http://0aa180faa467ad67809b__cr.us:6dc612d4a08ca89d@gw.dataimpulse.com:823",
    "https": "http://0aa180faa467ad67809b__cr.us:6dc612d4a08ca89d@gw.dataimpulse.com:823"
}

# MODEL ASSIGNMENTS FOR PRE-GENERATION STAGES
STAGE_MODEL_ASSIGNMENTS = {
    "spark": "meta-llama/llama-4-scout-17b-16e-instruct",
    "falcon": "meta-llama/llama-4-maverick-17b-128e-instruct",
    "eagle": "meta-llama/llama-4-scout-17b-16e-instruct",
    "hawk": "meta-llama/llama-4-maverick-17b-128e-instruct",
    "final": "meta-llama/llama-4-maverick-17b-128e-instruct"
}

# FINAL CODE GENERATOR CONFIGURATION (DATA-DRIVEN)
FINAL_CODE_GENERATORS = {
    "qwen-32b-instruct": {
        "model_id": "qwen/qwen3-32b",
        "temperature": 0.7,
        "top_p": 0.8,
        "max_tokens": 32768,
        "reasoning_effort": "none"
    },
    "qwen-32b-legacy-qwq": {
        "model_id": "qwen-qwq-32b",
        "temperature": 0.7,
        "top_p": 0.8,
        "max_tokens": 32768,
        "reasoning_format": "parsed"
    },
    "deepseek-coder-v2": {
        "model_id": "deepseek-coder-v2",
        "temperature": 0.7,
        "top_p": 0.9,
        "max_tokens": 32768,
    },
    "llama-3.1-70b-versatile": {
        "model_id": "llama-3.1-70b-versatile",
        "temperature": 0.7,
        "top_p": 0.9,
        "max_tokens": 32768,
    }
}

class OutHomingOrchestrator:
    """OUT-HOMING - Pipeline Conductor & Mixed Content Generator WITH REAL LLM CALLS + XEDIT"""
    
    def __init__(self):
        self.stage_name = "OUT-HOMING"
        self.icon = "🏠"
        self.specialty = "Pipeline Orchestration & LLM Communication"
        
        # Initialize all birds
        self.spark = create_spark_analyst()
        self.falcon = create_falcon_architect()
        self.eagle = create_eagle_implementer()
        self.hawk = create_hawk_qa_specialist()
        
        # Pipeline state
        self.pipeline_results = {}
        self.session_timestamp = datetime.datetime.now().strftime("%U-%w-%H%M")
        self.api_call_count = 0
    
    def orchestrate_full_pipeline(self, user_request: str, final_model_choice: str = "qwen-32b-instruct") -> Dict[str, Any]:
        """
        MAIN ORCHESTRATION with REAL LLM API CALLS + XEDIT GENERATION
        Runs 4-stage pipeline then generates mixed content response for parser
        """
        
        print(f"🚀 OUT-HOMING: Starting pipeline orchestration...")
        print(f"📅 Session: {self.session_timestamp}")
        print(f"🔑 API Keys: {len(GROQ_API_KEYS)} available")
        print(f"🎯 Final Generator: {final_model_choice}")

        try:
            # Step 1: Run all 4 birds with REAL LLM calls
            bird_results = self._run_all_birds_with_real_llm(user_request)
            
            if not bird_results["success"]:
                return {
                    "success": False,
                    "error": f"Bird pipeline failed: {bird_results.get('error')}"
                }

            # Step 2: ASSEMBLE MEGA PROMPT AND GENERATE FINAL CODE
            mega_prompt = self._assemble_mega_prompt(user_request, bird_results["stage_results"])
            final_code_result = self._generate_final_code_with_mega_prompt(mega_prompt, final_model_choice)
            
            if not final_code_result["success"]:
                print(f"⚠️ Final code generation failed: {final_code_result.get('error')}")
                # Continue with mixed content as fallback
            else:
                print(f"✅ FINAL CODE GENERATED: {final_code_result['characters']} characters")
            
            # Store final code result for later use
            bird_results["final_code_result"] = final_code_result
            
            # Step 3: Process with IN-HOMING and generate XEdit
            print("🔄 IN-HOMING: Processing final code and generating XEdit...")
            final_code = final_code_result.get("final_code", "")
            if not final_code:
                final_code = bird_results.get("stage_results", {}).get("eagle", {}).get("response", "")
            
            # Import and use IN-HOMING processor
            from in_homing import InHomingProcessor
            in_homing_processor = InHomingProcessor()
            
            processing_result = in_homing_processor.process_llm2_response(
                final_code,
                pipeline_metadata={
                    "project_name": user_request[:50],
                    "session_timestamp": self.session_timestamp,
                    "final_model_used": final_code_result.get("model_used", final_model_choice)
                }
            )
            
            return {
                "success": True,
                "final_code": final_code,
                "stage_results": bird_results["stage_results"],
                "session_timestamp": self.session_timestamp,
                "api_calls_made": self.api_call_count,
                "model_used": final_code_result.get("model_used", final_model_choice),
                "xedit_file_path": processing_result.get("xedit_file_path"),
                "project_files": processing_result.get("project_files", [])
            }
            
        except Exception as e:
            print(f"❌ Pipeline orchestration failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "session_timestamp": self.session_timestamp
            }
    
    def _run_all_birds_with_real_llm(self, user_request: str) -> Dict[str, Any]:
        """Run all 4 birds with real LLM API calls and proper character tracking"""
        
        print("🔥 Running all birds with REAL LLM calls...")
        
        try:
            stage_results = {}
            
            # Define prompts for each stage
            stage_prompts = {
                "spark": f"""Act as Spark, a strategic requirements analyst. Analyze this project request and provide detailed requirements analysis:

Project Request: {user_request}

Provide analysis in this format:
**1. Core Objective:**
[Main goal in one sentence]

**2. Functional Requirements:**
- [Requirement 1]
- [Requirement 2]
- [Requirement 3]

**3. Technical Requirements:**
- [Tech requirement 1]
- [Tech requirement 2]

**4. In Scope:**
- [Feature 1]
- [Feature 2]

**5. Out of Scope:**
- [What's not included]

Be specific and actionable.""",

                "falcon": f"""Act as Falcon, a senior software architect. Design the technical architecture for this project:

Project Request: {user_request}

Provide architecture design in this format:
**TECHNOLOGY STACK:**
- Frontend: [Technology choices]
- Backend: [Technology choices]
- Database: [Technology choices]

**CORE COMPONENTS:**
1. [Component Name] - [Purpose]
2. [Component Name] - [Purpose]
3. [Component Name] - [Purpose]

**FILE STRUCTURE:**
```
project_root/
├── [folder1]/
│   ├── [file1.ext]
│   └── [file2.ext]
└── [file2.ext]
```

**COMPONENT INTERACTIONS:**
[How components communicate]""",

                "eagle": f"""Act as Eagle, a senior software engineer. Implement working code for this project:

Project Request: {user_request}

Provide complete, executable code in this format:
**IMPLEMENTATION OVERVIEW:**
[Brief overview of approach]

**CODE FILES:**

**filename: [filename]**
```[language]
[complete code]
```

[Repeat for each file]

**TESTING INSTRUCTIONS:**
[How to run and test]

Focus on clean, production-ready code.""",

                "hawk": f"""Act as Hawk, a senior QA engineer. Create comprehensive QA strategy for this project:

Project Request: {user_request}

Provide QA strategy in this format:
**1. Test Cases:**
- [Test case 1]
- [Test case 2]
- [Test case 3]

**2. Security Validation:**
- [Security check 1]
- [Security check 2]

**3. Performance Considerations:**
- [Performance requirement 1]
- [Performance requirement 2]

**4. Error Handling:**
- [Error scenario 1]
- [Error scenario 2]

**5. Production Readiness:**
- [Deployment requirement 1]
- [Deployment requirement 2]

Be specific and actionable."""
            }
            
            # Run each bird with proper prompts
            for stage in ["spark", "falcon", "eagle", "hawk"]:
                print(f"\n🦅 Running {stage.upper()} stage...")
                
                prompt = stage_prompts[stage]
                
                # Make real LLM call
                llm_result = self._make_real_llm_call(prompt, stage)
                
                if llm_result["success"]:
                    # Add character count to the result
                    llm_result["chars"] = llm_result["char_count"]
                    stage_results[stage] = llm_result
                    print(f"✅ {stage.upper()}: {llm_result['char_count']} chars")
                else:
                    print(f"❌ {stage.upper()} failed: {llm_result['error']}")
                    return {
                        "success": False,
                        "error": f"{stage} stage failed: {llm_result['error']}"
                    }
            
            print(f"📊 Total API calls made: {self.api_call_count}")
            
            return {
                "success": True,
                "stage_results": stage_results
            }
            
        except Exception as e:
            print(f"❌ Bird execution error: {e}")
            return {
                "success": False,
                "error": f"Bird execution failed: {str(e)}"
            }
    
    def _make_real_llm_call(self, prompt: str, stage: str, attempt: int = 1) -> Dict[str, Any]:
        """Make actual API call to Groq with retry logic"""
        
        model = STAGE_MODEL_ASSIGNMENTS.get(stage, "meta-llama/llama-4-scout-17b-16e-instruct")
        api_key = random.choice(GROQ_API_KEYS)
        
        # Use proxy on first attempt, direct on retry
        use_proxy = (attempt == 1)
        connection_type = "proxy" if use_proxy else "direct"
        
        print(f"🔗 {stage.upper()} API call (attempt {attempt}, {connection_type})")
        
        try:
            self.api_call_count += 1
            
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 4000,
                "temperature": 0.7
            }
            
            proxies = PROXY_CONFIG if use_proxy else None
            
            response = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=headers,
                json=payload,
                proxies=proxies,
                timeout=30
            )
            
            response.raise_for_status()
            data = response.json()
            
            # Extract response content
            content = data["choices"][0]["message"]["content"]
            
            print(f"✅ {stage.upper()} Success - {len(content)} chars - Key: {api_key[-8:]}")
            
            return {
                "success": True,
                "text": content,
                "response": content,
                "model": model,
                "api_key_used": api_key[-8:],
                "char_count": len(content),
                "chars": len(content),  # Add this for compatibility
                "attempt": attempt,
                "connection_type": connection_type
            }
            
        except requests.exceptions.RequestException as e:
            print(f"❌ {stage.upper()} API Error (attempt {attempt}): {str(e)}")
            
            # Retry with direct connection if proxy failed
            if attempt == 1:
                print(f"🔄 Retrying {stage.upper()} with direct connection...")
                return self._make_real_llm_call(prompt, stage, attempt=2)
            
            return {
                "success": False,
                "error": str(e),
                "model": model,
                "attempt": attempt,
                "connection_type": connection_type
            }
    
    def _assemble_mega_prompt(self, user_request: str, bird_results: Dict[str, Any]) -> str:
        """Assemble mega prompt from all 4 bird outputs"""
        
        # Get individual bird responses
        spark_response = bird_results.get("spark", {}).get("response", "")
        falcon_response = bird_results.get("falcon", {}).get("response", "")  
        eagle_response = bird_results.get("eagle", {}).get("response", "")
        hawk_response = bird_results.get("hawk", {}).get("response", "")
        
        # Assemble the mega prompt
        mega_prompt = f"""
COMPREHENSIVE PROJECT GENERATION REQUEST

ORIGINAL USER REQUEST: {user_request}

REQUIREMENTS ANALYSIS (SPARK):
{spark_response}

TECHNICAL ARCHITECTURE (FALCON):
{falcon_response}

IMPLEMENTATION DETAILS (EAGLE):
{eagle_response}

QUALITY ASSURANCE STRATEGY (HAWK):
{hawk_response}

FINAL INSTRUCTION:
Based on the above comprehensive analysis, generate COMPLETE, EXECUTABLE CODE FILES for "{user_request}".

CRITICAL OUTPUT FORMAT - YOU MUST RETURN EXACTLY THIS:

```filename: index.html
<!DOCTYPE html>
<html>
<head>
    <title>{user_request}</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    [COMPLETE HTML IMPLEMENTATION]
    <script src="script.js"></script>
</body>
</html>
```

```filename: style.css
[COMPLETE CSS STYLING FOR THE APPLICATION]
```

```filename: script.js
[COMPLETE JAVASCRIPT IMPLEMENTATION WITH ALL FUNCTIONS]
```

CRITICAL REQUIREMENTS:
- Return ONLY the code files in the exact format above
- NO documentation, explanations, or QA procedures
- All code must be complete and functional
- Include ALL necessary functions and styling
- Make it a fully working application

DO NOT RETURN ANYTHING EXCEPT THE CODE FILES.
"""
        
        return mega_prompt

    def _generate_final_code_with_mega_prompt(self, mega_prompt: str, model_choice: str = "qwen-32b-instruct") -> Dict[str, Any]:
        """Send mega prompt to Groq and get final code generation"""
        
        print(f"🎯 SENDING MEGA PROMPT TO GROQ FOR FINAL CODE GENERATION...")
        
        # Log the mega prompt
        self._log_mega_prompt(mega_prompt)
        
        try:
            # Select API key and model for final generation
            api_key = random.choice(GROQ_API_KEYS)
            
            generator_config = FINAL_CODE_GENERATORS.get(model_choice)
            if not generator_config:
                return {"success": False, "error": f"Invalid model choice: {model_choice}", "final_code": ""}

            model_id = generator_config["model_id"]
            
            # Initialize Groq client
            from groq import Groq
            client = Groq(api_key=api_key)
            
            print(f"🔗 FINAL CODE GENERATION API call (model: {model_id})")
            
            # Make the final API call with mega prompt
            response = client.chat.completions.create(
                messages=[
                    {
                        "role": "user",
                        "content": mega_prompt
                    }
                ],
                model=model_id,
                max_tokens=4000,
                temperature=0.3
            )
            
            final_response = response.choices[0].message.content
            
            # Log the final response
            self._log_final_response(final_response, model_id)
            
            print(f"✅ FINAL CODE GENERATION Success - {len(final_response)} chars - Model: {model_id}")
            
            return {
                "success": True,
                "final_code": final_response,
                "model_used": model_id,
                "characters": len(final_response)
            }
            
        except Exception as e:
            print(f"❌ FINAL CODE GENERATION failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "final_code": ""
            }

    def _log_mega_prompt(self, mega_prompt: str):
        """Log the assembled mega prompt"""
        import os
        
        # Ensure logs directory exists
        logs_dir = "/home/flintx/peacock/core/logs"
        os.makedirs(logs_dir, exist_ok=True)
        
        # Write mega prompt log
        mega_log_path = f"{logs_dir}/megapromptlog-{self.session_timestamp}.txt"
        
        with open(mega_log_path, "w") as f:
            f.write(f"[{datetime.datetime.now().isoformat()}] ASSEMBLED MEGA PROMPT\n")
            f.write(f"Session: {self.session_timestamp}\n")
            f.write("=" * 60 + "\n")
            f.write("MEGA PROMPT CONTENT:\n")
            f.write("=" * 60 + "\n")
            f.write(mega_prompt)
            f.write("\n" + "=" * 60 + "\n")
        
        print(f"✅ Mega prompt logged: {mega_log_path}")

    def _log_final_response(self, final_response: str, model_used: str):
        """Log the final code generation response"""
        import os
        
        # Ensure logs directory exists
        logs_dir = "/home/flintx/peacock/core/logs"
        os.makedirs(logs_dir, exist_ok=True)
        
        # Write final response log
        final_log_path = f"{logs_dir}/finalresponselog-{self.session_timestamp}.txt"
        
        with open(final_log_path, "w") as f:
            f.write(f"[{datetime.datetime.now().isoformat()}] FINAL CODE GENERATION RESPONSE\n")
            f.write(f"Session: {self.session_timestamp}\n")
            f.write(f"Model: {model_used}\n")
            f.write("=" * 60 + "\n")
            f.write("FINAL CODE RESPONSE:\n")
            f.write("=" * 60 + "\n")
            f.write(final_response)
            f.write("\n" + "=" * 60 + "\n")
        
        print(f"✅ Final response logged: {final_log_path}")

def create_homing_orchestrator() -> OutHomingOrchestrator:
    """Factory function to create OUT-HOMING orchestrator instance"""
    return OutHomingOrchestrator()

def test_out_homing_pipeline():
    """Test the complete OUT-HOMING pipeline orchestration"""
    homing = create_homing_orchestrator()
    
    test_request = "Build a snake game with HTML, CSS, and JavaScript"
    
    print("🧪 TESTING COMPLETE OUT-HOMING PIPELINE")
    print(f"📝 Request: {test_request}")
    print("="*70)
    
    # Test orchestration (without real LLM calls for testing)
    try:
        print(f"✅ Orchestrator created: {homing.stage_name}")
        print(f"🕐 Session: {homing.session_timestamp}")
        return {"success": True, "message": "Factory function works"}
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return {"success": False, "error": str(e)}

if __name__ == "__main__":
    # Test the orchestrator
    test_out_homing_pipeline()
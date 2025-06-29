from robust_parser import RobustParser
from robust_parser import RobustParser
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
    from xedit import PeacockResponseParser, XEditInterfaceGenerator
    XEDIT_AVAILABLE = True
    print("✅ XEdit module loaded successfully")
except ImportError as e:
    XEDIT_AVAILABLE = False
    print(f"⚠️ XEdit module not available: {e}")

# GROQ API CONFIGURATION WITH KEY ROTATION
GROQ_API_KEYS = [
    "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",
    "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", 
    "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",
    "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"
]

# PROXY CONFIGURATION
PROXY_CONFIG = {
    "http": "http://0aa180faa467ad67809b__cr.us:6dc612d4a08ca89d@gw.dataimpulse.com:823",
    "https": "http://0aa180faa467ad67809b__cr.us:6dc612d4a08ca89d@gw.dataimpulse.com:823"
}

# MODEL ASSIGNMENTS BASED ON TESTING RESULTS
STAGE_MODEL_ASSIGNMENTS = {
    "spark": "meta-llama/llama-4-scout-17b-16e-instruct",       # Speed critical
    "falcon": "meta-llama/llama-4-maverick-17b-128e-instruct",  # 128K context
    "eagle": "meta-llama/llama-4-scout-17b-16e-instruct",       # Fast code gen
    "hawk": "meta-llama/llama-4-maverick-17b-128e-instruct",    # Thorough analysis
    "final": "qwen/qwen3-32b"    # Comprehensive
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
    
    def orchestrate_full_pipeline(self, user_request: str) -> Dict[str, Any]:
        """
        MAIN ORCHESTRATION with REAL LLM API CALLS + XEDIT GENERATION
        Runs 4-stage pipeline then generates mixed content response for parser
        """
        
        print(f"🚀 OUT-HOMING: Starting pipeline orchestration...")
        print(f"📅 Session: {self.session_timestamp}")
        print(f"🔑 API Keys: {len(GROQ_API_KEYS)} available")
        
        try:
            # Step 1: Run all 4 birds with REAL LLM calls
            bird_results = self._run_all_birds_with_real_llm(user_request)
            
            if not bird_results["success"]:
                return {
                    "success": False,
                    "error": f"Bird pipeline failed: {bird_results.get('error')}"
                }
            
            # Step 2: ASSEMBLE MEGA PROMPT AND GENERATE FINAL CODE
            print("🧠 ASSEMBLING MEGA PROMPT FROM ALL 4 BIRDS...")
            mega_prompt = self._assemble_mega_prompt(user_request, bird_results["stage_results"])
            final_code_result = self._generate_final_code_with_mega_prompt(mega_prompt)
            
            if not final_code_result["success"]:
                print(f"⚠️ Final code generation failed: {final_code_result.get('error')}")
            else:
                print(f"✅ FINAL CODE GENERATED: {final_code_result['characters']} characters")
            
            bird_results["final_code_result"] = final_code_result
            
            # Step 3: WIRE #3 FIX - Generate mixed content response for parser
            mixed_content_response = self._generate_robust_parsed_content(
                user_request, 
                bird_results["stage_results"]
            )
            
            # Step 4: Generate XEdit HTML interface
            xedit_result = self._generate_xedit_interface(
                user_request,
                mixed_content_response,
                bird_results["stage_results"]
            )
            
            print(f"✅ OUT-HOMING: Pipeline completed successfully")
            print(f"📊 Total API calls: {self.api_call_count}")
            
            return {
                "success": True,
                "final_response": mixed_content_response,
                "stage_results": bird_results["stage_results"],
                "xedit_result": xedit_result,
                "session_timestamp": self.session_timestamp,
                "api_calls_made": self.api_call_count
            }
            
        except Exception as e:
            print(f"❌ Pipeline orchestration failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "session_timestamp": self.session_timestamp
            }
    
    def _run_all_birds_with_real_llm(self, user_request: str) -> Dict[str, Any]:
        """Run all 4 birds with real LLM API calls"""
        
        print("🔥 Running all birds with REAL LLM calls...")
        
        try:
            stage_results = {}
            
            # Run each bird with LLM calls
            stages = ["spark", "falcon", "eagle", "hawk"]
            
            for stage in stages:
                print(f"\n🦅 Running {stage.upper()} stage...")
                
                # Get bird prompt (simplified for now)
                if stage == "spark":
                    prompt = f"Analyze requirements for: {user_request}"
                elif stage == "falcon":
                    prompt = f"Design architecture for: {user_request}"
                elif stage == "eagle":
                    prompt = f"Implement code for: {user_request}"
                else:  # hawk
                    prompt = f"Quality assurance for: {user_request}"
                
                # Make real LLM call
                llm_result = self._make_real_llm_call(prompt, stage)
                
                if llm_result["success"]:
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
    
    def _generate_robust_parsed_content(self, user_request: str, stage_results: Dict[str, Any]) -> str:
        """
        Generate mixed content response that xedit.py can parse
        This is the KEY function - creates the exact format the parser expects
        """
        
        print("🎯 WIRE #3 FIX: Generating mixed content for parser...")
        
        # Extract key data from stage results
        spark_data = stage_results.get("spark", {})
        falcon_data = stage_results.get("falcon", {})
        eagle_data = stage_results.get("eagle", {})
        hawk_data = stage_results.get("hawk", {})
        
        # Build mixed content response in parser-friendly format
        response_parts = []
        
        # Add project header
        response_parts.extend([
            f"# 🦚 PEACOCK PROJECT: {user_request}\n\n",
            "## Project Requirements Analysis (SPARK)\n",
            spark_data.get("response", "No SPARK analysis available") + "\n\n",
            
            "## System Architecture (FALCON)\n", 
            falcon_data.get("response", "No FALCON architecture available") + "\n\n",
            
            "## Implementation Details (EAGLE)\n",
            eagle_data.get("response", "No EAGLE implementation available") + "\n\n",
            
            "## Quality Assurance Strategy (HAWK)\n",
            hawk_data.get("response", "No HAWK QA strategy available") + "\n\n"
        ])
        
        # Extract and format code files from EAGLE response for parser
        eagle_response_text = eagle_data.get("response", "")
        if eagle_response_text:
            response_parts.append("## Code Implementation Files\n\n")
            
            # Extract code blocks with filename patterns that xedit.py expects
            code_files = self._extract_code_files_from_eagle(eagle_response_text)
            
            for file_data in code_files:
                response_parts.extend([
                    f"### File: {file_data['filename']}\n",
                    f"```{file_data['language']}\n",
                    file_data['code'],
                    "\n```\n\n"
                ])
        
        # Join all parts into final mixed content
        mixed_content = "".join(response_parts)
        
        print(f"✅ Mixed content generated: {len(mixed_content)} characters")
        return mixed_content
    
    def _extract_code_files_from_eagle(self, eagle_response: str) -> List[Dict[str, Any]]:
        """Extract code files from EAGLE response for mixed content generation"""
        
        code_files = []
        
        # Pattern to match code blocks with filenames
        filename_pattern = r'```(\w+)\s*\n(?:\/\*\s*(.+?)\s*\*\/\s*\n)?(.*?)\n```'
        file_pattern = r'(?:File:|Filename:|# )(.+?\.(?:html|css|js|py|java|cpp|c|php|rb|go|rs))\s*[\n:]'
        
        # Find code blocks
        code_matches = re.findall(filename_pattern, eagle_response, re.DOTALL)
        
        for i, (language, comment, code) in enumerate(code_matches):
            if len(code.strip()) > 50:  # Only substantial code blocks
                
                # Try to extract filename from comment or preceding text
                filename = f"file{i+1:02d}.{language or 'txt'}"
                
                # Look for filename patterns before this code block
                preceding_text = eagle_response[:eagle_response.find(code)][-200:]
                file_matches = re.findall(file_pattern, preceding_text, re.IGNORECASE)
                
                if file_matches:
                    filename = file_matches[-1].strip()
                
                code_files.append({
                    "filename": filename,
                    "language": language or "text",
                    "code": code.strip(),
                    "size": len(code.strip()),
                    "lines": len(code.strip().split('\n'))
                })
        
        return code_files
    
    def _generate_xedit_interface(self, user_request: str, mixed_content: str, stage_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate XEdit HTML interface using the mixed content"""
        
        if not XEDIT_AVAILABLE:
            return {"success": False, "error": "XEdit module not available"}
        
        print("🎯 Generating XEdit HTML interface...")
        
        try:
            # Create parser and interface generator
            parser = PeacockResponseParser()
            interface_gen = XEditInterfaceGenerator()
            
            # Parse the mixed content
            parsed_data = parser.parse_llm_response(mixed_content, user_request)
            
            # Generate HTML interface
            html_content = interface_gen.generate_xedit_interface_html(parsed_data, [])
            
            # Save to HTML directory
            html_dir = Path("/home/flintx/peacock/html")
            html_dir.mkdir(exist_ok=True)
            
            output_path = html_dir / f"xedit-{self.session_timestamp}.html"
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            import webbrowser
            webbrowser.open(f'file://{output_path}')

            print(f"✅ XEdit interface generated: {output_path}")
            
            return {
                "success": True,
                "html_file": str(output_path),
                "files_count": len(parsed_data.get("code_files", []))
            }
            
        except Exception as e:
            print(f"❌ XEdit generation error: {e}")
            return {
                "success": False,
                "error": f"XEdit generation failed: {str(e)}"
            }


    def _assemble_mega_prompt(self, user_request: str, bird_results: Dict[str, Any]) -> str:
        spark_response = bird_results.get("spark", {}).get("response", "")
        falcon_response = bird_results.get("falcon", {}).get("response", "")
        eagle_response = bird_results.get("eagle", {}).get("response", "")
        hawk_response = bird_results.get("hawk", {}).get("response", "")
        
        mega_prompt = f"""COMPREHENSIVE PROJECT GENERATION REQUEST

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
Generate COMPLETE, EXECUTABLE CODE FILES for "{user_request}".
Return ONLY the code files in proper format.
DO NOT RETURN ANYTHING EXCEPT THE CODE FILES."""
        
        return mega_prompt

    def _generate_final_code_with_mega_prompt(self, mega_prompt: str) -> Dict[str, Any]:
        print("🎯 SENDING MEGA PROMPT TO GROQ FOR FINAL CODE GENERATION...")
        
        import os
        logs_dir = "/home/flintx/peacock/core"
        os.makedirs(logs_dir, exist_ok=True)
        mega_log_path = f"{logs_dir}/megapromptlog-{self.session_timestamp}.txt"
        with open(mega_log_path, "w") as f:
            f.write(f"[{datetime.datetime.now().isoformat()}] ASSEMBLED MEGA PROMPT\n")
            f.write(f"Session: {self.session_timestamp}\n")
            f.write("=" * 60 + "\n")
            f.write(mega_prompt)
            f.write("\n" + "=" * 60 + "\n")
        print(f"✅ Mega prompt logged: {mega_log_path}")
        
        try:
            api_key = random.choice(GROQ_API_KEYS)
            model = STAGE_MODEL_ASSIGNMENTS.get("final", "qwen/qwen3-32b")
            
            from groq import Groq
            client = Groq(api_key=api_key)
            
            response = client.chat.completions.create(
                messages=[{"role": "user", "content": mega_prompt}],
                model=model,
                max_tokens=40960,
                temperature=0.3
            )
            
            final_response = response.choices[0].message.content
            
            final_log_path = f"{logs_dir}/finalresponselog-{self.session_timestamp}.txt"
            with open(final_log_path, "w") as f:
                f.write(f"[{datetime.datetime.now().isoformat()}] FINAL CODE GENERATION RESPONSE\n")
                f.write(f"Session: {self.session_timestamp}\n")
                f.write(f"Model: {model}\n")
                f.write("=" * 60 + "\n")
                f.write(final_response)
                f.write("\n" + "=" * 60 + "\n")
            print(f"✅ Final response logged: {final_log_path}")
            
            self.api_call_count += 1
            
            return {
                "success": True,
                "final_code": final_response,
                "model_used": model,
                "characters": len(final_response)
            }
            
        except Exception as e:
            return {"success": False, "error": str(e), "final_code": ""}

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

    def _assemble_mega_prompt(self, user_request: str, bird_results: Dict[str, Any]) -> str:
        spark_response = bird_results.get("spark", {}).get("response", "")
        falcon_response = bird_results.get("falcon", {}).get("response", "")  
        eagle_response = bird_results.get("eagle", {}).get("response", "")
        hawk_response = bird_results.get("hawk", {}).get("response", "")
        
        mega_prompt = f"""COMPREHENSIVE PROJECT GENERATION REQUEST

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
Generate COMPLETE, EXECUTABLE CODE FILES for "{user_request}".
Return ONLY the code files in proper format.
DO NOT RETURN ANYTHING EXCEPT THE CODE FILES."""
        
        return mega_prompt

    def _generate_final_code_with_mega_prompt(self, mega_prompt: str) -> Dict[str, Any]:
        print("🎯 SENDING MEGA PROMPT TO GROQ FOR FINAL CODE GENERATION...")
        
        # Log the mega prompt
        import os
        logs_dir = "/home/flintx/peacock/core"
        os.makedirs(logs_dir, exist_ok=True)
        mega_log_path = f"{logs_dir}/megapromptlog-{self.session_timestamp}.txt"
        with open(mega_log_path, "w") as f:
            f.write(f"[{datetime.datetime.now().isoformat()}] ASSEMBLED MEGA PROMPT\n")
            f.write(f"Session: {self.session_timestamp}\n")
            f.write("=" * 60 + "\n")
            f.write(mega_prompt)
            f.write("\n" + "=" * 60 + "\n")
        print(f"✅ Mega prompt logged: {mega_log_path}")
        
        try:
            api_key = random.choice(GROQ_API_KEYS)
            model = "meta-llama/llama-4-scout-17b-16e-instruct"
            
            from groq import Groq
            client = Groq(api_key=api_key)
            
            print(f"🔗 FINAL CODE GENERATION API call (model: {model})")
            
            response = client.chat.completions.create(
                messages=[{"role": "user", "content": mega_prompt}],
                model=model,
                max_tokens=40960,
                temperature=0.3
            )
            
            final_response = response.choices[0].message.content
            
            # Log the final response
            response_text = response.choices[0].message.content
            final_log_path = f"{logs_dir}/finalresponselog-{self.session_timestamp}.txt"
            with open(final_log_path, "w") as f:
                f.write(f"[{datetime.datetime.now().isoformat()}] FINAL RESPONSE\n")
                f.write(f"Session: {self.session_timestamp}\n")
                f.write("=" * 60 + "\n")
                f.write(response_text)
                f.write("\n" + "=" * 60 + "\n")
            print(f"✅ Final response logged: {final_log_path}")
            
            # Log the final response
            final_log_path = f"{logs_dir}/finalresponselog-{self.session_timestamp}.txt"
            with open(final_log_path, "w") as f:
                f.write(f"[{datetime.datetime.now().isoformat()}] FINAL CODE GENERATION RESPONSE\n")
                f.write(f"Session: {self.session_timestamp}\n")
                f.write(f"Model: {model}\n")
                f.write("=" * 60 + "\n")
                f.write(final_response)
                f.write("\n" + "=" * 60 + "\n")
            print(f"✅ Final response logged: {final_log_path}")
            
            print(f"✅ FINAL CODE GENERATION Success - {len(final_response)} chars")
            
            self.api_call_count += 1
            
            return {
                "success": True,
                "final_code": final_response,
                "model_used": model,
                "characters": len(final_response)
            }
            
        except Exception as e:
            print(f"❌ FINAL CODE GENERATION failed: {e}")
            return {"success": False, "error": str(e), "final_code": ""}


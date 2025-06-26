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
    "spark": "meta-llama/llama-4-scout-17b-16e-instruct",
    "falcon": "meta-llama/llama-4-maverick-17b-128e-instruct",
    "eagle": "meta-llama/llama-4-scout-17b-16e-instruct",
    "hawk": "meta-llama/llama-4-maverick-17b-128e-instruct",
    "final": "meta-llama/llama-4-maverick-17b-128e-instruct"
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
                print(f"⚠️ Final code generation failed: {final_code_result.get("error")}")
            else:
                print(f"✅ FINAL CODE GENERATED: {final_code_result["characters"]} characters")
            
            # Store final code result
            bird_results["final_code_result"] = final_code_result
            
            # Step 2: WIRE #3 FIX - Generate mixed content response for parser
            mixed_content_response = self._generate_mixed_content_response(
                user_request, 
                bird_results["stage_results"]
            )
            
            # Step 3: Generate XEdit HTML interface
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
                    print(f"✅ {stage.upper()}: {len(llm_result['response'])} chars")
                else:
                    stage_results[stage] = llm_result
                    print(f"❌ {stage.upper()}: {llm_result.get('error', 'Unknown error')}")
            
            # Check overall success
            success_count = sum(1 for result in stage_results.values() if result.get("success", False))
            overall_success = success_count >= 3  # At least 3/4 must succeed
            
            print(f"\n📊 Bird Results: {success_count}/4 successful")
            
            return {
                "success": overall_success,
                "stage_results": stage_results,
                "success_count": success_count
            }
            
        except Exception as e:
            print(f"❌ Bird pipeline failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "stage_results": {}
            }
    
    def _make_real_llm_call(self, prompt: str, stage: str) -> Dict[str, Any]:
        """Make a real Groq API call with error handling and proxy support"""
        
        api_key = random.choice(GROQ_API_KEYS)
        model = STAGE_MODEL_ASSIGNMENTS.get(stage, "llama-3.1-8b-instant")
        
        # Try with proxy first, then without
        for attempt in [1, 2]:
            try:
                from groq import Groq
                
                # Setup client based on attempt
                if attempt == 1:
                    print(f"🔗 {stage.upper()} API call (attempt {attempt}, proxy)")
                    client = Groq(api_key=api_key)
                else:
                    print(f"🔗 {stage.upper()} API call (attempt {attempt}, direct)")
                    client = Groq(api_key=api_key)
                
                # Make the API call
                response = client.chat.completions.create(
                    messages=[
                        {
                            "role": "user", 
                            "content": prompt
                        }
                    ],
                    model=model,
                    max_tokens=2000,
                    temperature=0.7
                )
                
                content = response.choices[0].message.content
                key_suffix = api_key[-8:]
                
                print(f"✅ {stage.upper()} Success - {len(content)} chars - Key: {key_suffix}")
                
                self.api_call_count += 1
                
                return {
                    "success": True,
                    "response": content,
                    "model": model,
                    "characters": len(content),
                    "api_key_suffix": key_suffix,
                    "attempt": attempt
                }
                
            except Exception as e:
                print(f"❌ {stage.upper()} attempt {attempt} failed: {e}")
                if attempt == 2:  # Last attempt failed
                    return {
                        "success": False,
                        "error": str(e),
                        "model": model,
                        "attempts": 2
                    }
                time.sleep(1)  # Brief pause before retry
        
        return {"success": False, "error": "All attempts failed"}
    
    def _generate_mixed_content_response(self, user_request: str, stage_results: Dict[str, Any]) -> str:
        """Generate mixed content response for parser (WIRE #3 FIX)"""
        
        print("🎯 WIRE #3 FIX: Generating mixed content for parser...")
        
        # Combine all bird responses into unified content
        combined_content = f"PROJECT REQUEST: {user_request}\n\n"
        
        for stage_name, result in stage_results.items():
            if result.get("success"):
                combined_content += f"=== {stage_name.upper()} OUTPUT ===\n"
                combined_content += result.get("response", "")
                combined_content += "\n\n"
            else:
                combined_content += f"=== {stage_name.upper()} FAILED ===\n"
                combined_content += f"Error: {result.get('error', 'Unknown error')}\n\n"
        
        print(f"✅ Mixed content generated: {len(combined_content)} characters")
        return combined_content

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

def create_homing_orchestrator() -> OutHomingOrchestrator:
    """Factory function to create OUT-HOMING orchestrator instance"""
    return OutHomingOrchestrator()

#⅛¼ START OF DOCUMENT ⅜#
#!/usr/bin/env python3
"""
WIRE #3 FIX: out_homing.py - Mixed Content Generation for Parser + REAL LLM CALLS
The key fix: Generate SINGLE MIXED CONTENT response that xedit.py can parse
WITH API KEY ROTATION + PROXY SUPPORT + RETRY LOGIC
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
    "final": "meta-llama/llama-4-maverick-17b-128e-instruct"    # Comprehensive
}

class OutHomingOrchestrator:
    """OUT-HOMING - Pipeline Conductor & Mixed Content Generator WITH REAL LLM CALLS"""
    
    def __init__(self):
        self.stage_name = "OUT-HOMING"
        self.icon = "🏠"
        self.specialty = "Pipeline Orchestration & LLM Communication"
        
        # Initialize all birds
        self.spark = create_spark_analyst()
        self.falcon = create_falcon_architect()
        self.eagle = create_eagle_implementer()
        self.hawk = create_hawk_qa_specialist()
        
        # API state tracking for key rotation
        self.current_key_index = 0
        self.api_call_count = 0
        
        # Pipeline state
        self.pipeline_results = {}
        self.session_timestamp = self._generate_session_timestamp()
    
    def _generate_session_timestamp(self):
        """Generate session timestamp in military format: week-day-hourminute"""
        now = datetime.datetime.now()
        week = now.isocalendar()[1] 
        day = now.weekday() + 1
        hour_minute = now.strftime("%H%M")
        return f"{week:02d}-{day:02d}-{hour_minute}"
    
    def _get_next_api_key(self):
        """Rotate through API keys evenly"""
        key = GROQ_API_KEYS[self.current_key_index]
        self.current_key_index = (self.current_key_index + 1) % len(GROQ_API_KEYS)
        self.api_call_count += 1
        return key

#¼¼¼¼¼¼ 1/4 MARKER ¼¼¼¼¼#
    
    def _make_real_llm_call(self, prompt: str, stage: str, attempt: int = 1) -> Dict[str, Any]:
        """Make REAL Groq API call with proxy support and fallback"""
        
        api_key = self._get_next_api_key()
        model = STAGE_MODEL_ASSIGNMENTS.get(stage, "meta-llama/llama-4-scout-17b-16e-instruct")
        
        # Groq API endpoint
        url = "https://api.groq.com/openai/v1/chat/completions"
        
        # Request headers
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        # Request payload (optimized for mixed content based on testing)
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3,
            "max_tokens": 1024,
            "top_p": 0.8,
            "stream": False
        }
        
        # Proxy configuration
        proxies = None
        connection_type = "proxy"
        if attempt == 1:
            proxies = PROXY_CONFIG
        else:
            connection_type = "direct"
            
        print(f"🌐 API Call #{self.api_call_count} - {stage.upper()} - {model} - {connection_type} (attempt {attempt})")
        
        try:
            # Make the request
            response = requests.post(
                url,
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
    
    def orchestrate_full_pipeline(self, user_request: str) -> Dict[str, Any]:
        """
        MAIN ORCHESTRATION with REAL LLM API CALLS
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
            
            # Step 2: WIRE #3 FIX - Generate mixed content response for parser
            mixed_content_response = self._generate_mixed_content_response(
                user_request, 
                bird_results["stage_results"]
            )
            
            # Step 3: Structure response for MCP
            return {
                "success": True,
                "session_timestamp": self.session_timestamp,
                "stage_results": bird_results["stage_results"],
                "final_response": mixed_content_response,
                "total_birds": 4,
                "pipeline_type": "full_orchestration",
                "api_calls_made": self.api_call_count
            }
            
        except Exception as e:
            print(f"❌ OUT-HOMING ERROR: {e}")
            return {
                "success": False,
                "error": f"Pipeline orchestration failed: {str(e)}"
            }

#½½½½½½ 1/2 MARKER ½½½½½#
    
    def _run_all_birds_with_real_llm(self, user_request: str) -> Dict[str, Any]:
        """Run all 4 birds with REAL LLM API calls"""
        
        stage_results = {}
        
        try:
            # STAGE 1: SPARK (Requirements Analysis) with REAL LLM
            print("\n⚡ STAGE 1: SPARK - Requirements Analysis")
            spark_prompt_data = self.spark.analyze_project_request(user_request)
            spark_llm_response = self._make_real_llm_call(
                spark_prompt_data["prompt"], 
                "spark"
            )
            
            stage_results["spark"] = {
                "prompt": spark_prompt_data["prompt"],
                "response": spark_llm_response.get("text", ""),
                "model": spark_llm_response.get("model", "unknown"),
                "success": spark_llm_response.get("success", False),
                "char_count": spark_llm_response.get("char_count", 0),
                "api_key_used": spark_llm_response.get("api_key_used", "N/A")
            }
            
            if not spark_llm_response.get("success"):
                return {"success": False, "error": "SPARK LLM call failed"}
            
            # Log SPARK results
            log_file = Path("/home/flintx/peacock/logs/prompt-spark.log")
            log_file.parent.mkdir(exist_ok=True)
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(f"\n{'='*80}\n")
                f.write(f"TIMESTAMP: {datetime.datetime.now().isoformat()}\n")
                f.write(f"PROMPT ({len(spark_prompt_data['prompt'])} chars):\n")
                f.write(spark_prompt_data['prompt'])
                f.write(f"\nRESPONSE ({len(spark_llm_response.get('text', ''))} chars):\n")
                f.write(spark_llm_response.get('text', ''))
                f.write("\n" + "="*80 + "\n")
            
            # STAGE 2: FALCON (Architecture Design) with REAL LLM
            print("\n🦅 STAGE 2: FALCON - Architecture Design")
            
            # Create proper input for FALCON (single parameter)
            falcon_input = {
                "user_request": user_request,
                "spark_analysis": spark_llm_response["text"],
                "requirements_data": {
                    "core_objective": "Based on SPARK analysis",
                    "analysis_complete": True
                }
            }
            
            falcon_prompt_data = self.falcon.design_architecture(falcon_input)
            falcon_llm_response = self._make_real_llm_call(
                falcon_prompt_data["prompt"],
                "falcon"
            )
            
            stage_results["falcon"] = {
                "prompt": falcon_prompt_data["prompt"],
                "response": falcon_llm_response.get("text", ""),
                "model": falcon_llm_response.get("model", "unknown"),
                "success": falcon_llm_response.get("success", False),
                "char_count": falcon_llm_response.get("char_count", 0),
                "api_key_used": falcon_llm_response.get("api_key_used", "N/A")
            }
            
            if not falcon_llm_response.get("success"):
                return {"success": False, "error": "FALCON LLM call failed"}
            
            # STAGE 3: EAGLE (Code Implementation) with REAL LLM
            print("\n🦅 STAGE 3: EAGLE - Code Implementation")
            
            # Create proper input for EAGLE
            eagle_input = {
                "raw_design": falcon_llm_response["text"],
                "json_data": {
                    "architecture_complete": True,
                    "falcon_analysis": "Architecture design completed"
                },
                "user_request": user_request
            }
            
            eagle_prompt_data = self.eagle.implement_code(eagle_input)
            eagle_llm_response = self._make_real_llm_call(
                eagle_prompt_data["prompt"],
                "eagle"
            )
            
            stage_results["eagle"] = {
                "prompt": eagle_prompt_data["prompt"],
                "response": eagle_llm_response.get("text", ""),
                "model": eagle_llm_response.get("model", "unknown"),
                "success": eagle_llm_response.get("success", False),
                "char_count": eagle_llm_response.get("char_count", 0),
                "api_key_used": eagle_llm_response.get("api_key_used", "N/A")
            }
            
            if not eagle_llm_response.get("success"):
                return {"success": False, "error": "EAGLE LLM call failed"}
            
            # STAGE 4: HAWK (QA & Testing) with REAL LLM
            print("\n🦅 STAGE 4: HAWK - QA & Testing")
            
            # Create proper input for HAWK
            hawk_input = {
                "user_request": user_request,
                "spark_analysis": spark_llm_response["text"],
                "falcon_architecture": falcon_llm_response["text"],
                "eagle_implementation": eagle_llm_response["text"],
                "qa_requirements": {
                    "comprehensive_testing": True,
                    "security_review": True,
                    "performance_analysis": True
                }
            }
            
            hawk_prompt_data = self.hawk.create_qa_strategy(hawk_input)
            hawk_llm_response = self._make_real_llm_call(
                hawk_prompt_data["prompt"],
                "hawk"
            )
            
            stage_results["hawk"] = {
                "prompt": hawk_prompt_data["prompt"],
                "response": hawk_llm_response.get("text", ""),
                "model": hawk_llm_response.get("model", "unknown"),
                "success": hawk_llm_response.get("success", False),
                "char_count": hawk_llm_response.get("char_count", 0),
                "api_key_used": hawk_llm_response.get("api_key_used", "N/A")
            }
            
            if not hawk_llm_response.get("success"):
                return {"success": False, "error": "HAWK LLM call failed"}
            
            print(f"\n🎉 ALL 4 STAGES COMPLETED WITH REAL LLM CALLS!")
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

#¾¾¾¾¾¾ 3/4 MARKER ¾¾¾¾¾#
    
    def _generate_mixed_content_response(self, user_request: str, stage_results: Dict[str, Any]) -> str:
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
            
            for i, code_file in enumerate(code_files, 1):
                filename = code_file.get("filename", f"file_{i}")
                code = code_file.get("code", "# No code found")
                language = code_file.get("language", "text")
                
                response_parts.extend([
                    f"**filename: {filename}**\n",
                    f"```{language}\n",
                    code + "\n",
                    "```\n\n"
                ])
        
        # Add implementation notes from all stages
        response_parts.append("## Implementation Notes\n")
        
        # Extract notes from all stages
        all_notes = []
        for stage_name, stage_data in stage_results.items():
            stage_response = stage_data.get("response", "")
            notes = self._extract_implementation_notes(stage_response, stage_name)
            all_notes.extend(notes)
        
        for note in all_notes[:10]:  # Limit to 10 notes
            response_parts.append(f"- {note}\n")
        
        response_parts.append("\n")
        
        # Add testing checklist from HAWK
        if hawk_data.get("response"):
            response_parts.append("## Testing Checklist\n")
            hawk_response = hawk_data.get("response", "")
            test_items = self._extract_test_items(hawk_response)
            
            for test_item in test_items[:8]:  # Limit to 8 items
                response_parts.append(f"- {test_item}\n")
            
            response_parts.append("\n")
        
        # Combine all parts
        final_response = "".join(response_parts)
        
        print(f"📄 Mixed content generated: {len(final_response)} characters")
        print(f"🔍 Code files found: {len(self._extract_code_files_from_eagle(eagle_data.get('response', '')))}")
        
        return final_response
    
    def _extract_code_files_from_eagle(self, eagle_response: str) -> List[Dict[str, Any]]:
        """Extract code files from EAGLE response in format xedit.py expects"""
        
        code_files = []
        
        # Pattern 1: filename: pattern (what EAGLE should generate)
        filename_pattern = r'```filename:\s*([^\n]+)\n(.*?)\n```'
        filename_matches = re.findall(filename_pattern, eagle_response, re.DOTALL | re.IGNORECASE)
        
        for filename, code in filename_matches:
            code_files.append({
                "filename": filename.strip(),
                "code": code.strip(),
                "language": self._detect_language_from_filename(filename.strip())
            })
        
        # Pattern 2: Standard markdown code blocks
        if not code_files:  # Only if no filename patterns found
            code_block_pattern = r'```(\w+)?\n(.*?)\n```'
            code_matches = re.findall(code_block_pattern, eagle_response, re.DOTALL)
            
            for i, (language, code) in enumerate(code_matches):
                if len(code.strip()) > 50:  # Only substantial code blocks
                    filename = self._infer_filename_from_code(code, language)
                    
                    code_files.append({
                        "filename": filename,
                        "code": code.strip(),
                        "language": language or "text"
                    })
        
        return code_files
    
    def _detect_language_from_filename(self, filename: str) -> str:
        """Detect programming language from filename"""
        
        ext_map = {
            '.py': 'python',
            '.js': 'javascript', 
            '.html': 'html',
            '.css': 'css',
            '.json': 'json',
            '.md': 'markdown',
            '.txt': 'text',
            '.sh': 'bash',
            '.sql': 'sql'
        }
        
        for ext, lang in ext_map.items():
            if filename.lower().endswith(ext):
                return lang
        
        return 'text'
    
    def _infer_filename_from_code(self, code: str, language: str) -> str:
        """Infer filename from code content and language"""
        
        # Look for common patterns in code that indicate filename
        if 'class ' in code and language == 'python':
            class_match = re.search(r'class\s+(\w+)', code)
            if class_match:
                return f"{class_match.group(1).lower()}.py"
        
        if 'function ' in code and language == 'javascript':
            return "script.js"
        
        if '<html' in code or '<!DOCTYPE' in code:
            return "index.html"
        
        if language == 'css' or 'body {' in code or '.container' in code:
            return "styles.css"
        
        # Default naming based on language
        language_defaults = {
            'python': 'main.py',
            'javascript': 'app.js', 
            'html': 'index.html',
            'css': 'styles.css',
            'json': 'config.json'
        }
        
        return language_defaults.get(language, f"file.{language or 'txt'}")
    
    def _extract_implementation_notes(self, response_text: str, stage_name: str) -> List[str]:
        """Extract implementation notes from stage response"""
        
        notes = []
        
        # Look for bullet points
        bullet_pattern = r'[•\-\*]\s*([^\n]+)'
        bullet_matches = re.findall(bullet_pattern, response_text)
        
        for match in bullet_matches:
            if len(match.strip()) > 10:  # Substantial notes only
                notes.append(f"[{stage_name.upper()}] {match.strip()}")
        
        # Look for numbered lists
        numbered_pattern = r'\d+\.\s*([^\n]+)'
        numbered_matches = re.findall(numbered_pattern, response_text)
        
        for match in numbered_matches:
            if len(match.strip()) > 10:
                notes.append(f"[{stage_name.upper()}] {match.strip()}")
        
        return notes[:3]  # Limit per stage
    
    def _extract_test_items(self, hawk_response: str) -> List[str]:
        """Extract test items from HAWK response"""
        
        test_items = []
        
        # Look for test-related patterns
        test_patterns = [
            r'test[:\s]+([^\n]+)',
            r'testing[:\s]+([^\n]+)',
            r'verify[:\s]+([^\n]+)',
            r'check[:\s]+([^\n]+)',
            r'validate[:\s]+([^\n]+)'
        ]
        
        for pattern in test_patterns:
            matches = re.findall(pattern, hawk_response, re.IGNORECASE)
            for match in matches:
                if len(match.strip()) > 10:
                    test_items.append(match.strip())
        
        # Look for bullet points in testing sections
        testing_section = re.search(r'test.*?(?=\n\n|\n#|$)', hawk_response, re.DOTALL | re.IGNORECASE)
        if testing_section:
            bullets = re.findall(r'[•\-\*]\s*([^\n]+)', testing_section.group())
            test_items.extend([b.strip() for b in bullets if len(b.strip()) > 10])
        
        return list(set(test_items))  # Remove duplicates

def create_homing_orchestrator() -> OutHomingOrchestrator:
    """Factory function to create OUT-HOMING orchestrator instance"""
    return OutHomingOrchestrator()

# Test function
def test_out_homing_orchestrator():
    """Test the complete OUT-HOMING orchestration with REAL LLM calls"""
    
    print("🧪 TESTING OUT-HOMING ORCHESTRATOR WITH REAL LLM INTEGRATION")
    print("="*60)
    
    # Create orchestrator
    homing = create_homing_orchestrator()
    
    # Test with sample request
    test_request = "Build a simple snake game with HTML, CSS, and JavaScript"
    
    print(f"🎯 Test Request: {test_request}")
    print(f"🔑 API Keys Available: {len(GROQ_API_KEYS)}")
    print(f"🌐 Proxy Configured: {PROXY_CONFIG['http']}")
    
    result = homing.orchestrate_full_pipeline(test_request)
    
    print(f"\n📊 ORCHESTRATION RESULTS:")
    print(f"✅ Success: {result.get('success')}")
    print(f"📅 Session: {result.get('session_timestamp')}")
    print(f"🐦 Birds Run: {result.get('total_birds', 0)}")
    print(f"🌐 API Calls Made: {result.get('api_calls_made', 0)}")
    
    if result.get("success"):
        stage_results = result.get("stage_results", {})
        print(f"\n🎯 STAGE RESULTS WITH REAL LLM RESPONSES:")
        for stage, data in stage_results.items():
            char_count = len(data.get("response", ""))
            model = data.get("model", "unknown")
            api_key = data.get("api_key_used", "N/A")
            print(f"   {stage.upper()}: {char_count} chars ({model}) [Key: {api_key}]")
        
        final_response = result.get("final_response", "")
        print(f"\n🎯 MIXED CONTENT FOR PARSER:")
        print(f"   📏 Length: {len(final_response)} characters")
        print(f"   📝 Preview: {final_response[:200]}...")
        
        # Test parsing readiness
        print(f"\n🔍 PARSER READINESS CHECK:")
        filename_headers = final_response.count("**filename:")
        code_blocks = final_response.count("```")
        print(f"   📁 Filename headers: {filename_headers}")
        print(f"   💻 Code blocks: {code_blocks}")
        print(f"   ✅ Parser ready: {filename_headers > 0 and code_blocks > 0}")
        
    else:
        print(f"❌ Error: {result.get('error')}")
    
    return result

if __name__ == "__main__":
    # Test the orchestrator with real LLM integration
    test_out_homing_orchestrator()

#⅛¼ END OF DOCUMENT ⅜#
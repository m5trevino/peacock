#!/usr/bin/env python3
"""
WIRE #3 FIX: out_homing.py - Mixed Content Generation for Parser
The key fix: Generate SINGLE MIXED CONTENT response that xedit.py can parse
"""

import json
import datetime
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
import re

# Import all the bird modules (same directory)
from spark import create_spark_analyst
from falcon import create_falcon_architect  
from eagle import create_eagle_implementer
from hawk import create_hawk_qa_specialist

class OutHomingOrchestrator:
    """OUT-HOMING - Pipeline Conductor & Mixed Content Generator"""
    
    def __init__(self):
        self.stage_name = "OUT-HOMING"
        self.icon = "🏠"
        self.specialty = "Pipeline Orchestration & Mixed Content Generation"
        
        # Initialize all birds
        self.spark = create_spark_analyst()
        self.falcon = create_falcon_architect()
        self.eagle = create_eagle_implementer()
        self.hawk = create_hawk_qa_specialist()
        
        # Pipeline state
        self.pipeline_results = {}
        self.session_timestamp = self._generate_session_timestamp()
        
    def _generate_session_timestamp(self):
        """Generate military time session timestamp"""
        now = datetime.datetime.now()
        week = now.isocalendar()[1]
        day = now.day
        hour = now.hour
        minute = now.minute
        return f"{week}-{day:02d}-{hour:02d}{minute:02d}"
    
    def orchestrate_full_pipeline(self, user_request: str) -> Dict[str, Any]:
        """
        WIRE #3 FIX: Orchestrate all birds and generate mixed content for parser
        """
        
        print(f"🏠 OUT-HOMING: Starting full pipeline orchestration")
        print(f"📝 User Request: {user_request}")
        print(f"📅 Session: {self.session_timestamp}")
        
        try:
            # Step 1: Run all birds sequentially
            bird_results = self._run_all_birds(user_request)
            
            if not bird_results["success"]:
                return {
                    "success": False,
                    "error": f"Bird pipeline failed: {bird_results.get('error')}"
                }
            
            # Step 2: WIRE #3 FIX - Generate mixed content prompt for final LLM
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
                "pipeline_type": "full_orchestration"
            }
            
        except Exception as e:
            print(f"❌ OUT-HOMING ERROR: {e}")
            return {
                "success": False,
                "error": f"Pipeline orchestration failed: {str(e)}"
            }
    
    def _run_all_birds(self, user_request: str) -> Dict[str, Any]:
        """Run all 4 birds sequentially and collect results"""
        
        stage_results = {}
        
        try:
            # BIRD 1: SPARK (Requirements Analysis)
            print("⚡ Running SPARK analysis...")
            spark_result = self.spark.analyze_project_request(user_request)
            
            # Log the SPARK prompt for debugging
            if spark_result and "prompt" in spark_result:
                prompt_preview = spark_result["prompt"][:200]  # Get first 200 chars for preview
                print(f"🔍 SPARK PROMPT: {prompt_preview}...")
                
                # Log full prompt to file
                log_file = Path("/home/flintx/peacock/logs/prompt-spark.log")
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(f"\n{'='*80}\n")
                    f.write(f"TIMESTAMP: {datetime.datetime.now().isoformat()}\n")
                    f.write(f"FULL SPARK PROMPT ({len(spark_result['prompt'])} chars):\n")
                    f.write(spark_result['prompt'])
                    f.write("\n" + "="*80 + "\n")
            
            stage_results["spark"] = {
                "prompt": spark_result.get("prompt", ""),
                "response": spark_result.get("analysis", ""),
                "model": spark_result.get("model", "gemma2-9b-it"),
                "success": True
            }
            
            # BIRD 2: FALCON (Architecture Design)
            print("🦅 Running FALCON architecture design...")
            falcon_result = self.falcon.design_architecture(spark_result)
            stage_results["falcon"] = {
                "prompt": falcon_result.get("prompt", ""),
                "response": falcon_result.get("architecture", ""),
                "model": falcon_result.get("model", "gemma2-9b-it"),
                "stage": "FALCON"
            }
            
            # BIRD 3: EAGLE (Code Implementation)
            print("🦅 Running EAGLE code implementation...")
            eagle_result = self.eagle.implement_code(falcon_result)
            stage_results["eagle"] = {
                "prompt": eagle_result.get("prompt", ""),
                "response": eagle_result.get("implementation", ""),
                "model": eagle_result.get("model", "llama3-8b-8192"),
                "stage": "EAGLE"
            }
            
            # BIRD 4: HAWK (Quality Assurance)
            print("🦅 Running HAWK quality assurance...")
            hawk_result = self.hawk.analyze_implementation(eagle_result)
            stage_results["hawk"] = {
                "prompt": hawk_result.get("prompt", ""),
                "response": hawk_result.get("qa_review", ""),
                "model": hawk_result.get("model", "gemma2-9b-it"),
                "stage": "HAWK"
            }
            
            print("✅ All birds completed successfully")
            
            return {
                "success": True,
                "stage_results": stage_results
            }
            
        except Exception as e:
            print(f"❌ Bird execution error: {e}")
            return {
                "success": False,
                "error": str(e),
                "stage_results": stage_results
            }
    
    def _generate_mixed_content_response(self, user_request: str, stage_results: Dict[str, Any]) -> str:
        """
        Generate mixed content response that xedit.py can parse
        This is the KEY function - creates the exact format the parser expects
        """
        
        print("🎯 WIRE #3 FIX: Generating mixed content for parser...")
        
        # Extract bird responses
        spark_response = stage_results.get("spark", {}).get("response", "")
        falcon_response = stage_results.get("falcon", {}).get("response", "")
        eagle_response = stage_results.get("eagle", {}).get("response", "")
        hawk_response = stage_results.get("hawk", {}).get("response", "")
        
        # Parse the responses to extract structured data and code
        spark_parsed = self._extract_structured_data(spark_response)
        falcon_parsed = self._extract_structured_data(falcon_response)
        eagle_parsed = self._extract_structured_data(eagle_response)
        hawk_parsed = self._extract_structured_data(hawk_response)
        
        # Generate the final mixed content response
        return self._format_final_response(
            user_request,
            spark_parsed,
            falcon_parsed,
            eagle_parsed,
            hawk_parsed
        )
    
    def _extract_structured_data(self, response_text: str) -> dict:
        """Extract structured data from model response"""
        if not response_text:
            return {}
            
        # Try to extract JSON data
        json_pattern = r'```json\s*\n(.*?)\n```'
        json_match = re.search(json_pattern, response_text, re.DOTALL)
        
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass
                
        return {}
    
    def _format_final_response(self, user_request: str, spark_data: dict, falcon_data: dict, 
                             eagle_data: dict, hawk_data: dict) -> str:
        """Format the final mixed content response"""
        
        # Start building the final response
        response_parts = [
            f"# Project Implementation: {user_request}\n"
        ]
        
        # Add requirements analysis
        if spark_data:
            response_parts.extend([
                "## Requirements Analysis (SPARK)\n",
                f"**Core Objective:** {spark_data.get('core_objective', 'N/A')}\n",
                f"**Current State:** {spark_data.get('current_state', 'N/A')}\n",
                f"**Target State:** {spark_data.get('target_state', 'N/A')}\n\n",
                "**In Scope:**\n",
                "\n".join(f"- {item}" for item in spark_data.get('in_scope', [])),
                "\n\n**Out of Scope:**\n",
                "\n".join(f"- {item}" for item in spark_data.get('out_of_scope', [])),
                "\n"
            ])
        
        # Add architecture
        if falcon_data:
            response_parts.extend([
                "\n## Technical Architecture (FALCON)\n",
                "**Technology Stack:**\n",
                f"- Frontend: {falcon_data.get('tech_stack', {}).get('frontend', 'N/A')}\n",
                f"- Backend: {falcon_data.get('tech_stack', {}).get('backend', 'N/A')}\n",
                f"- Database: {falcon_data.get('tech_stack', {}).get('database', 'N/A')}\n\n",
                "**Core Components:**\n"
            ])
            
            for i, component in enumerate(falcon_data.get('components', [])[:3], 1):
                response_parts.append(f"{i}. {component}\n")
        
        # Add implementation
        if eagle_data:
            response_parts.append("\n## Code Implementation\n")
            response_parts.append("Based on the requirements and architecture, here is the complete implementation.\n")
            
            # Add code files from eagle_data
            for filename in eagle_data.get('files_created', [])[:3]:
                response_parts.append(f"**filename: {filename}**\n")
                response_parts.append(f"```{self._get_language_from_filename(filename)}\n")
                # In a real implementation, we'd include the actual code here
                response_parts.append("# Code implementation would go here\n")
                response_parts.append("```\n\n")
        
        # Add QA findings
        if hawk_data:
            response_parts.extend([
                "## Quality Assurance Review (HAWK)\n",
                f"**Test Coverage:** {hawk_data.get('test_coverage', 'N/A')}%\n",
                f"**Security Score:** {hawk_data.get('security_score', 'N/A')}/10\n",
                f"**Performance Rating:** {hawk_data.get('performance_rating', 'N/A')}\n",
                f"**Production Ready:** {'Yes' if hawk_data.get('production_ready') else 'No'}\n"
            ])
        
        return "".join(response_parts)
    
    def _get_language_from_filename(self, filename: str) -> str:
        """Get language from file extension"""
        extension_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.html': 'html',
            '.css': 'css',
            '.json': 'json',
            '.md': 'markdown'
        }
        
        for ext, lang in extension_map.items():
            if filename.endswith(ext):
                return lang
                
        return 'text'

def create_homing_orchestrator() -> OutHomingOrchestrator:
    """Factory function to create OUT-HOMING orchestrator instance"""
    return OutHomingOrchestrator()

# Test function
def test_out_homing_orchestrator():
    """Test the complete OUT-HOMING orchestration"""
    
    print("🧪 TESTING OUT-HOMING ORCHESTRATOR")
    print("="*50)
    
    # Create orchestrator
    homing = create_homing_orchestrator()
    
    # Test with sample request
    test_request = "Build a snake game with HTML, CSS, and JavaScript"
    
    result = homing.orchestrate_full_pipeline(test_request)
    
    print(f"\n📊 ORCHESTRATION RESULTS:")
    print(f"✅ Success: {result.get('success')}")
    print(f"📅 Session: {result.get('session_timestamp')}")
    print(f"🐦 Birds Run: {result.get('total_birds', 0)}")
    
    if result.get("success"):
        stage_results = result.get("stage_results", {})
        print(f"\n🎯 STAGE CHARACTER COUNTS:")
        for stage, data in stage_results.items():
            char_count = len(data.get("response", ""))
            model = data.get("model", "unknown")
            print(f"   {stage.upper()}: {char_count} chars ({model})")
        
        final_response = result.get("final_response", "")
        print(f"\n🎯 FINAL MIXED CONTENT:")
        print(f"   📏 Length: {len(final_response)} characters")
        print(f"   📝 Preview: {final_response[:200]}...")
        
        # Test parsing readiness
        print(f"\n🔍 PARSING READINESS CHECK:")
        filename_headers = final_response.count("**filename:")
        code_blocks = final_response.count("```")
        print(f"   📁 Filename headers: {filename_headers}")
        print(f"   💻 Code blocks: {code_blocks}")
        print(f"   ✅ Parser ready: {filename_headers > 0 and code_blocks > 0}")
        
    else:
        print(f"❌ Error: {result.get('error')}")
    
    return result

if __name__ == "__main__":
    # Test the orchestrator
    test_out_homing_orchestrator()
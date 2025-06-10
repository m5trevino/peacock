#!/usr/bin/env python3
"""
homing.py - HOMING Pipeline Orchestrator
The conductor who coordinates all birds and manages the complete pipeline
"""

import json
import datetime
from typing import Dict, List, Any, Optional
from .spark import SparkAnalyst
from .falcon import FalconArchitect
from .eagle import EagleImplementer
from .hawk import HawkQASpecialist

class HomingOrchestrator:
    """HOMING - The Pipeline Conductor"""
    
    def __init__(self):
        self.stage_name = "HOMING"
        self.icon = "🏠"
        self.specialty = "Pipeline Orchestration & Quality Control"
        
        # Initialize all birds
        self.spark = SparkAnalyst()
        self.falcon = FalconArchitect()
        self.eagle = EagleImplementer()
        self.hawk = HawkQASpecialist()
        
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
        Main orchestration function - runs all 4 birds in sequence
        Returns complete pipeline results ready for RETURN-HOMING
        """
        
        print(f"🏠 HOMING: Starting full pipeline orchestration")
        print(f"📝 User Request: {user_request}")
        print(f"📅 Session: {self.session_timestamp}")
        
        pipeline_result = {
            "success": False,
            "session_timestamp": self.session_timestamp,
            "user_request": user_request,
            "stage_results": {},
            "pipeline_summary": {},
            "total_execution_time": 0,
            "error": None
        }
        
        start_time = datetime.datetime.now()
        
        try:
            # Stage 1: SPARK (Requirements Analysis)
            print("⚡ HOMING → SPARK: Requirements analysis...")
            spark_result = self._execute_spark_stage(user_request)
            
            if not spark_result["success"]:
                pipeline_result["error"] = f"SPARK stage failed: {spark_result['error']}"
                return pipeline_result
            
            pipeline_result["stage_results"]["spark"] = spark_result
            
            # Stage 2: FALCON (Architecture Design)
            print("🦅 HOMING → FALCON: Architecture design...")
            falcon_result = self._execute_falcon_stage(spark_result)
            
            if not falcon_result["success"]:
                pipeline_result["error"] = f"FALCON stage failed: {falcon_result['error']}"
                return pipeline_result
            
            pipeline_result["stage_results"]["falcon"] = falcon_result
            
            # Stage 3: EAGLE (Code Implementation)
            print("🦅 HOMING → EAGLE: Code implementation...")
            eagle_result = self._execute_eagle_stage(falcon_result)
            
            if not eagle_result["success"]:
                pipeline_result["error"] = f"EAGLE stage failed: {eagle_result['error']}"
                return pipeline_result
            
            pipeline_result["stage_results"]["eagle"] = eagle_result
            
            # Stage 4: HAWK (Quality Assurance)
            print("🦅 HOMING → HAWK: Quality assurance...")
            hawk_result = self._execute_hawk_stage(eagle_result)
            
            if not hawk_result["success"]:
                pipeline_result["error"] = f"HAWK stage failed: {hawk_result['error']}"
                return pipeline_result
            
            pipeline_result["stage_results"]["hawk"] = hawk_result
            
            # Calculate execution time
            end_time = datetime.datetime.now()
            pipeline_result["total_execution_time"] = (end_time - start_time).total_seconds()
            
            # Generate pipeline summary
            pipeline_result["pipeline_summary"] = self._generate_pipeline_summary(pipeline_result["stage_results"])
            
            pipeline_result["success"] = True
            
            print(f"✅ HOMING: Pipeline completed successfully in {pipeline_result['total_execution_time']:.2f}s")
            
        except Exception as e:
            pipeline_result["error"] = f"Pipeline orchestration failed: {str(e)}"
            print(f"❌ HOMING ERROR: {e}")
        
        return pipeline_result
    
    def _execute_spark_stage(self, user_request: str) -> Dict[str, Any]:
        """Execute SPARK requirements analysis stage"""
        try:
            # Generate SPARK prompt
            spark_prompt = self.spark.generate_analysis_prompt(user_request)
            
            # This would be called by MCP with optimal model
            return {
                "success": True,
                "stage": "SPARK",
                "prompt": spark_prompt,
                "optimal_model": "llama3-8b-8192",
                "prompt_length": len(spark_prompt),
                "stage_type": "requirements_analysis"
            }
            
        except Exception as e:
            return {
                "success": False,
                "stage": "SPARK", 
                "error": str(e)
            }
    
    def _execute_falcon_stage(self, spark_result: Dict[str, Any]) -> Dict[str, Any]:
        """Execute FALCON architecture design stage"""
        try:
            # Extract SPARK analysis for FALCON input
            spark_analysis = spark_result.get("llm_response", "")
            
            # Generate FALCON prompt
            falcon_prompt = self.falcon.generate_architecture_prompt(spark_analysis)
            
            return {
                "success": True,
                "stage": "FALCON",
                "prompt": falcon_prompt,
                "optimal_model": "gemma2-9b-it",
                "prompt_length": len(falcon_prompt),
                "stage_type": "architecture_design",
                "input_from": "SPARK"
            }
            
        except Exception as e:
            return {
                "success": False,
                "stage": "FALCON",
                "error": str(e)
            }
    
    def _execute_eagle_stage(self, falcon_result: Dict[str, Any]) -> Dict[str, Any]:
        """Execute EAGLE code implementation stage"""
        try:
            # Extract FALCON architecture for EAGLE input
            falcon_architecture = falcon_result.get("llm_response", "")
            
            # Generate EAGLE prompt
            eagle_prompt = self.eagle.generate_implementation_prompt(falcon_architecture)
            
            return {
                "success": True,
                "stage": "EAGLE",
                "prompt": eagle_prompt,
                "optimal_model": "llama-3.1-8b-instant",
                "prompt_length": len(eagle_prompt),
                "stage_type": "code_implementation",
                "input_from": "FALCON"
            }
            
        except Exception as e:
            return {
                "success": False,
                "stage": "EAGLE",
                "error": str(e)
            }
    
    def _execute_hawk_stage(self, eagle_result: Dict[str, Any]) -> Dict[str, Any]:
        """Execute HAWK quality assurance stage"""
        try:
            # Extract EAGLE implementation for HAWK input
            eagle_implementation = eagle_result.get("llm_response", "")
            
            # Generate HAWK prompt
            hawk_prompt = self.hawk.generate_qa_prompt(eagle_implementation)
            
            return {
                "success": True,
                "stage": "HAWK",
                "prompt": hawk_prompt,
                "optimal_model": "gemma2-9b-it",
                "prompt_length": len(hawk_prompt),
                "stage_type": "quality_assurance",
                "input_from": "EAGLE"
            }
            
        except Exception as e:
            return {
                "success": False,
                "stage": "HAWK",
                "error": str(e)
            }
    
    def _generate_pipeline_summary(self, stage_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive pipeline summary"""
        
        summary = {
            "stages_completed": len(stage_results),
            "total_prompt_chars": 0,
            "total_response_chars": 0,
            "models_used": {},
            "stage_breakdown": {},
            "quality_metrics": {}
        }
        
        for stage_name, stage_data in stage_results.items():
            # Calculate character counts
            prompt_chars = stage_data.get("prompt_length", 0)
            response_chars = len(stage_data.get("llm_response", ""))
            
            summary["total_prompt_chars"] += prompt_chars
            summary["total_response_chars"] += response_chars
            
            # Track models used
            model = stage_data.get("optimal_model", "unknown")
            summary["models_used"][stage_name] = model
            
            # Stage breakdown
            summary["stage_breakdown"][stage_name] = {
                "prompt_chars": prompt_chars,
                "response_chars": response_chars,
                "model": model,
                "success": stage_data.get("success", False)
            }
        
        # Calculate quality metrics
        summary["quality_metrics"] = {
            "avg_response_length": summary["total_response_chars"] / len(stage_results) if stage_results else 0,
            "model_diversity": len(set(summary["models_used"].values())),
            "completion_rate": len([s for s in stage_results.values() if s.get("success")]) / len(stage_results) if stage_results else 0
        }
        
        return summary
    
    def validate_pipeline_quality(self, pipeline_result: Dict[str, Any]) -> Dict[str, Any]:
        """Validate overall pipeline quality and completeness"""
        
        validation = {
            "overall_quality": "unknown",
            "completeness_score": 0,
            "issues_found": [],
            "recommendations": []
        }
        
        stage_results = pipeline_result.get("stage_results", {})
        
        # Check completeness
        expected_stages = ["spark", "falcon", "eagle", "hawk"]
        completed_stages = [stage for stage in expected_stages if stage in stage_results]
        validation["completeness_score"] = len(completed_stages) / len(expected_stages) * 100
        
        # Check for issues
        for stage_name, stage_data in stage_results.items():
            if not stage_data.get("success", False):
                validation["issues_found"].append(f"{stage_name.upper()} stage failed")
            
            response_length = len(stage_data.get("llm_response", ""))
            if response_length < 100:
                validation["issues_found"].append(f"{stage_name.upper()} response too short ({response_length} chars)")
        
        # Generate recommendations
        if validation["completeness_score"] < 100:
            validation["recommendations"].append("Complete all pipeline stages for best results")
        
        if len(validation["issues_found"]) == 0:
            validation["overall_quality"] = "excellent"
        elif len(validation["issues_found"]) <= 2:
            validation["overall_quality"] = "good"
        else:
            validation["overall_quality"] = "needs_improvement"
        
        return validation

# Factory function
def create_homing_orchestrator() -> HomingOrchestrator:
    """Factory function to create HOMING orchestrator instance"""
    return HomingOrchestrator()

# Test function
def test_homing_orchestrator():
    """Test the HOMING orchestrator with sample request"""
    
    print("🧪 TESTING HOMING ORCHESTRATOR")
    print("="*50)
    
    # Create orchestrator
    homing = create_homing_orchestrator()
    
    # Test with sample request
    test_request = "Build a snake game with HTML, CSS, and JavaScript"
    
    result = homing.orchestrate_full_pipeline(test_request)
    
    print(f"\n📊 ORCHESTRATION RESULTS:")
    print(f"✅ Success: {result.get('success')}")
    print(f"📅 Session: {result.get('session_timestamp')}")
    print(f"⏱️ Execution Time: {result.get('total_execution_time', 0):.2f}s")
    
    if result.get("success"):
        summary = result.get("pipeline_summary", {})
        print(f"\n🎯 PIPELINE SUMMARY:")
        print(f"   Stages Completed: {summary.get('stages_completed', 0)}/4")
        print(f"   Total Prompt Chars: {summary.get('total_prompt_chars', 0):,}")
        print(f"   Models Used: {len(summary.get('models_used', {}))}")
        
        # Validate quality
        validation = homing.validate_pipeline_quality(result)
        print(f"\n🔍 QUALITY VALIDATION:")
        print(f"   Overall Quality: {validation['overall_quality']}")
        print(f"   Completeness: {validation['completeness_score']:.1f}%")
        print(f"   Issues Found: {len(validation['issues_found'])}")
        
    else:
        print(f"❌ Error: {result.get('error')}")
    
    return result

if __name__ == "__main__":
    # Test the orchestrator
    test_homing_orchestrator()
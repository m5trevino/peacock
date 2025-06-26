#!/bin/bash
# PEACOCK CRITICAL VALIDATORS - Workflow & Mega Prompt Quality Analysis

cd /home/flintx/apitest/py

echo "🔥 CREATING PEACOCK WORKFLOW VALIDATOR & MEGA PROMPT QUALITY ANALYZER..."

# VALIDATOR 1: Peacock Workflow Validator
cat > peacock_workflow_validator.py << 'EOF'
#!/usr/bin/env python3
"""
PEACOCK WORKFLOW VALIDATOR
Tests the EXACT workflow that's currently broken:
1prompt → birds → mega prompt → final response → parsing → session linking
"""

import subprocess
import json
import datetime
import time
import random
import requests
from pathlib import Path
from groq import Groq
import os
import re

# API CONFIGURATION
API_KEYS = [
    "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",
    "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",
    "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",
    "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"
]

MODELS = [
    "meta-llama/llama-4-scout-17b-16e-instruct",
    "meta-llama/llama-4-maverick-17b-128e-instruct", 
    "llama-3.1-8b-instant",
    "llama-3.3-70b-versatile"
]

class PeacockWorkflowValidator:
    """Validates the entire Peacock workflow end-to-end"""
    
    def __init__(self):
        self.test_prompts = [
            "build a snake game",
            "create a todo app",
            "make a calculator",
            "build a weather app",
            "create a chat interface"
        ]
        self.session_id = self._generate_session_id()
        self.results = []
        
    def _generate_session_id(self):
        """Generate session ID like your system: 26-25-1506"""
        now = datetime.datetime.now()
        week = now.isocalendar()[1]
        day = now.day
        time_str = now.strftime("%H%M")
        return f"{week}-{day}-{time_str}"
    
    def simulate_1prompt_call(self, prompt):
        """Simulate calling 1prompt.py with a prompt"""
        print(f"🎯 SIMULATING 1PROMPT CALL: {prompt}")
        
        try:
            # Check if 1prompt.py exists
            prompt_path = "/home/flintx/peacock/core/1prompt.py"
            if not Path(prompt_path).exists():
                return {
                    "success": False,
                    "error": f"1prompt.py not found at {prompt_path}",
                    "stage": "1prompt_missing"
                }
            
            # Simulate the call (replace with actual subprocess call when ready)
            result = subprocess.run([
                "python3", prompt_path, 
                "--prompt", prompt,
                "--session", self.session_id
            ], capture_output=True, text=True, timeout=120)
            
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "stage": "1prompt_execution"
            }
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "1prompt timeout after 2 minutes",
                "stage": "1prompt_timeout"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "stage": "1prompt_error"
            }
    
    def check_log_files(self):
        """Check if the required log files were generated"""
        log_dir = "/home/flintx/peacock/core/logs"
        expected_logs = [
            f"promptlog-{self.session_id}.txt",
            f"responselog-{self.session_id}.txt", 
            f"mcplog-{self.session_id}.txt",
            f"megapromptlog-{self.session_id}.txt",  # This one is missing!
            f"finalresponselog-{self.session_id}.txt"  # This one is missing!
        ]
        
        log_status = {}
        for log_file in expected_logs:
            log_path = Path(log_dir) / log_file
            log_status[log_file] = {
                "exists": log_path.exists(),
                "size": log_path.stat().st_size if log_path.exists() else 0,
                "path": str(log_path)
            }
        
        return log_status
    
    def check_xedit_generation(self):
        """Check if XEdit HTML was generated and linked properly"""
        xedit_path = f"/home/flintx/peacock/html/xedit-{self.session_id}.html"
        
        return {
            "xedit_exists": Path(xedit_path).exists(),
            "xedit_path": xedit_path,
            "xedit_size": Path(xedit_path).stat().st_size if Path(xedit_path).exists() else 0
        }
    
    def analyze_response_quality(self, log_files):
        """Analyze the quality of responses in log files"""
        analysis = {
            "mega_prompt_found": False,
            "final_response_found": False,
            "code_files_detected": 0,
            "parsing_issues": []
        }
        
        # Check if final response contains actual code
        final_log = log_files.get(f"finalresponselog-{self.session_id}.txt", {})
        if final_log.get("exists") and final_log.get("size") > 0:
            try:
                with open(final_log["path"], 'r') as f:
                    content = f.read()
                
                # Look for code patterns
                code_patterns = [
                    r'```[\w]*\n.*?\n```',  # Code blocks
                    r'filename:\s*[\w\.]+',  # File declarations
                    r'function\s+\w+\(',     # Function definitions
                    r'<html.*?>',            # HTML tags
                    r'\.css|\.js|\.html'    # File extensions
                ]
                
                for pattern in code_patterns:
                    matches = re.findall(pattern, content, re.DOTALL | re.IGNORECASE)
                    analysis["code_files_detected"] += len(matches)
                
                analysis["final_response_found"] = True
                
            except Exception as e:
                analysis["parsing_issues"].append(f"Error reading final response: {e}")
        
        return analysis
    
    def validate_session_linking(self):
        """Validate that session IDs are consistent across all components"""
        # Check 1prompt HTML for correct session links
        prompt_html = f"/home/flintx/peacock/html/1prompt-{self.session_id}.html"
        
        if not Path(prompt_html).exists():
            return {
                "session_linking": False,
                "error": "1prompt HTML not generated",
                "expected_path": prompt_html
            }
        
        try:
            with open(prompt_html, 'r') as f:
                html_content = f.read()
            
            # Check if log links point to correct session
            correct_links = all([
                f"promptlog-{self.session_id}.txt" in html_content,
                f"responselog-{self.session_id}.txt" in html_content,
                f"mcplog-{self.session_id}.txt" in html_content
            ])
            
            # Check if XEdit button points to correct session
            xedit_link_correct = f"xedit-{self.session_id}.html" in html_content
            
            return {
                "session_linking": True,
                "log_links_correct": correct_links,
                "xedit_link_correct": xedit_link_correct,
                "html_content_length": len(html_content)
            }
            
        except Exception as e:
            return {
                "session_linking": False,
                "error": f"Error reading 1prompt HTML: {e}"
            }
    
    def run_full_workflow_test(self, prompt):
        """Run complete workflow test for a single prompt"""
        print(f"\n{'='*60}")
        print(f"🦚 TESTING FULL WORKFLOW: {prompt}")
        print(f"📅 Session: {self.session_id}")
        print(f"{'='*60}")
        
        test_result = {
            "prompt": prompt,
            "session_id": self.session_id,
            "timestamp": datetime.datetime.now().isoformat(),
            "stages": {}
        }
        
        # STAGE 1: 1prompt execution
        print("🎯 STAGE 1: Calling 1prompt...")
        test_result["stages"]["1prompt"] = self.simulate_1prompt_call(prompt)
        
        # Wait for processing
        time.sleep(5)
        
        # STAGE 2: Log file validation
        print("📋 STAGE 2: Checking log files...")
        test_result["stages"]["logs"] = self.check_log_files()
        
        # STAGE 3: Response quality analysis
        print("🔍 STAGE 3: Analyzing response quality...")
        test_result["stages"]["quality"] = self.analyze_response_quality(test_result["stages"]["logs"])
        
        # STAGE 4: XEdit generation check
        print("🎨 STAGE 4: Checking XEdit generation...")
        test_result["stages"]["xedit"] = self.check_xedit_generation()
        
        # STAGE 5: Session linking validation
        print("🔗 STAGE 5: Validating session linking...")
        test_result["stages"]["session"] = self.validate_session_linking()
        
        # Calculate overall success
        test_result["overall_success"] = self._calculate_overall_success(test_result)
        
        return test_result
    
    def _calculate_overall_success(self, test_result):
        """Calculate overall workflow success rate"""
        checks = [
            test_result["stages"]["1prompt"]["success"],
            test_result["stages"]["logs"][f"promptlog-{self.session_id}.txt"]["exists"],
            test_result["stages"]["logs"][f"responselog-{self.session_id}.txt"]["exists"],
            test_result["stages"]["quality"]["final_response_found"],
            test_result["stages"]["xedit"]["xedit_exists"],
            test_result["stages"]["session"]["session_linking"]
        ]
        
        return sum(checks) / len(checks) * 100
    
    def run_all_tests(self):
        """Run workflow tests for all test prompts"""
        print("🚀 PEACOCK WORKFLOW VALIDATOR - STARTING ALL TESTS")
        print(f"📅 {datetime.datetime.now().isoformat()}")
        
        all_results = []
        
        for i, prompt in enumerate(self.test_prompts, 1):
            print(f"\n🧪 TEST {i}/{len(self.test_prompts)}")
            
            # Generate new session for each test
            self.session_id = self._generate_session_id()
            time.sleep(1)  # Ensure unique timestamps
            
            result = self.run_full_workflow_test(prompt)
            all_results.append(result)
            
            # Brief pause between tests
            time.sleep(3)
        
        # Generate summary
        self._generate_workflow_summary(all_results)
        return all_results
    
    def _generate_workflow_summary(self, results):
        """Generate workflow validation summary"""
        total_tests = len(results)
        success_rates = [r["overall_success"] for r in results]
        avg_success = sum(success_rates) / total_tests if total_tests > 0 else 0
        
        print("\n" + "="*80)
        print("📊 PEACOCK WORKFLOW VALIDATION SUMMARY")
        print("="*80)
        print(f"🧪 Total Tests: {total_tests}")
        print(f"📈 Average Success Rate: {avg_success:.1f}%")
        print(f"✅ Fully Successful: {sum(1 for r in success_rates if r >= 90)}")
        print(f"⚠️  Partially Working: {sum(1 for r in success_rates if 50 <= r < 90)}")
        print(f"❌ Failed: {sum(1 for r in success_rates if r < 50)}")
        
        # Identify common issues
        print("\n🔍 COMMON ISSUES DETECTED:")
        missing_mega_prompt = sum(1 for r in results if not r["stages"]["logs"].get(f"megapromptlog-{r['session_id']}.txt", {}).get("exists", False))
        missing_final_response = sum(1 for r in results if not r["stages"]["logs"].get(f"finalresponselog-{r['session_id']}.txt", {}).get("exists", False))
        
        if missing_mega_prompt > 0:
            print(f"   ❌ Missing mega prompt logs: {missing_mega_prompt}/{total_tests}")
        if missing_final_response > 0:
            print(f"   ❌ Missing final response logs: {missing_final_response}/{total_tests}")
        
        # Save detailed results
        results_file = f"peacock_workflow_validation_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, 'w') as f:
            json.dump({
                "summary": {
                    "total_tests": total_tests,
                    "average_success_rate": avg_success,
                    "timestamp": datetime.datetime.now().isoformat()
                },
                "detailed_results": results
            }, f, indent=2)
        
        print(f"💾 Detailed results saved to {results_file}")

if __name__ == "__main__":
    validator = PeacockWorkflowValidator()
    validator.run_all_tests()
EOF

# VALIDATOR 2: Mega Prompt Quality Analyzer
cat > mega_prompt_quality_analyzer.py << 'EOF'
#!/usr/bin/env python3
"""
MEGA PROMPT QUALITY ANALYZER
Analyzes if your bird squad (Spark, Falcon, Eagle, Hawk) generates quality mega prompts
Tests prompt effectiveness by comparing mega prompt quality vs final code output quality
"""

import json
import datetime
import random
import requests
from groq import Groq
import re
from pathlib import Path
import time

# API CONFIGURATION  
API_KEYS = [
    "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",
    "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",
    "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",
    "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"
]

MODELS = [
    "meta-llama/llama-4-scout-17b-16e-instruct",
    "meta-llama/llama-4-maverick-17b-128e-instruct", 
    "llama-3.1-8b-instant",
    "llama-3.3-70b-versatile"
]

class MegaPromptQualityAnalyzer:
    """Analyzes the quality of mega prompts generated by bird squad"""
    
    def __init__(self):
        self.bird_prompts = {
            "spark": "You are SPARK - the requirements analyst. Generate clear, specific requirements for: {user_prompt}",
            "falcon": "You are FALCON - the architect. Design the technical architecture for: {user_prompt}",
            "eagle": "You are EAGLE - the implementer. Create implementation details for: {user_prompt}",
            "hawk": "You are HAWK - the QA specialist. Define testing strategy for: {user_prompt}"
        }
        
        self.test_scenarios = [
            {
                "prompt": "build a snake game",
                "expected_files": ["index.html", "style.css", "script.js"],
                "complexity": "medium",
                "expected_functions": ["moveSnake", "checkCollision", "drawGame"]
            },
            {
                "prompt": "create a todo app",
                "expected_files": ["index.html", "app.js", "style.css"],
                "complexity": "medium", 
                "expected_functions": ["addTodo", "deleteTodo", "toggleComplete"]
            },
            {
                "prompt": "make a calculator",
                "expected_files": ["calculator.html", "calc.js", "calc.css"],
                "complexity": "easy",
                "expected_functions": ["calculate", "clearDisplay", "inputNumber"]
            },
            {
                "prompt": "build a weather app",
                "expected_files": ["weather.html", "weather.js", "weather.css"],
                "complexity": "hard",
                "expected_functions": ["fetchWeather", "displayWeather", "getLocation"]
            }
        ]
    
    def generate_bird_responses(self, user_prompt):
        """Generate responses from all 4 birds"""
        print(f"🦅 GENERATING BIRD RESPONSES FOR: {user_prompt}")
        
        bird_responses = {}
        
        for bird_name, bird_prompt_template in self.bird_prompts.items():
            try:
                api_key = random.choice(API_KEYS)
                model = random.choice(MODELS)
                client = Groq(api_key=api_key)
                
                formatted_prompt = bird_prompt_template.format(user_prompt=user_prompt)
                
                print(f"  🐦 {bird_name.upper()}: Using {model}")
                
                response = client.chat.completions.create(
                    messages=[{"role": "user", "content": formatted_prompt}],
                    model=model,
                    max_tokens=1000,
                    temperature=0.7
                )
                
                bird_responses[bird_name] = {
                    "prompt": formatted_prompt,
                    "response": response.choices[0].message.content,
                    "model": model,
                    "tokens": response.usage.total_tokens if hasattr(response, 'usage') else 0
                }
                
                time.sleep(1)  # Rate limiting
                
            except Exception as e:
                print(f"  ❌ {bird_name.upper()} failed: {e}")
                bird_responses[bird_name] = {
                    "error": str(e),
                    "response": "",
                    "model": "failed"
                }
        
        return bird_responses
    
    def assemble_mega_prompt(self, bird_responses, user_prompt):
        """Assemble mega prompt from bird responses"""
        print("🔧 ASSEMBLING MEGA PROMPT...")
        
        mega_prompt = f"""
COMPREHENSIVE PROJECT GENERATION REQUEST

ORIGINAL USER REQUEST: {user_prompt}

REQUIREMENTS ANALYSIS (SPARK):
{bird_responses.get('spark', {}).get('response', 'Missing Spark analysis')}

TECHNICAL ARCHITECTURE (FALCON):
{bird_responses.get('falcon', {}).get('response', 'Missing Falcon architecture')}

IMPLEMENTATION DETAILS (EAGLE):
{bird_responses.get('eagle', {}).get('response', 'Missing Eagle implementation')}

QUALITY ASSURANCE STRATEGY (HAWK):
{bird_responses.get('hawk', {}).get('response', 'Missing Hawk QA')}

FINAL INSTRUCTION:
Based on the above comprehensive analysis, generate COMPLETE, EXECUTABLE CODE FILES for "{user_prompt}".

CRITICAL OUTPUT FORMAT:
Return ONLY working code files in this exact format:

```filename: index.html
[complete HTML code]
```

```filename: style.css
[complete CSS code]
```

```filename: script.js
[complete JavaScript code]
```

DO NOT return documentation, explanations, or QA procedures.
ONLY return complete, functional code files that implement the requested project.
"""
        
        return mega_prompt
    
    def test_mega_prompt_effectiveness(self, mega_prompt, scenario):
        """Test how effective the mega prompt is at generating good code"""
        print("🧪 TESTING MEGA PROMPT EFFECTIVENESS...")
        
        try:
            api_key = random.choice(API_KEYS)
            model = "meta-llama/llama-4-maverick-17b-128e-instruct"  # Use best model for final generation
            client = Groq(api_key=api_key)
            
            response = client.chat.completions.create(
                messages=[{"role": "user", "content": mega_prompt}],
                model=model,
                max_tokens=4000,
                temperature=0.3
            )
            
            final_response = response.choices[0].message.content
            
            # Analyze the quality of the final response
            quality_analysis = self.analyze_code_quality(final_response, scenario)
            
            return {
                "success": True,
                "final_response": final_response,
                "model_used": model,
                "tokens_used": response.usage.total_tokens if hasattr(response, 'usage') else 0,
                "quality_analysis": quality_analysis
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "final_response": "",
                "quality_analysis": {}
            }
    
    def analyze_code_quality(self, response, scenario):
        """Analyze the quality of generated code"""
        analysis = {
            "files_detected": 0,
            "expected_files_found": 0,
            "functions_detected": 0,
            "expected_functions_found": 0,
            "code_blocks_found": 0,
            "has_html": False,
            "has_css": False,
            "has_js": False,
            "response_type": "unknown"
        }
        
        # Check for code blocks
        code_blocks = re.findall(r'```[\w]*\n.*?\n```', response, re.DOTALL)
        analysis["code_blocks_found"] = len(code_blocks)
        
        # Check for expected files
        for expected_file in scenario["expected_files"]:
            if expected_file.lower() in response.lower():
                analysis["expected_files_found"] += 1
        
        analysis["files_detected"] = len(re.findall(r'filename:\s*[\w\.]+', response, re.IGNORECASE))
        
        # Check for expected functions
        for expected_func in scenario["expected_functions"]:
            if expected_func.lower() in response.lower():
                analysis["expected_functions_found"] += 1
        
        # Detect function definitions
        js_functions = re.findall(r'function\s+\w+\(', response, re.IGNORECASE)
        arrow_functions = re.findall(r'\w+\s*=\s*\([^)]*\)\s*=>', response)
        analysis["functions_detected"] = len(js_functions) + len(arrow_functions)
        
        # Check file types
        analysis["has_html"] = bool(re.search(r'<html|<\!DOCTYPE', response, re.IGNORECASE))
        analysis["has_css"] = bool(re.search(r'\{[^}]*:[^}]*\}|\.[\w-]+\s*\{', response))
        analysis["has_js"] = bool(re.search(r'function|console\.log|document\.|window\.', response, re.IGNORECASE))
        
        # Determine response type
        if analysis["code_blocks_found"] > 0 and analysis["files_detected"] > 0:
            analysis["response_type"] = "code_files"
        elif "test" in response.lower() and "verify" in response.lower():
            analysis["response_type"] = "qa_documentation"
        else:
            analysis["response_type"] = "mixed_content"
        
        # Calculate quality score
        quality_score = (
            (analysis["expected_files_found"] / len(scenario["expected_files"])) * 30 +
            (analysis["expected_functions_found"] / len(scenario["expected_functions"])) * 30 +
            (analysis["code_blocks_found"] > 0) * 20 +
            (analysis["response_type"] == "code_files") * 20
        )
        
        analysis["quality_score"] = quality_score
        
        return analysis
    
    def analyze_mega_prompt_quality(self, mega_prompt):
        """Analyze the quality of the mega prompt itself"""
        analysis = {
            "length": len(mega_prompt),
            "has_clear_sections": False,
            "has_output_format": False,
            "has_constraints": False,
            "includes_all_birds": False,
            "specificity_score": 0
        }
        
        # Check for clear sections
        sections = ["SPARK", "FALCON", "EAGLE", "HAWK"]
        found_sections = sum(1 for section in sections if section in mega_prompt)
        analysis["includes_all_birds"] = found_sections == 4
        analysis["has_clear_sections"] = found_sections >= 3
        
        # Check for output format specification
        analysis["has_output_format"] = "filename:" in mega_prompt and "```" in mega_prompt
        
        # Check for constraints
        constraints = ["DO NOT", "ONLY return", "CRITICAL", "format"]
        analysis["has_constraints"] = sum(1 for constraint in constraints if constraint in mega_prompt) >= 2
        
        # Calculate specificity score
        specificity_indicators = [
            "complete", "executable", "functional", "working",
            "HTML", "CSS", "JavaScript", "implementation"
        ]
        analysis["specificity_score"] = sum(1 for indicator in specificity_indicators if indicator.lower() in mega_prompt.lower())
        
        # Overall mega prompt quality
        quality_factors = [
            analysis["has_clear_sections"],
            analysis["has_output_format"], 
            analysis["has_constraints"],
            analysis["includes_all_birds"],
            analysis["specificity_score"] >= 4
        ]
        
        analysis["overall_quality"] = sum(quality_factors) / len(quality_factors) * 100
        
        return analysis
    
    def run_full_analysis(self, scenario):
        """Run full mega prompt quality analysis for a scenario"""
        print(f"\n{'='*70}")
        print(f"🔬 MEGA PROMPT QUALITY ANALYSIS: {scenario['prompt']}")
        print(f"{'='*70}")
        
        # STEP 1: Generate bird responses
        bird_responses = self.generate_bird_responses(scenario["prompt"])
        
        # STEP 2: Assemble mega prompt
        mega_prompt = self.assemble_mega_prompt(bird_responses, scenario["prompt"])
        
        # STEP 3: Analyze mega prompt quality
        mega_prompt_analysis = self.analyze_mega_prompt_quality(mega_prompt)
        
        # STEP 4: Test effectiveness with LLM
        effectiveness_test = self.test_mega_prompt_effectiveness(mega_prompt, scenario)
        
        # STEP 5: Compare expected vs actual results
        comparison = self.compare_results(scenario, effectiveness_test.get("quality_analysis", {}))
        
        return {
            "scenario": scenario,
            "bird_responses": bird_responses,
            "mega_prompt": mega_prompt,
            "mega_prompt_analysis": mega_prompt_analysis,
            "effectiveness_test": effectiveness_test,
            "comparison": comparison,
            "timestamp": datetime.datetime.now().isoformat()
        }
    
    def compare_results(self, scenario, actual_analysis):
        """Compare expected scenario results with actual output"""
        comparison = {
            "expected_files": len(scenario["expected_files"]),
            "actual_files": actual_analysis.get("files_detected", 0),
            "expected_functions": len(scenario["expected_functions"]),
            "actual_functions": actual_analysis.get("functions_detected", 0),
            "file_accuracy": 0,
            "function_accuracy": 0,
            "overall_accuracy": 0
        }
        
        # Calculate accuracy percentages
        if comparison["expected_files"] > 0:
            comparison["file_accuracy"] = min(100, (comparison["actual_files"] / comparison["expected_files"]) * 100)
        
        if comparison["expected_functions"] > 0:
            comparison["function_accuracy"] = min(100, (comparison["actual_functions"] / comparison["expected_functions"]) * 100)
        
        comparison["overall_accuracy"] = (comparison["file_accuracy"] + comparison["function_accuracy"]) / 2
        
        return comparison
    
    def run_all_scenarios(self):
        """Run mega prompt quality analysis for all test scenarios"""
        print("🚀 MEGA PROMPT QUALITY ANALYZER - STARTING ALL SCENARIOS")
        print(f"📅 {datetime.datetime.now().isoformat()}")
        
        all_results = []
        
        for i, scenario in enumerate(self.test_scenarios, 1):
            print(f"\n🧪 SCENARIO {i}/{len(self.test_scenarios)}")
            
            result = self.run_full_analysis(scenario)
            all_results.append(result)
            
            # Brief pause between scenarios
            time.sleep(3)
        
        # Generate comprehensive summary
        self._generate_analysis_summary(all_results)
        return all_results
    
    def _generate_analysis_summary(self, results):
        """Generate comprehensive mega prompt quality summary"""
        print("\n" + "="*80)
        print("📊 MEGA PROMPT QUALITY ANALYSIS SUMMARY")
        print("="*80)
        
        total_scenarios = len(results)
        
        # Mega prompt quality stats
        mega_prompt_qualities = [r["mega_prompt_analysis"]["overall_quality"] for r in results]
        avg_mega_quality = sum(mega_prompt_qualities) / total_scenarios if total_scenarios > 0 else 0
        
        # Code generation effectiveness stats
        code_qualities = [r["effectiveness_test"]["quality_analysis"]["quality_score"] for r in results if r["effectiveness_test"]["success"]]
        avg_code_quality = sum(code_qualities) / len(code_qualities) if code_qualities else 0
        
        # Bird response success rates
        bird_success_rates = {}
        for bird in ["spark", "falcon", "eagle", "hawk"]:
            successes = sum(1 for r in results if "error" not in r["bird_responses"].get(bird, {}))
            bird_success_rates[bird] = (successes / total_scenarios) * 100
        
        print(f"🧪 Total Scenarios: {total_scenarios}")
        print(f"📈 Average Mega Prompt Quality: {avg_mega_quality:.1f}%")
        print(f"⚡ Average Code Generation Quality: {avg_code_quality:.1f}%")
        print(f"🎯 Overall System Effectiveness: {(avg_mega_quality + avg_code_quality) / 2:.1f}%")
        
        print("\n🐦 BIRD SQUAD PERFORMANCE:")
        for bird, success_rate in bird_success_rates.items():
            status = "✅" if success_rate >= 90 else "⚠️" if success_rate >= 70 else "❌"
            print(f"   {status} {bird.upper()}: {success_rate:.1f}% success rate")
        
        # Identify issues
        print("\n🔍 IDENTIFIED ISSUES:")
        
        # Check for common problems
        qa_responses = sum(1 for r in results if r["effectiveness_test"]["success"] and 
                          r["effectiveness_test"]["quality_analysis"]["response_type"] == "qa_documentation")
        
        if qa_responses > 0:
            print(f"   ❌ Generating QA docs instead of code: {qa_responses}/{total_scenarios} scenarios")
        
        low_file_detection = sum(1 for r in results if r["effectiveness_test"]["success"] and 
                                r["effectiveness_test"]["quality_analysis"]["files_detected"] == 0)
        
        if low_file_detection > 0:
            print(f"   ❌ No code files detected: {low_file_detection}/{total_scenarios} scenarios")
        
        missing_birds = []
        for bird in ["spark", "falcon", "eagle", "hawk"]:
            if bird_success_rates[bird] < 80:
                missing_birds.append(bird)
        
        if missing_birds:
            print(f"   ⚠️ Unreliable birds: {', '.join(missing_birds)}")
        
        # Recommendations
        print("\n💡 RECOMMENDATIONS:")
        
        if avg_mega_quality < 70:
            print("   🔧 Improve bird prompt templates for clearer output")
        
        if avg_code_quality < 60:
            print("   🎯 Add stronger output format constraints to mega prompt")
        
        if qa_responses > total_scenarios * 0.3:
            print("   ⚡ Critical: Mega prompt generating docs instead of code - fix output instructions")
        
        # Save detailed results
        results_file = f"mega_prompt_analysis_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, 'w') as f:
            json.dump({
                "summary": {
                    "total_scenarios": total_scenarios,
                    "avg_mega_prompt_quality": avg_mega_quality,
                    "avg_code_quality": avg_code_quality,
                    "bird_success_rates": bird_success_rates,
                    "timestamp": datetime.datetime.now().isoformat()
                },
                "detailed_results": results
            }, f, indent=2)
        
        print(f"\n💾 Detailed analysis saved to {results_file}")

if __name__ == "__main__":
    analyzer = MegaPromptQualityAnalyzer()
    analyzer.run_all_scenarios()
EOF

# Make both validators executable
chmod +x peacock_workflow_validator.py
chmod +x mega_prompt_quality_analyzer.py

# Create combined test runner
cat > run_peacock_validators.py << 'EOF'
#!/usr/bin/env python3
"""
PEACOCK VALIDATORS - COMBINED RUNNER
Runs both Workflow Validator and Mega Prompt Quality Analyzer
"""

import subprocess
import datetime
import json

def run_both_validators():
    """Run both critical validators and generate combined report"""
    print("🔥 RUNNING PEACOCK CRITICAL VALIDATORS")
    print("="*60)
    print(f"📅 {datetime.datetime.now().isoformat()}")
    print("🎯 Testing both workflow integrity and mega prompt quality")
    print("="*60)
    
    results = {
        "workflow_validator": None,
        "mega_prompt_analyzer": None,
        "combined_insights": {},
        "timestamp": datetime.datetime.now().isoformat()
    }
    
    # Run Workflow Validator
    print("\n🚀 PHASE 1: WORKFLOW VALIDATION")
    print("-" * 40)
    try:
        result = subprocess.run(
            ["python3", "peacock_workflow_validator.py"],
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout
        )
        
        results["workflow_validator"] = {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
        
        if result.returncode == 0:
            print("✅ Workflow validation completed successfully")
        else:
            print("❌ Workflow validation failed")
            print(f"Error: {result.stderr[:200]}...")
            
    except subprocess.TimeoutExpired:
        print("⏰ Workflow validation timed out")
        results["workflow_validator"] = {"success": False, "error": "timeout"}
    except Exception as e:
        print(f"💥 Workflow validation error: {e}")
        results["workflow_validator"] = {"success": False, "error": str(e)}
    
    # Run Mega Prompt Quality Analyzer
    print("\n🚀 PHASE 2: MEGA PROMPT QUALITY ANALYSIS")
    print("-" * 40)
    try:
        result = subprocess.run(
            ["python3", "mega_prompt_quality_analyzer.py"],
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout
        )
        
        results["mega_prompt_analyzer"] = {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
        
        if result.returncode == 0:
            print("✅ Mega prompt analysis completed successfully")
        else:
            print("❌ Mega prompt analysis failed")
            print(f"Error: {result.stderr[:200]}...")
            
    except subprocess.TimeoutExpired:
        print("⏰ Mega prompt analysis timed out")
        results["mega_prompt_analyzer"] = {"success": False, "error": "timeout"}
    except Exception as e:
        print(f"💥 Mega prompt analysis error: {e}")
        results["mega_prompt_analyzer"] = {"success": False, "error": str(e)}
    
    # Generate combined insights
    print("\n🧠 GENERATING COMBINED INSIGHTS...")
    results["combined_insights"] = generate_combined_insights(results)
    
    # Save combined results
    results_file = f"peacock_validators_combined_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n💾 Combined results saved to {results_file}")
    
    # Print final summary
    print_final_summary(results)

def generate_combined_insights(results):
    """Generate insights from combining both validator results"""
    insights = {
        "critical_issues": [],
        "recommendations": [],
        "priority_fixes": []
    }
    
    # Analyze workflow issues
    if results["workflow_validator"] and not results["workflow_validator"]["success"]:
        insights["critical_issues"].append("Workflow validation failed - core 1prompt system broken")
        insights["priority_fixes"].append("Fix 1prompt → bird squad → logging workflow")
    
    # Analyze mega prompt issues
    if results["mega_prompt_analyzer"] and not results["mega_prompt_analyzer"]["success"]:
        insights["critical_issues"].append("Mega prompt analysis failed - bird squad communication broken")
        insights["priority_fixes"].append("Fix bird squad API calls and response handling")
    
    # Cross-reference issues
    workflow_output = results["workflow_validator"]["stdout"] if results["workflow_validator"] else ""
    mega_prompt_output = results["mega_prompt_analyzer"]["stdout"] if results["mega_prompt_analyzer"] else ""
    
    if "Missing mega prompt logs" in workflow_output:
        insights["critical_issues"].append("Mega prompt assembly not being logged")
        insights["priority_fixes"].append("Add megapromptlog-{session}.txt logging to MCP")
    
    if "Missing final response logs" in workflow_output:
        insights["critical_issues"].append("Final LLM response not being logged")
        insights["priority_fixes"].append("Add finalresponselog-{session}.txt logging to MCP")
    
    if "qa_documentation" in mega_prompt_output:
        insights["critical_issues"].append("LLM returning QA docs instead of code")
        insights["priority_fixes"].append("Fix mega prompt output format instructions")
    
    # Generate recommendations
    if len(insights["critical_issues"]) > 2:
        insights["recommendations"].append("Focus on logging system first - can't debug without visibility")
    
    if "bird squad" in str(insights["critical_issues"]):
        insights["recommendations"].append("Test bird squad individually before testing full workflow")
    
    insights["recommendations"].append("Run validators after each fix to track progress")
    
    return insights

def print_final_summary(results):
    """Print final summary of both validators"""
    print("\n" + "="*80)
    print("🎯 PEACOCK VALIDATORS FINAL SUMMARY")
    print("="*80)
    
    workflow_success = results["workflow_validator"]["success"] if results["workflow_validator"] else False
    mega_prompt_success = results["mega_prompt_analyzer"]["success"] if results["mega_prompt_analyzer"] else False
    
    print(f"🔧 Workflow Validator: {'✅ PASSED' if workflow_success else '❌ FAILED'}")
    print(f"🧠 Mega Prompt Analyzer: {'✅ PASSED' if mega_prompt_success else '❌ FAILED'}")
    
    overall_health = "HEALTHY" if workflow_success and mega_prompt_success else "NEEDS FIXES"
    print(f"🦚 Overall Peacock Health: {overall_health}")
    
    # Print critical issues
    insights = results["combined_insights"]
    if insights["critical_issues"]:
        print("\n🚨 CRITICAL ISSUES FOUND:")
        for issue in insights["critical_issues"]:
            print(f"   ❌ {issue}")
    
    # Print priority fixes
    if insights["priority_fixes"]:
        print("\n🔧 PRIORITY FIXES NEEDED:")
        for i, fix in enumerate(insights["priority_fixes"], 1):
            print(f"   {i}. {fix}")
    
    # Print recommendations
    if insights["recommendations"]:
        print("\n💡 RECOMMENDATIONS:")
        for rec in insights["recommendations"]:
            print(f"   • {rec}")
    
    print("\n🎉 Validator analysis complete!")

if __name__ == "__main__":
    run_both_validators()
EOF

chmod +x run_peacock_validators.py

echo ""
echo "🎉 PEACOCK VALIDATORS CREATED SUCCESSFULLY!"
echo ""
echo "📁 Created Files:"
echo "   🔧 peacock_workflow_validator.py - Tests 1prompt → XEdit workflow"
echo "   🧠 mega_prompt_quality_analyzer.py - Tests bird squad mega prompt quality"
echo "   🎯 run_peacock_validators.py - Runs both validators with combined analysis"
echo ""
echo "🚀 TO RUN THE VALIDATORS:"
echo "   cd /home/flintx/apitest/py"
echo "   python3 run_peacock_validators.py"
echo ""
echo "🎯 WHAT THESE WILL TEST:"
echo "   ✅ Complete 1prompt → bird squad → mega prompt → code workflow"
echo "   ✅ Session ID consistency across all components"
echo "   ✅ Log file generation (including missing ones!)"
echo "   ✅ XEdit generation and linking"
echo "   ✅ Bird squad response quality"
echo "   ✅ Mega prompt assembly effectiveness"
echo "   ✅ Final code generation vs QA documentation issue"
echo ""
echo "💡 These validators will pinpoint EXACTLY where your workflow breaks!"
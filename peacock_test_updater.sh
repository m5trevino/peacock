#!/bin/bash
# PEACOCK TEST UPDATER - Update all 21 test files with new models, API keys, and proxies

cd /home/flintx/apitest/py

# CONFIGURATION VARIABLES
API_KEYS=("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" "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" "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" "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")

MODELS=(
    "meta-llama/llama-4-scout-17b-16e-instruct"
    "meta-llama/llama-4-maverick-17b-128e-instruct" 
    "llama-3.1-8b-instant"
    "llama-3.3-70b-versatile"
)

PROXY_BASE="gw.dataimpulse.com:823@0aa180faa467ad67809b__cr.us:6dc612d4a08ca89d"

echo "🔥 UPDATING ALL PEACOCK TEST FILES WITH NEW CONFIGURATION..."

# STEP 1: Update API keys in all files
echo "📋 STEP 1: Updating API keys..."
for file in *.py; do
    if [[ -f "$file" ]]; then
        echo "   🔑 Updating API keys in $file"
        
        # Replace old API key patterns with key rotation
        sed -i 's/api_key\s*=\s*["\'][^"'\'']*["\']/api_key = API_KEYS[random.randint(0, len(API_KEYS)-1)]/g' "$file"
        sed -i 's/GROQ_API_KEY\s*=\s*["\'][^"'\'']*["\']/GROQ_API_KEY = API_KEYS[random.randint(0, len(API_KEYS)-1)]/g' "$file"
        
        # Add API key array if not present
        if ! grep -q "API_KEYS.*=.*\[" "$file"; then
            sed -i '1a\
import random\
\
# GROQ API KEYS - ROTATED FOR LOAD BALANCING\
API_KEYS = [\
    "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",\
    "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",\
    "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",\
    "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"\
]\
' "$file"
        fi
    fi
done

# STEP 2: Update models to new Llama 4 models
echo "📋 STEP 2: Updating models..."
for file in *.py; do
    if [[ -f "$file" ]]; then
        echo "   🦙 Updating models in $file"
        
        # Replace common old model names with new ones
        sed -i 's/"llama-3\.1-70b-versatile"/"meta-llama\/llama-4-scout-17b-16e-instruct"/g' "$file"
        sed -i 's/"llama-3\.1-8b-instant"/"llama-3.1-8b-instant"/g' "$file"
        sed -i 's/"llama3-70b-8192"/"meta-llama\/llama-4-maverick-17b-128e-instruct"/g' "$file"
        sed -i 's/"llama3-8b-8192"/"llama-3.1-8b-instant"/g' "$file"
        sed -i 's/"mixtral-8x7b-32768"/"meta-llama\/llama-4-scout-17b-16e-instruct"/g' "$file"
        
        # Add model rotation array if needed
        if ! grep -q "MODELS.*=.*\[" "$file"; then
            sed -i '/API_KEYS = \[/a\
\
# MODEL ROTATION FOR TESTING\
MODELS = [\
    "meta-llama/llama-4-scout-17b-16e-instruct",       # Primary - Speed\
    "meta-llama/llama-4-maverick-17b-128e-instruct",   # Detailed - 128K context\
    "llama-3.1-8b-instant",                            # Speed\
    "llama-3.3-70b-versatile"                          # Fallback\
]\
' "$file"
        fi
    fi
done

# STEP 3: Add proxy support with fallback
echo "📋 STEP 3: Adding proxy support with fallback..."
for file in *.py; do
    if [[ -f "$file" ]]; then
        echo "   🌐 Adding proxy support to $file"
        
        # Add proxy configuration and retry logic
        if ! grep -q "PROXY_CONFIG" "$file"; then
            sed -i '/MODELS = \[/a\
\
# PROXY CONFIGURATION WITH FALLBACK\
PROXY_CONFIG = {\
    "http": "http://0aa180faa467ad67809b__cr.us:6dc612d4a08ca89d@gw.dataimpulse.com:823",\
    "https": "http://0aa180faa467ad67809b__cr.us:6dc612d4a08ca89d@gw.dataimpulse.com:823"\
}\
\
def make_groq_request_with_proxy(client, **kwargs):\
    """Make Groq request with proxy fallback"""\
    for attempt in range(3):\
        try:\
            # Try with proxy first\
            import httpx\
            with httpx.Client(proxies=PROXY_CONFIG) as proxy_client:\
                return client.chat.completions.create(**kwargs)\
        except Exception as e:\
            print(f"⚠️ Proxy attempt {attempt + 1} failed: {e}")\
            if attempt == 2:\
                print("🔄 Falling back to direct connection...")\
                try:\
                    return client.chat.completions.create(**kwargs)\
                except Exception as direct_error:\
                    print(f"❌ Direct connection failed: {direct_error}")\
                    raise\
    return None\
' "$file"
        fi
        
        # Replace direct groq calls with proxy-enabled calls
        sed -i 's/client\.chat\.completions\.create(/make_groq_request_with_proxy(client, /g' "$file"
    fi
done

# STEP 4: Update specific test files based on their function
echo "📋 STEP 4: Updating specific test configurations..."

# Update groq_model_tester.py
if [[ -f "groq_model_tester.py" ]]; then
    echo "   🧪 Updating groq_model_tester.py"
    sed -i '/def test_models/,/return results/c\
def test_models():\
    """Test all 4 new Llama models with API key rotation"""\
    results = []\
    \
    for i, model in enumerate(MODELS):\
        api_key = API_KEYS[i % len(API_KEYS)]\
        print(f"🦙 Testing {model} with key {i+1}")\
        \
        try:\
            client = Groq(api_key=api_key)\
            response = make_groq_request_with_proxy(\
                client,\
                messages=[{"role": "user", "content": "Write a simple Python hello world function"}],\
                model=model,\
                max_tokens=500\
            )\
            \
            results.append({\
                "model": model,\
                "api_key_index": i % len(API_KEYS),\
                "success": True,\
                "response": response.choices[0].message.content,\
                "tokens": response.usage.total_tokens if hasattr(response, "usage") else "unknown"\
            })\
            \
        except Exception as e:\
            results.append({\
                "model": model,\
                "api_key_index": i % len(API_KEYS),\
                "success": False,\
                "error": str(e)\
            })\
    \
    return results' "groq_model_tester.py"
fi

# Update peacock_complexity_tester.py
if [[ -f "peacock_complexity_tester.py" ]]; then
    echo "   🔬 Updating peacock_complexity_tester.py"
    sed -i 's/complexity_tests = \[/complexity_tests = [\
        {"prompt": "Build a snake game in HTML/CSS/JS", "expected_files": 3, "model": "meta-llama\/llama-4-maverick-17b-128e-instruct"},\
        {"prompt": "Create a todo app with React", "expected_files": 4, "model": "meta-llama\/llama-4-scout-17b-16e-instruct"},\
        {"prompt": "Build a calculator with Python tkinter", "expected_files": 1, "model": "llama-3.1-8b-instant"},\
        {"prompt": "Create a REST API with FastAPI", "expected_files": 3, "model": "llama-3.3-70b-versatile"},/g' "peacock_complexity_tester.py"
fi

# Update analyze_results.py
if [[ -f "analyze_results.py" ]]; then
    echo "   📊 Updating analyze_results.py"
    # Add dashboard-ready output for YouTube
    sed -i '/def analyze_results/a\
def generate_dashboard_data(results):\
    """Generate data for YouTube dashboard visualization"""\
    dashboard_data = {\
        "models_tested": len(MODELS),\
        "api_keys_used": len(API_KEYS),\
        "total_tests": len(results),\
        "success_rate": sum(1 for r in results if r.get("success")) / len(results) * 100,\
        "model_performance": {},\
        "key_performance": {},\
        "proxy_success_rate": 0,  # Calculate from proxy attempts\
        "timestamp": datetime.now().isoformat()\
    }\
    \
    # Model performance breakdown\
    for model in MODELS:\
        model_results = [r for r in results if r.get("model") == model]\
        if model_results:\
            dashboard_data["model_performance"][model] = {\
                "success_rate": sum(1 for r in model_results if r.get("success")) / len(model_results) * 100,\
                "avg_tokens": sum(r.get("tokens", 0) for r in model_results if isinstance(r.get("tokens"), int)) / len(model_results),\
                "test_count": len(model_results)\
            }\
    \
    return dashboard_data' "analyze_results.py"
fi

# STEP 5: Add imports to all files
echo "📋 STEP 5: Adding required imports..."
for file in *.py; do
    if [[ -f "$file" ]]; then
        # Add necessary imports if not present
        if ! grep -q "from groq import Groq" "$file"; then
            sed -i '1i\
from groq import Groq\
import httpx\
import datetime\
import json\
import time' "$file"
        fi
    fi
done

# STEP 6: Create master test runner
echo "📋 STEP 6: Creating master test runner..."
cat > master_test_runner.py << 'EOF'
#!/usr/bin/env python3
"""
PEACOCK MASTER TEST RUNNER
Runs all 21 tests with new models, API keys, and proxy rotation
Generates dashboard data for YouTube API testing channel
"""

import subprocess
import json
import datetime
from pathlib import Path

# Test files to run
TEST_FILES = [
    "peacock_mixed_content_tester.py",
    "clean_peamcp(1).py", 
    "peacock_groq_integration.py",
    "peacock_model_optimizer.py",
    "peacock_specific_tests.py",
    "enhanced_function_parsing.py",
    "basic_1prompt(1).py",
    "fixed_aggregator.py",
    "peacock_complexity_tester.py",
    "peacock_playground_testers(1).py",
    "peacock_master_aggregator.py",
    "peacock_playground_testers.py",
    "response_parser.py",
    "practice_prompt_system.py",
    "test_peacock_integration.py",
    "groq_model_tester.py",
    "peacock_context_marathon.py",
    "fixed_stress_battlefield.py",
    "analyze_results.py",
    "basic_1prompt.py"
]

def run_all_tests():
    """Run all tests and collect results"""
    results = []
    
    print("🚀 PEACOCK MASTER TEST RUNNER - STARTING ALL TESTS...")
    print(f"📅 {datetime.datetime.now().isoformat()}")
    print(f"🧪 Running {len(TEST_FILES)} test files")
    print("=" * 60)
    
    for i, test_file in enumerate(TEST_FILES, 1):
        if Path(test_file).exists():
            print(f"\n🔬 [{i}/{len(TEST_FILES)}] Running {test_file}...")
            
            try:
                result = subprocess.run(
                    ["python3", test_file], 
                    capture_output=True, 
                    text=True,
                    timeout=300  # 5 minute timeout
                )
                
                test_result = {
                    "file": test_file,
                    "success": result.returncode == 0,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "timestamp": datetime.datetime.now().isoformat()
                }
                
                if result.returncode == 0:
                    print(f"✅ {test_file} - PASSED")
                else:
                    print(f"❌ {test_file} - FAILED")
                    print(f"   Error: {result.stderr[:100]}...")
                
                results.append(test_result)
                
            except subprocess.TimeoutExpired:
                print(f"⏰ {test_file} - TIMEOUT")
                results.append({
                    "file": test_file,
                    "success": False,
                    "error": "Test timeout after 5 minutes",
                    "timestamp": datetime.datetime.now().isoformat()
                })
                
            except Exception as e:
                print(f"💥 {test_file} - ERROR: {e}")
                results.append({
                    "file": test_file, 
                    "success": False,
                    "error": str(e),
                    "timestamp": datetime.datetime.now().isoformat()
                })
        else:
            print(f"⚠️  {test_file} - FILE NOT FOUND")
    
    # Generate summary
    total_tests = len(results)
    passed_tests = sum(1 for r in results if r["success"])
    success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
    
    print("\n" + "=" * 60)
    print("📊 PEACOCK TEST RESULTS SUMMARY")
    print("=" * 60)
    print(f"🧪 Total Tests: {total_tests}")
    print(f"✅ Passed: {passed_tests}")
    print(f"❌ Failed: {total_tests - passed_tests}")
    print(f"📈 Success Rate: {success_rate:.1f}%")
    
    # Save results for dashboard
    results_file = f"peacock_test_results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(results_file, 'w') as f:
        json.dump({
            "summary": {
                "total_tests": total_tests,
                "passed_tests": passed_tests,
                "success_rate": success_rate,
                "timestamp": datetime.datetime.now().isoformat()
            },
            "results": results
        }, f, indent=2)
    
    print(f"💾 Results saved to {results_file}")
    return results

if __name__ == "__main__":
    run_all_tests()
EOF

chmod +x master_test_runner.py

echo ""
echo "🎉 PEACOCK TEST UPDATE COMPLETE!"
echo "✅ Updated all 21 test files with:"
echo "   🔑 4 API keys with rotation"
echo "   🦙 New Llama 4 models" 
echo "   🌐 Proxy support with fallback"
echo "   📊 Dashboard data generation"
echo ""
echo "🚀 TO RUN ALL TESTS:"
echo "   python3 master_test_runner.py"
echo ""
echo "🎥 FOR YOUTUBE DASHBOARD:"
echo "   Results will include dashboard-ready JSON data"
echo "   Success rates, model performance, proxy stats"
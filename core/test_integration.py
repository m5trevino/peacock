#!/usr/bin/env python3
"""
Test Peacock Integration
Verify that all components work together correctly
"""

import json
import requests
import time
from pathlib import Path

def test_mcp_server():
    """Test that the MCP server is running and responsive"""
    try:
        response = requests.get("http://127.0.0.1:8000/", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ MCP Server is running: {data.get('service', 'Unknown')}")
            return True
        else:
            print(f"❌ MCP Server returned status {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ MCP Server not reachable: {e}")
        return False

def test_pipeline_request():
    """Test a full pipeline request"""
    test_prompt = "Build a simple calculator with HTML, CSS, and JavaScript"
    
    payload = {
        "command": "peacock_full",
        "text": test_prompt,
        "timestamp": "test-session",
        "final_model_choice": "qwen-32b-instruct"
    }
    
    try:
        print(f"🧪 Testing pipeline with prompt: {test_prompt}")
        response = requests.post(
            "http://127.0.0.1:8000/process",
            json=payload,
            timeout=120  # 2 minutes timeout
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                print("✅ Pipeline request successful")
                
                # Check stage results
                stage_results = data.get("stage_results", {})
                for stage, result in stage_results.items():
                    chars = result.get("chars", result.get("char_count", 0))
                    print(f"   {stage.upper()}: {chars} chars")
                
                # Check XEdit file
                xedit_path = data.get("xedit_file_path")
                if xedit_path and Path(xedit_path).exists():
                    print(f"✅ XEdit file generated: {xedit_path}")
                else:
                    print(f"⚠️ XEdit file not found: {xedit_path}")
                
                return True
            else:
                print(f"❌ Pipeline failed: {data.get('error')}")
                return False
        else:
            print(f"❌ Request failed with status {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")
        return False

def test_file_structure():
    """Test that all necessary files and directories exist"""
    required_paths = [
        "/home/flintx/peacock/html",
        "/home/flintx/peacock/core/logs",
        "/home/flintx/peacock/core/1prompt.py",
        "/home/flintx/peacock/core/pea-mcp-1.py",
        "/home/flintx/peacock/aviary/out_homing.py",
        "/home/flintx/peacock/aviary/in_homing.py"
    ]
    
    all_exist = True
    for path in required_paths:
        if Path(path).exists():
            print(f"✅ {path}")
        else:
            print(f"❌ {path} - NOT FOUND")
            all_exist = False
    
    return all_exist

def main():
    """Run all integration tests"""
    print("🧪 TESTING PEACOCK INTEGRATION")
    print("=" * 50)
    
    tests = [
        ("File Structure", test_file_structure),
        ("MCP Server", test_mcp_server),
        ("Pipeline Request", test_pipeline_request)
    ]
    
    passed = 0
    for name, test_func in tests:
        print(f"\n🧪 Testing {name}...")
        if test_func():
            passed += 1
        else:
            print(f"❌ {name} test failed")
    
    print("\n" + "=" * 50)
    print(f"📊 RESULTS: {passed}/{len(tests)} tests passed")
    
    if passed == len(tests):
        print("🎉 All tests passed! Peacock integration is working correctly.")
    else:
        print("⚠️ Some tests failed. Check the output above for details.")

if __name__ == "__main__":
    main()
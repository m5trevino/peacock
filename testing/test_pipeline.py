#!/usr/bin/env python3
"""
Test the full Peacock pipeline: Input → Spark → LLM2 → Professional HTML
"""

import requests
import json
import webbrowser
import sys

def test_full_peacock_pipeline(user_request):
    """Test the complete Peacock pipeline"""
    
    print("🦚 TESTING FULL PEACOCK PIPELINE")
    print("=" * 50)
    print(f"User Request: {user_request}")
    print()
    
    # Send to MCP with peacock_full command
    payload = {
        "command": "peacock_full",
        "text": user_request,
        "language": "project_analysis",
        "original_request": user_request
    }
    
    try:
        print("🔄 Sending to Enhanced MCP...")
        response = requests.post(
            "http://127.0.0.1:8000/process",
            json=payload,
            timeout=120
        )
        
        if response.status_code == 200:
            result = response.json()
            
            if result.get("status") == "success":
                print("✅ PIPELINE SUCCESS!")
                print()
                
                internal_data = result.get("internal_data", {})
                
                # Show pipeline stages
                if "pipeline_stages" in internal_data:
                    print("📊 PIPELINE STAGES:")
                    for stage, status in internal_data["pipeline_stages"].items():
                        print(f"   {stage}: {status}")
                    print()
                
                # Show file count
                if "file_count" in internal_data:
                    print(f"📁 Generated {internal_data['file_count']} files")
                    print()
                
                # Open HTML report
                html_path = result.get("report_filepath")
                if html_path:
                    print(f"🌐 Opening HTML report: {html_path}")
                    webbrowser.open(f"file://{html_path}")
                    return True
                else:
                    print("❌ No HTML report generated")
                    return False
            else:
                print(f"❌ MCP Error: {result.get('message')}")
                return False
        else:
            print(f"❌ HTTP Error: {response.status_code}")
            print(response.text)
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Enhanced MCP server not running!")
        print("Start it with: python enhanced_mcp_server.py")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1:
        user_request = " ".join(sys.argv[1:])
    else:
        user_request = input("🎯 What do you want to build? ")
    
    if user_request.strip():
        success = test_full_peacock_pipeline(user_request)
        if success:
            print("\n🎉 Full Peacock pipeline working perfectly!")
        else:
            print("\n❌ Pipeline test failed")
    else:
        print("❌ Please provide a project request")
#!/usr/bin/env python3
import requests
import json
import webbrowser
import sys

def test_full_peacock_pipeline(user_request):
    print("🦚 TESTING FULL PEACOCK PIPELINE")
    print("=" * 50)
    print(f"User Request: {user_request}")
    print()
    
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
                internal_data = result.get("internal_data", {})
                
                if "pipeline_stages" in internal_data:
                    print("📊 PIPELINE STAGES:")
                    for stage, status in internal_data["pipeline_stages"].items():
                        print(f"   {stage}: {status}")
                
                if "file_count" in internal_data:
                    print(f"📁 Generated {internal_data['file_count']} files")
                
                html_path = result.get("report_filepath")
                if html_path:
                    print(f"🌐 Opening HTML report: {html_path}")
                    webbrowser.open(f"file://{html_path}")
                    return True
                    
        print(f"❌ Error: {response.status_code}")
        return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Enhanced MCP server not running!")
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
        test_full_peacock_pipeline(user_request)

#!/usr/bin/env python3
"""
Simple MCP Server that doesn't hang - for testing
"""

import http.server
import socketserver
import json
import sys
import traceback
from pathlib import Path

# Configuration
HOST = "127.0.0.1"
PORT = 8000

# API Configuration
GROQ_API_KEY = "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"
GROQ_MODEL_NAME = "qwen-qwq-32b"

def call_groq_api(prompt):
    """Simple Groq API call"""
    try:
        from groq import Groq
        client = Groq(api_key=GROQ_API_KEY)
        chat_completion = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model=GROQ_MODEL_NAME,
            temperature=0.1,
            max_tokens=4000
        )
        return {"success": True, "text": chat_completion.choices[0].message.content}
    except Exception as e:
        return {"error": f"Groq API call failed: {str(e)}"}

class SimpleMCPHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return  # Disable logging
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            health_data = {"status": "healthy", "model": GROQ_MODEL_NAME, "api": "groq"}
            self.wfile.write(json.dumps(health_data).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/process":
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                received_data = json.loads(post_data.decode('utf-8'))
                
                command = received_data.get('command', 'unknown')
                text = received_data.get('text', '')
                
                print(f"🦚 Processing: {command} - {text[:50]}...")
                
                if command == "peacock_full":
                    prompt = f"""Generate a complete, working {text} application.

Create a fully functional implementation with:
1. Complete code ready to run
2. Proper error handling  
3. Modern best practices

Format the output as:
```filename: main.py
[complete code here]
```

Generate working code now:
"""
                    
                    llm_response = call_groq_api(prompt)
                    
                    if llm_response.get("success"):
                        response_payload = {
                            "status": "success",
                            "command": command,
                            "message": "Code generated successfully with GROQ qwen-qwq-32b",
                            "result_text": llm_response.get("text", ""),
                            "model": GROQ_MODEL_NAME
                        }
                        
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.send_header("Access-Control-Allow-Origin", "*")
                        self.end_headers()
                        self.wfile.write(json.dumps(response_payload).encode('utf-8'))
                    else:
                        error_payload = {
                            "status": "error", 
                            "message": llm_response.get("error", "Unknown error")
                        }
                        self.send_response(500)
                        self.send_header('Content-type', 'application/json')
                        self.send_header("Access-Control-Allow-Origin", "*")
                        self.end_headers()
                        self.wfile.write(json.dumps(error_payload).encode('utf-8'))
                else:
                    error_payload = {"status": "error", "message": f"Unknown command: {command}"}
                    self.send_response(400)
                    self.send_header('Content-type', 'application/json')
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    self.wfile.write(json.dumps(error_payload).encode('utf-8'))
                    
            except Exception as e:
                print(f"❌ Error: {e}")
                error_payload = {"status": "error", "message": str(e)}
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps(error_payload).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == "__main__":
    print(f"🦚 Simple MCP Server starting on {HOST}:{PORT}")
    print(f"🔥 Using GROQ {GROQ_MODEL_NAME}")
    
    with socketserver.TCPServer((HOST, PORT), SimpleMCPHandler) as httpd:
        httpd.allow_reuse_address = True
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🦚 Server stopped.")

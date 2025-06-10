#!/usr/bin/env python3
"""
1prompt.py - BASIC BLUNT WRAP DELIVERY SERVICE
ONE JOB: Take request, hand to MCP, confirm delivery. THAT'S IT.
"""

import datetime
import webbrowser
import sys
from pathlib import Path

# BASIC PATHS
HTML_OUTPUT_DIR = Path("/home/flintx/peacock/html")

def get_session_timestamp():
    """Simple timestamp for file naming"""
    now = datetime.datetime.now()
    week = now.isocalendar()[1]
    day = now.day
    hour = now.hour
    minute = now.minute
    return f"{week}-{day}-{hour}{minute:02d}"

def generate_basic_interface(session_timestamp):
    """Generate BASIC interface - no technical bullshit"""
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🦚 Peacock Project Builder</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'SF Mono', monospace; 
            background: #0d1117; 
            color: #e6edf3; 
            height: 100vh; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
        }}
        
        .container {{ 
            background: #161b22; 
            border: 1px solid #30363d; 
            border-radius: 12px; 
            padding: 40px; 
            max-width: 600px; 
            width: 90%; 
            text-align: center; 
        }}
        
        .logo {{ 
            font-size: 24px; 
            font-weight: bold; 
            color: #ff6b35; 
            margin-bottom: 30px; 
        }}
        
        .input-container {{ 
            margin-bottom: 30px; 
        }}
        
        .prompt-input {{ 
            width: 100%; 
            padding: 16px 20px; 
            background: #0d1117; 
            border: 2px solid #30363d; 
            border-radius: 8px; 
            color: #e6edf3; 
            font-size: 16px; 
            font-family: inherit;
            margin-bottom: 20px;
        }}
        
        .prompt-input:focus {{ 
            outline: none; 
            border-color: #ff6b35; 
        }}
        
        .send-btn {{ 
            padding: 16px 32px; 
            background: linear-gradient(45deg, #ff6b35, #ff8c5a); 
            border: none; 
            border-radius: 8px; 
            color: white; 
            font-weight: 600; 
            font-size: 16px;
            cursor: pointer; 
            transition: all 0.2s; 
        }}
        
        .send-btn:hover {{ 
            transform: translateY(-2px); 
            box-shadow: 0 4px 12px rgba(255, 107, 53, 0.3); 
        }}
        
        .send-btn:disabled {{ 
            background: #30363d; 
            color: #8b949e; 
            cursor: not-allowed; 
            transform: none; 
        }}
        
        .status {{ 
            margin-top: 30px; 
            padding: 16px; 
            border-radius: 8px; 
            font-size: 14px; 
            display: none;
        }}
        
        .status.processing {{ 
            display: block;
            background: rgba(255, 107, 53, 0.1); 
            border: 1px solid #ff6b35; 
            color: #ff6b35; 
        }}
        
        .status.complete {{ 
            display: block;
            background: rgba(35, 134, 54, 0.1); 
            border: 1px solid #238636; 
            color: #238636; 
        }}
        
        .status.error {{ 
            display: block;
            background: rgba(218, 54, 51, 0.1); 
            border: 1px solid #da3633; 
            color: #da3633; 
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🦚 Peacock Project Builder</div>
        
        <div class="input-container">
            <input type="text" 
                   class="prompt-input" 
                   id="promptInput" 
                   placeholder="Describe your project..." />
            <button class="send-btn" id="sendBtn" onclick="buildProject()">
                Build Project
            </button>
        </div>
        
        <div class="status processing" id="processingStatus">
            🔄 Building your project...
        </div>
        
        <div class="status complete" id="completeStatus">
            ✅ Project complete! Your files have been generated.
        </div>
        
        <div class="status error" id="errorStatus">
            ❌ Something went wrong. Please try again.
        </div>
    </div>

    <script>
        async function buildProject() {{
            const promptInput = document.getElementById('promptInput');
            const sendBtn = document.getElementById('sendBtn');
            const processingStatus = document.getElementById('processingStatus');
            const completeStatus = document.getElementById('completeStatus');
            const errorStatus = document.getElementById('errorStatus');
            
            const prompt = promptInput.value.trim();
            
            if (!prompt) {{
                alert('Please describe your project');
                return;
            }}

            // Hide all status
            processingStatus.style.display = 'none';
            completeStatus.style.display = 'none';
            errorStatus.style.display = 'none';
            
            // Show processing
            processingStatus.style.display = 'block';
            promptInput.disabled = true;
            sendBtn.disabled = true;
            sendBtn.textContent = 'Building...';

            try {{
                const response = await fetch('http://127.0.0.1:8000/process', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{
                        command: 'peacock_full',
                        text: prompt
                    }})
                }});

                if (!response.ok) {{
                    throw new Error(`HTTP ${{response.status}}`);
                }}

                const result = await response.json();
                
                // Hide processing
                processingStatus.style.display = 'none';
                
                if (result.success) {{
                    // Show complete
                    completeStatus.style.display = 'block';
                }} else {{
                    throw new Error(result.error || 'Build failed');
                }}

            }} catch (error) {{
                // Hide processing
                processingStatus.style.display = 'none';
                // Show error
                errorStatus.style.display = 'block';
                console.error('Build error:', error);
            }} finally {{
                // Re-enable input
                promptInput.disabled = false;
                sendBtn.disabled = false;
                sendBtn.textContent = 'Build Project';
            }}
        }}

        // Enable Enter key
        document.getElementById('promptInput').addEventListener('keypress', function(e) {{
            if (e.key === 'Enter') {{
                buildProject();
            }}
        }});
    </script>
</body>
</html>"""
    
    output_path = HTML_OUTPUT_DIR / f"1prompt-basic-{session_timestamp}.html"
    HTML_OUTPUT_DIR.mkdir(exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return output_path

def main():
    """BASIC main function - no extra bullshit"""
    print("🦚 BASIC 1PROMPT - BLUNT WRAP DELIVERY SERVICE")
    print("="*50)
    
    session_timestamp = get_session_timestamp()
    
    # Generate basic interface
    interface_file = generate_basic_interface(session_timestamp)
    
    print(f"✅ Basic interface generated: {interface_file}")
    
    # Open in browser
    webbrowser.open(f"file://{interface_file.absolute()}")
    
    print("🦚 ONE JOB: Take request, hand to MCP, confirm delivery.")
    print("   NO EXTRAS. NO TECHNICAL BULLSHIT.")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n🛑 Stopped")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
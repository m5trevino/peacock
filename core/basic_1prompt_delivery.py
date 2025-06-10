#!/usr/bin/env python3
"""
basic_1prompt_delivery.py - Stripped Down Delivery Service
STAY IN YOUR LANE - Basic delivery only, no technical showboating
"""

import datetime
import webbrowser
from pathlib import Path

def generate_session_timestamp():
    """Generate military time session timestamp"""
    now = datetime.datetime.now()
    week = now.isocalendar()[1]
    day = now.day
    hour = now.hour
    minute = now.minute
    return f"{week}-{day:02d}-{hour:02d}{minute:02d}"

def generate_basic_delivery_interface():
    """Generate basic delivery interface - NO TECHNICAL DETAILS"""
    
    session_timestamp = generate_session_timestamp()
    
    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🦚 Peacock Delivery Service</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'SF Mono', monospace; background: #0d1117; color: #e6edf3; min-height: 100vh; }}
        
        .header {{ background: #161b22; border-bottom: 1px solid #30363d; padding: 20px; text-align: center; }}
        .logo {{ font-size: 24px; font-weight: bold; color: #ff6b35; margin-bottom: 8px; }}
        .tagline {{ color: #8b949e; font-size: 14px; }}
        .session {{ background: rgba(0, 255, 136, 0.1); border: 1px solid #00ff88; border-radius: 6px; padding: 6px 12px; font-size: 12px; color: #00ff88; display: inline-block; margin-top: 12px; }}
        
        .main-container {{ max-width: 800px; margin: 0 auto; padding: 40px 20px; }}
        
        .delivery-section {{ background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 32px; margin-bottom: 32px; text-align: center; }}
        .delivery-title {{ color: #ff6b35; font-size: 20px; font-weight: 600; margin-bottom: 16px; }}
        .delivery-description {{ color: #8b949e; font-size: 16px; line-height: 1.6; margin-bottom: 32px; }}
        
        .input-container {{ margin-bottom: 24px; }}
        .prompt-input {{ width: 100%; padding: 16px 20px; background: #0d1117; border: 2px solid #30363d; border-radius: 8px; color: #e6edf3; font-size: 16px; font-family: inherit; min-height: 120px; resize: vertical; }}
        .prompt-input:focus {{ outline: none; border-color: #ff6b35; }}
        .prompt-input::placeholder {{ color: #6e7681; }}
        
        .delivery-btn {{ background: linear-gradient(45deg, #ff6b35, #ff8c5a); border: none; color: white; padding: 16px 32px; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: all 0.2s; }}
        .delivery-btn:hover {{ transform: translateY(-2px); box-shadow: 0 6px 20px rgba(255, 107, 53, 0.3); }}
        .delivery-btn:disabled {{ background: #30363d; color: #8b949e; cursor: not-allowed; transform: none; }}
        
        .status-section {{ background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 24px; display: none; }}
        .status-section.show {{ display: block; }}
        .status-title {{ color: #238636; font-size: 18px; font-weight: 600; margin-bottom: 16px; text-align: center; }}
        .status-message {{ color: #8b949e; text-align: center; margin-bottom: 20px; }}
        
        .delivery-complete {{ background: rgba(35, 134, 54, 0.1); border: 1px solid #238636; border-radius: 8px; padding: 20px; text-align: center; }}
        .complete-icon {{ font-size: 48px; margin-bottom: 12px; }}
        .complete-text {{ color: #238636; font-weight: 600; font-size: 18px; }}
        
        .footer {{ text-align: center; padding: 40px 20px; color: #6e7681; font-size: 14px; }}
        
        @keyframes pulse {{
            0% {{ opacity: 1; }}
            50% {{ opacity: 0.5; }}
            100% {{ opacity: 1; }}
        }}
        
        .processing {{ animation: pulse 2s infinite; }}
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">🦚 Peacock Delivery Service</div>
        <div class="tagline">Simple. Fast. Reliable.</div>
        <div class="session">Session: {session_timestamp}</div>
    </div>

    <div class="main-container">
        <div class="delivery-section">
            <div class="delivery-title">📦 What would you like built?</div>
            <div class="delivery-description">
                Describe your project idea and we'll handle the rest. 
                Our team will design, build, and deliver your complete application.
            </div>
            
            <div class="input-container">
                <textarea 
                    class="prompt-input" 
                    id="projectInput" 
                    placeholder="Example: Build a snake game with HTML, CSS, and JavaScript..."
                ></textarea>
            </div>
            
            <button class="delivery-btn" id="deliveryBtn" onclick="startDelivery()">
                🚀 Start Delivery
            </button>
        </div>

        <div class="status-section" id="statusSection">
            <div class="status-title">📋 Delivery Status</div>
            <div class="status-message" id="statusMessage">Preparing your order...</div>
            
            <div class="delivery-complete" id="deliveryComplete" style="display: none;">
                <div class="complete-icon">✅</div>
                <div class="complete-text">Delivery Complete!</div>
                <div style="margin-top: 12px; color: #8b949e;">Your project has been built and is ready for review.</div>
            </div>
        </div>
    </div>

    <div class="footer">
        🦚 Peacock Delivery Service - We bring blunt wraps, nothing more.
    </div>

    <script>
        const sessionTimestamp = '{session_timestamp}';
        
        async function startDelivery() {{
            const projectInput = document.getElementById('projectInput');
            const deliveryBtn = document.getElementById('deliveryBtn');
            const statusSection = document.getElementById('statusSection');
            const statusMessage = document.getElementById('statusMessage');
            const deliveryComplete = document.getElementById('deliveryComplete');
            
            const prompt = projectInput.value.trim();
            
            if (!prompt) {{
                alert('Please describe what you want built');
                return;
            }}

            // Disable input and show status
            projectInput.disabled = true;
            deliveryBtn.disabled = true;
            deliveryBtn.textContent = '📦 Processing...';
            deliveryBtn.classList.add('processing');
            statusSection.classList.add('show');
            
            try {{
                console.log('🚀 Starting delivery for:', prompt);
                statusMessage.textContent = 'Connecting to our development team...';
                
                // Call MCP server (the right hand who does the real work)
                const response = await fetch('http://127.0.0.1:8000/process', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{
                        command: 'peacock_full',
                        text: prompt,
                        session_timestamp: sessionTimestamp,
                        delivery_service: true
                    }})
                }});

                if (!response.ok) {{
                    throw new Error(`Delivery service unavailable: ${{response.status}}`);
                }}

                statusMessage.textContent = 'Your project is being built...';
                
                const result = await response.json();
                
                if (result.success) {{
                    statusMessage.textContent = 'Quality checking and packaging...';
                    
                    // Show completion
                    setTimeout(() => {{
                        statusMessage.style.display = 'none';
                        deliveryComplete.style.display = 'block';
                        
                        console.log('✅ Delivery completed successfully');
                        console.log('📊 Project details:', {{
                            stages: result.total_stages,
                            xedit_generated: result.xedit_generated,
                            session: result.session_timestamp
                        }});
                        
                    }}, 2000);
                    
                }} else {{
                    throw new Error(result.error || 'Delivery failed');
                }}
                
            }} catch (error) {{
                console.error('❌ Delivery error:', error);
                statusMessage.textContent = `Delivery failed: ${{error.message}}`;
                statusMessage.style.color = '#da3633';
            }} finally {{
                // Re-enable interface
                setTimeout(() => {{
                    projectInput.disabled = false;
                    deliveryBtn.disabled = false;
                    deliveryBtn.textContent = '🚀 Start Delivery';
                    deliveryBtn.classList.remove('processing');
                }}, 3000);
            }}
        }}

        // Enable Enter key to start delivery
        document.getElementById('projectInput').addEventListener('keypress', function(e) {{
            if (e.key === 'Enter' && e.ctrlKey) {{
                startDelivery();
            }}
        }});
        
        console.log('🦚 Peacock Delivery Service loaded');
        console.log('📦 Session:', sessionTimestamp);
        console.log('🎯 Role: Basic delivery only - stay in your lane');
    </script>
</body>
</html>'''
    
    return html_content

def main():
    """Main entry point - generate and open delivery interface"""
    
    print("🦚" + "="*50 + "🦚")
    print("    PEACOCK DELIVERY SERVICE")
    print("🦚" + "="*50 + "🦚")
    print()
    print("📦 Role: Basic delivery service ONLY")
    print("🎯 Mission: Take request, hand to MCP, confirm delivery")
    print("🚫 NOT doing: Technical details, architecture, implementation")
    print("✅ Staying in lane: Blunt wraps delivery")
    print()
    
    # Generate delivery interface
    html_output = generate_basic_delivery_interface()
    session_timestamp = generate_session_timestamp()
    
    # Save to html directory
    html_dir = Path("/home/flintx/peacock/html")
    html_dir.mkdir(exist_ok=True)
    output_path = html_dir / f"delivery-{session_timestamp}.html"
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_output)
    
    print(f"📁 Delivery interface: {output_path}")
    print(f"🌐 Opening in browser...")
    print()
    print("🦚 DELIVERY SERVICE READY!")
    print("="*60)
    
    # Open in browser
    webbrowser.open(f"file://{output_path.absolute()}")

if __name__ == "__main__":
    main()
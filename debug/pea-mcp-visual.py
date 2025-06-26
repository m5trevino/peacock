{
  `title`: `BUILD SCRIPT - BASH COMPLETE`,
  `folder`: `peacock-debug`,
  `content`: `#!/bin/bash
# 🔧 PEA-MCP BUILDER SCRIPT - PART 2
# Completes the visual version build

# Continue pea-mcp-visual.py from where we left off
cat << 'EOF' >> pea-mcp-visual.py
_used\", \"\")[-8:] if falcon_result.get(\"api_key_used\") else \"\")
            
            display_separator()
            
            # EAGLE Stage
            display_stage_start(\"EAGLE\", \"Code Implementation\")
            eagle_result = orchestrator.execute_eagle(falcon_result.get(\"response\", \"\"))
            display_stage_result(\"EAGLE\", eagle_result.get(\"success\", False),
                                eagle_result.get(\"char_count\", 0),
                                eagle_result.get(\"model\", \"\"),
                                eagle_result.get(\"api_key_used\", \"\")[-8:] if eagle_result.get(\"api_key_used\") else \"\")
            
            display_separator()
            
            # HAWK Stage
            display_stage_start(\"HAWK\", \"QA & Testing\")
            hawk_result = orchestrator.execute_hawk(user_input, eagle_result.get(\"response\", \"\"))
            display_stage_result(\"HAWK\", hawk_result.get(\"success\", False),
                                hawk_result.get(\"char_count\", 0),
                                hawk_result.get(\"model\", \"\"),
                                hawk_result.get(\"api_key_used\", \"\")[-8:] if hawk_result.get(\"api_key_used\") else \"\")
            
            display_separator()
            
            # Compile results
            stage_results = {
                \"spark\": spark_result,
                \"falcon\": falcon_result, 
                \"eagle\": eagle_result,
                \"hawk\": hawk_result
            }
            
            display_character_summary(stage_results)
            
            # Generate final response
            final_response = orchestrator.compile_final_response(stage_results)
            
            return {
                \"success\": True,
                \"pipeline_result\": {
                    \"success\": True,
                    \"session_timestamp\": SESSION_TIMESTAMP,
                    \"stage_results\": stage_results,
                    \"final_response\": final_response,
                    \"total_birds\": 4,
                    \"pipeline_type\": \"full_orchestration\",
                    \"api_calls_made\": sum(1 for result in stage_results.values() if result.get(\"success\"))
                },
                \"stage_results\": {name: {\"char_count\": result.get(\"char_count\", 0), 
                                       \"model\": result.get(\"model\", \"\"), 
                                       \"success\": result.get(\"success\", False)}
                                for name, result in stage_results.items()},
                \"message\": \"Peacock pipeline completed with real API calls\"
            }
            
        except Exception as e:
            logging.error(f\"Pipeline execution error: {e}\")
            return {
                \"success\": False,
                \"error\": str(e),
                \"message\": \"Pipeline execution failed\"
            }

def start_server():
    \"\"\"Start the HTTP server\"\"\"
    display_server_start()
    
    server = HTTPServer((HOST, PORT), PeacockHandler)
    
    def run_server():
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print(\"\
Shutting down server...\")
            server.shutdown()
    
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    
    return server

def main():
    \"\"\"Main server function\"\"\"
    global LOGGING_ENABLED
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Peacock MCP Server - VISUAL VERSION')
    parser.add_argument('--log', action='store_true', help='Enable logging')
    args = parser.parse_args()
    
    if args.log:
        LOGGING_ENABLED = True
    
    # Setup logging
    setup_logging()
    
    # Display initialization
    display_init()
    display_config()
    display_birds_loaded()
    display_commands()
    
    # Start server
    server = start_server()
    
    try:
        print(\"⚡ Press Ctrl+C to stop\")
        
        # Keep main thread alive
        while True:
            import time
            time.sleep(1)
            
    except KeyboardInterrupt:
        print(\"\
Shutting down Peacock MCP Server...\")
        server.shutdown()

if __name__ == \"__main__\":
    main()
EOF

echo \"✅ Created pea-mcp-visual.py\"

# Make both files executable
chmod +x pea-mcp-debug.py
chmod +x pea-mcp-visual.py

echo \"\"
echo \"🚀 BUILD COMPLETE!\"
echo \"\"
echo \"📁 Files created:\"
echo \"   pea-mcp-debug.py  - Clean debug output with detailed logging\"
echo \"   pea-mcp-visual.py - Cyberpunk styling with visual effects\"
echo \"\"
echo \"🔧 Usage:\"
echo \"   python3 pea-mcp-debug.py --log    # Debug mode with file logging\"
echo \"   python3 pea-mcp-visual.py --log   # Visual mode with file logging\"
echo \"\"
echo \"💡 The original pea-mcp.py remains unchanged\"
echo \"   Switch between versions as needed for debugging vs production\"
echo \"\"`
}

####START OF DOCUMENT####
# START ### BASIC MCP LISTENER WITH OLLAMA LLM INTEGRATION ###
import http.server
import socketserver
import json
import os
import urllib.request # Used for making HTTP requests to the local LLM server

# --- CONFIGURATION ---
HOST = "127.0.0.1"
PORT = 8000
PROCESS_PATH = "/process"

# --- LOCAL LLM CONFIGURATION (OLLAMA) ---
# Configure the URL for your local Ollama API server.
# Default Ollama API endpoint for generation is /api/generate
LOCAL_LLM_MODEL_NAME = "codegeex4:9b-all-q4_K_M" 

     # <-- Configured for Ollama generate endpoint

# Configure the specific model name you want to use from your Ollama list
LOCAL_LLM_MODEL_NAME = "codegeex4:9b-all-q4_K_M" # <-- Configured for your listed model

# --- LLM INTERACTION FUNCTIONS ---

def build_llm_prompt(command, text, language):
    """Builds the prompt for the LLM based on the command and context."""
    # Basic prompts - these can be significantly refined!
    # The format might need adjustment based on how your local model is fine-tuned
    # Using a simple instruction format for llama2-uncensored
    if command == "explain":
        return f"Explain the following {language} code:\n\n{language}\n{text}\n\nProvide a clear, concise explanation."
    elif command == "fix":
        # Ask for corrected code and a brief explanation
        return f"Review the following {language} code for issues (syntax, logic, formatting, style) and provide the corrected version. Also, include a brief explanation of the changes made. Format your response clearly, perhaps with the corrected code first, then the explanation.\n\n{language}\n{text}\n\nCorrected code:\n{language}\n[Insert corrected code here]\n\nExplanation:\n[Insert explanation here]"
    elif command == "rewrite":
         # Ask for rewritten code and a brief explanation
         return f"Rewrite the following {language} code to be more concise, efficient, or idiomatic. Also, include a brief explanation of the changes made. Format your response clearly, perhaps with the rewritten code first, then the explanation.\n\n{language}\n{text}\n\nRewritten code:\n{language}\n[Insert rewritten code here]\n\nExplanation:\n[Insert explanation here]"
    elif command == "alternatives":
        return f"Suggest alternative ways to write the following {language} code or achieve the same result:\n\n{language}\n{text}\n\nProvide a list of alternatives or different approaches."
    elif command == "question":
        # If no explicit question is sent by EIP, treat 'question' like 'explain' for now
        # A more advanced EIP/MCP would handle a user-provided question string
        return f"Analyze the following {language} code and provide insights or answer potential questions about it:\n\n{language}\n{text}\n\nAnalysis/Answer:"
    else:
        # Default or unknown command
        return f"Analyze the following {language} code:\n\n{language}\n{text}\n\nProvide a general analysis."

def call_llm(prompt):
    """Calls the local Ollama API server with the given prompt."""
    if not LOCAL_LLM_URL or "YOUR_LOCAL_LLM_PORT" in LOCAL_LLM_URL:
        # This check is less critical now that it's hardcoded for Ollama,
        # but good practice if config was external.
        pass # URL is set, proceed

    try:
        # --- CUSTOMIZED PAYLOAD FOR OLLAMA /api/generate ---
        llm_request_payload = {
            "model": LOCAL_LLM_MODEL_NAME,
            "prompt": prompt,
            "stream": False # We want the full response at once
            # Add other Ollama parameters if needed, e.g., "temperature": 0.7
        }
        # --- END CUSTOMIZATION ---

        json_data = json.dumps(llm_request_payload).encode('utf-8')

        req = urllib.request.Request(LOCAL_LLM_URL, data=json_data,
                                     headers={'Content-Type': 'application/json'},
                                     method='POST')

        print(f"MCP: Calling local LLM ({LOCAL_LLM_MODEL_NAME}) at {LOCAL_LLM_URL}...") # Log the call

        with urllib.request.urlopen(req) as response:
            llm_response_json_raw = response.read().decode('utf-8')
            llm_response_json = json.loads(llm_response_json_raw)

            # --- CUSTOMIZED EXTRACTION FOR OLLAMA /api/generate ---
            # The generated text is in the 'response' key
            llm_text_response = llm_response_json.get('response', '')
            # --- END CUSTOMIZATION ---

####1/4 MARKER####

            if not isinstance(llm_text_response, str):
                 # If extraction failed or returned non-string, log the full response
                 print(f"MCP WARNING: LLM response extraction might be incorrect. Full response: {llm_response_json_raw}")
                 llm_text_response = str(llm_response_json_raw) # Use raw string as fallback

            print("MCP: Received response from local LLM.") # Log successful response
            return {"success": True, "text": llm_text_response}

    except urllib.error.URLError as e:
        print(f"MCP ERROR: Could not connect to local Ollama hub at {LOCAL_LLM_URL}. Is the Ollama service running?")
        return {"error": f"Local Ollama connection failed. Is service running at {LOCAL_LLM_URL}? Error: {e}"}
    except json.JSONDecodeError:
         print(f"MCP ERROR: Failed to parse JSON response from local LLM: {llm_response_json_raw}")
         return {"error": f"Failed to parse JSON response from local LLM."}
    except Exception as e:
        print(f"MCP ERROR: An unexpected error occurred during local LLM call: {e}")
        return {"error": f"An unexpected error occurred during local LLM call: {e}"}

def process_llm_response(command, llm_raw_text, location_info):
    """
    Processes the raw text response from the LLM into a structured format (IRP function).
    This is a simple implementation; a real IRP would be more complex and robust.
    It assumes the LLM follows the prompt's requested format reasonably well.
    """
    internal_data = {}

    if command in ["explain", "question"]:
        # For explanation/question, just return the text
        internal_data["explanation_text"] = llm_raw_text
        # Also add a generic result_text key for fallback in EIP
        internal_data["result_text"] = llm_raw_text

    elif command in ["fix", "rewrite"]:
        # This is a simple IRP for fix/rewrite.
        # It tries to find code blocks and explanation text.
        # A robust IRP might use regex, AST parsing, or expect JSON from LLM.

        suggested_change = {
            "type": "replace", # Assume replacement for now
            "replacement_code": "Could not parse suggested code from LLM.",
            "explanation": "Could not parse explanation from LLM.",
            # Get original location info from the EIP request
            "start_line_1based": location_info.get('selected_region', {}).get('start', {}).get('line_1based', '??'),
            "end_line_1based": location_info.get('selected_region', {}).get('end', {}).get('line_1based', '??')
        }

        # Simple attempt to find code blocks and explanation
        # Look for the last code block as the potential replacement code
        code_blocks = []
        explanation_parts = []
        in_code_block = False
        current_code_block = []

        lines = llm_raw_text.splitlines()
        for line in lines:
            if line.strip().startswith(""):
                if in_code_block:
                    # End of a code block
                    code_blocks.append("\n".join(current_code_block))
                    current_code_block = []
                    in_code_block = False
                else:
                    # Start of a code block (ignore the language specifier like python)
                    in_code_block = True
            elif in_code_block:
                current_code_block.append(line)
            else:
                # Assume lines outside code blocks are explanation
                explanation_parts.append(line)

        if code_blocks:
            # Take the last code block as the replacement code
            suggested_change["replacement_code"] = code_blocks[-1].strip()

        # Join explanation parts, ignoring empty lines
        explanation = "\n".join(part for part in explanation_parts if part.strip())
        if explanation:
             suggested_change["explanation"] = explanation.strip()

####1/2 MARKER####
        else:
             # If no explanation found outside code blocks, maybe the LLM put it inside?
             # Or the prompt wasn't followed. Use a default.
             suggested_change["explanation"] = "See suggested code above."

        internal_data["suggested_change"] = suggested_change

    elif command == "alternatives":
        # Simple IRP for alternatives - split lines or look for list items
        # A better IRP would parse bullet points, numbered lists, etc.
        # For now, just return the raw text, EIP can display it.
        internal_data["result_text"] = llm_raw_text
        # Could try to parse into a list if the LLM formats it consistently
        # alternatives_list = [line.strip() for line in llm_raw_text.splitlines() if line.strip()]
        # internal_data["alternatives"] = alternatives_list


    else:
        # Default handling for unknown commands or commands not explicitly processed
        internal_data["result_text"] = llm_raw_text # Just return the raw LLM text

    # Add the raw LLM response for debugging/inspection if needed
    internal_data["_raw_llm_response"] = llm_raw_text

    return internal_data

# Custom handler to process incoming requests
class MCPRequestHandler(http.server.BaseHTTPRequestHandler):
    # Disable logging requests to console - keeps it cleaner unless we need it
    def log_request(self, code='-', size='-'):
        pass # Comment out or remove this line to re-enable request logging

    def do_POST(self):
        # Only handle POST requests on the specified path
        if self.path == PROCESS_PATH:
            content_length = int(self.headers['Content-Length']) # Get the size of the data
            post_data = self.rfile.read(content_length) # Read the raw data

            try:
                # Parse the JSON data received from the EIP (this is the AIP payload content)
                received_data = json.loads(post_data.decode('utf-8'))

                # Extract key info from the received data
                command = received_data.get('command', 'unknown')
                text_to_process = received_data.get('text', '')
                language = received_data.get('language', 'unknown')
                location_info = received_data.get('location', {}) # Get location info

                print("MCP: Received data from EIP:")
                print("---")
                print("Command: {}".format(command))
                print("Language: {}".format(language))
                print("File: {}".format(os.path.basename(location_info.get('filepath', 'N/A'))))
                # print("Selected Text (first 100 chars): {}...".format(text_to_process[:100])) # Optional: print snippet
                print("---")

                # --- NEW: Build prompt and call LLM ---
                llm_prompt = build_llm_prompt(command, text_to_process, language)
                llm_response = call_llm(llm_prompt) # This calls your local Ollama

                # --- NEW: Process LLM response (IRP) ---
                if llm_response.get("success"):
                    llm_raw_text = llm_response.get("text", "")
                    # Process the raw LLM text into structured internal data
                    internal_structured_data = process_llm_response(command, llm_raw_text, location_info)

                    # --- Send back the structured response ---
                    self.send_response(200) # HTTP 200 OK
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()

                    response_payload = {
                        "status": "success",
                        "command": command, # Echo the command
                        "message": "LLM processed successfully.",
                        "internal_data": internal_structured_data, # <-- Send the structured data here
                        # Include location info from the original request if needed by EIP
                        "location": location_info

####3/4 MARKER####
                        # TODO: Add 'report_filepath' here if generating HTML reports later
                    }
                    self.wfile.write(json.dumps(response_payload).encode('utf-8'))

                else:
                    # Handle errors from the LLM call
                    error_message = llm_response.get("error", "Unknown LLM error.")
                    self.send_response(500) # Internal Server Error (or 503 Service Unavailable)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    error_payload = {
                        "status": "error",
                        "command": command, # Echo the command
                        "message": f"MCP: LLM processing failed: {error_message}",
                        "internal_data": {
                            "_llm_error": error_message
                        }
                    }
                    self.wfile.write(json.dumps(error_payload).encode('utf-8'))
                    print(f"MCP ERROR: LLM processing failed: {error_message}")


            except json.JSONDecodeError as e:
                # Handle invalid JSON payload from EIP
                self.send_response(400) # Bad Request
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                error_payload = {
                    "status": "error",
                    "message": "MCP: Failed to parse JSON payload from EIP: {}".format(e),
                    "command": "json_error"
                }
                self.wfile.write(json.dumps(error_payload).encode('utf-8'))
                # Print error to MCP console
                print("MCP ERROR: Failed to parse JSON: {}".format(e)) # Use .format()

            except Exception as e:
                # Handle any other unexpected errors during processing
                self.send_response(500) # Internal Server Error
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                error_payload = {
                    "status": "error",
                    "message": "MCP: An unexpected error occurred while processing request: {}".format(e), # Use .format()
                    "command": "internal_error"
                }
                self.wfile.write(json.dumps(error_payload).encode('utf-8'))
                # Print error to MCP console
                print("MCP ERROR: Unexpected error during processing: {}".format(e)) # Use .format()

        else:
            # Handle requests to other paths (e.g., root) - return 404 Not Found
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'404 Not Found')

# Set up and start the server
# socketserver.TCPServer creates a socket that listens on the given address and port
# allow_reuse_address is True so we can restart it quickly
with socketserver.TCPServer((HOST, PORT), MCPRequestHandler, bind_and_activate=False) as httpd:
     # Optional: To avoid "Address already in use" errors if server isn't shut down cleanly
     httpd.allow_reuse_address = True
     httpd.server_bind()
     httpd.server_activate()

     # --- FIX: Changed f-string to .format() ---
     print("MCP: Starting server on {}:{}".format(HOST, PORT))
     print("MCP: Listening for requests on {}".format(PROCESS_PATH))
     print("MCP: Press Ctrl+C to stop.")
     # --- END FIX ---

     try:
         # Activate the server; this will keep running until interrupted (e.g. with Ctrl+C)
         httpd.serve_forever()
     except KeyboardInterrupt:
         print("\nMCP: Stopping server.")
         httpd.shutdown() # Cleanly shut down the server
         print("MCP: Server stopped.")
# FINISH ### BASIC MCP LISTENER ###

####END OF DOCUMENT####

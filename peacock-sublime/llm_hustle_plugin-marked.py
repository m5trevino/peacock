
    ####START OF DOCUMENT####                                                                                
    # START ### IMPORTS ###                                                                                  
    import sublime                                                                                           
    import sublime_plugin                                                                                    
    import json                                                                                              
    import urllib.request                                                                                    
    import os                                                                                                
    import webbrowser # For opening reports in browser                                                       
    # FINISH ### IMPORTS ###                                                                                 
                                                                                                             
    # START ### CONFIGURATION ###                                                                            
    # Define the address for our local MCP hub                                                               
    # This is the IP and port where your MCP service will listen.                                            
    # This will likely remain localhost (127.0.0.1) for a local setup.                                       
    MCP_HUB_URL = "http://127.0.0.1:8000/process"                                                            
    # FINISH ### CONFIGURATION ###                                                                           
                                                                                                             
    # START ### BASE EIP COMMAND CLASS (LlmHustleCommand) ###                                                
    class LlmHustleCommand(sublime_plugin.TextCommand):                                                      
                                                                                                             
        def get_selected_text(self):                                                                         
            """Gets the text from the primary selection."""                                                  
            selected_text = ""                                                                               
            # Only take the first non-empty selection for now                                                
            for region in self.view.sel():                                                                   
                if not region.empty():                                                                       
                    selected_text = self.view.substr(region)                                                 
                    break # Only process the first one                                                       
                                                                                                             
            if not selected_text:                                                                            
                sublime.status_message("Peacock EIP: No text selected.")                                     
                return None # Return None if no text is selected                                             
                                                                                                             
            return selected_text.strip() # Clean up whitespace                                               
                                                                                                             
        def get_file_language(self):                                                                         
            """Gets the detected language (syntax) of the current file."""                                   
            syntax_setting = self.view.settings().get('syntax')                                              
            if not syntax_setting:                                                                           
                return "unknown" # Default if syntax isn't set                                               
                                                                                                             
            # Syntax setting looks like 'Packages/Python/Python.sublime-syntax'                              
            # Extract the base language name (e.g., 'Python')                                                
            language_name = "unknown"                                                                        
            parts = syntax_setting.split('/')                                                                
            if len(parts) > 1:                                                                               
                # Get the last part (e.g., 'Python.sublime-syntax')                                          
                file_part = parts[-1]                                                                        
                # Split by '.' and take the first part (e.g., 'Python')                                      
                language_name = file_part.split('.')[0]                                                      
                                                                                                             
            # Return a lowercase version for consistency                                                     
            return language_name.lower()                                                                     
                                                                                                             
                                                                                                             
        def get_location_info(self):                                                                         
            """Gets file path and selected region details for the primary selection."""                      
            file_path = self.view.file_name() # Get the full file path                                       
            # Operation requires a saved file with a path                                                    
            if not file_path:                                                                                
                sublime.status_message("Peacock EIP: Operation requires a saved file.")                      
                return None # Indicate failure                                                               
                                                                                                             
            # Get the primary selection region (already handled in get_selected_text, but get region here)   
            primary_region = None                                                                            
            for region in self.view.sel():                                                                   
                if not region.empty():                                                                       
                    primary_region = region # Get the region object                                          
                    break                                                                                    
            if not primary_region:                                                                           
                # Should be caught by get_selected_text, but defensive check                                 
                sublime.status_message("Peacock EIP: No text selected for location info.")                   
                return None                                                                                  
                                                                                                             
            # Get line and column numbers for start and end of selection                                     
            # rowcol returns (row, col) which are 0-indexed                                                  
            start_row, start_col = self.view.rowcol(primary_region.begin())                                  
            end_row, end_col = self.view.rowcol(primary_region.end())                                        
                                                                                                             
            # Prepare location info including 1-based indexing for human readability/tools that expect it    
            location_info = {                                                                                
                "filepath": file_path,                                                                       
                "selected_region": {                                                                         
                    "start": {"row": start_row, "col": start_col, "line_1based": start_row + 1, "col_1based":
start_col + 1},                                                                                              
                    "end": {"row": end_row, "col": end_col, "line_1based": end_row + 1, "col_1based": end_col
+ 1} # Include end coordinates                                                                               
                }                                                                                            
                # TODO: Add info about the function/class surrounding the selection later (CRM advanced)     
            }                                                                                                
                                                                                                             
            # print("Peacock EIP: Captured location info: {}".format(location_info)) # Verbose logging       
            return location_info                                                                             
                                                                                                             
        def is_enabled(self):                                                                                
            """                                                                                              
            Determines if the command should be enabled (menu item active).                                  
            Enabled only if text is selected and the file is saved.                                          
            """                                                                                              
            # Check if there is a non-empty selection                                                        
            has_selection = any(not region.empty() for region in self.view.sel())                            
                                                                                                             
            # Check if the file has been saved (has a file path)                                             
            has_filepath = self.view.file_name() is not None                                                 
                                                                                                             
            # Command is enabled only if both conditions are true                                            
            return has_selection and has_filepath                                                            
                                                                                                             
                                                                                                             
    def send_to_mcp(self, text, command_type, language, location_info):                                      
        """                                                                                                  
        Packages intel and sends request to the MCP hub via HTTP POST.                                       
        """                                                                                                  
        # The is_enabled check should prevent this, but keep defensive check                                 
        if location_info is None or text is None:                                                            
            # Error handled in get_location_info and run                                                     
            return                                                                                           
                                                                                                             
        # Prep the package (data) as a dictionary - this is the AIP payload content!                         
        # The MCP will build the full AIP JSON payload around this content.                                  
        data_package_for_mcp = {                                                                             
            "text": text,                                                                                    
            "command": command_type,                                                                         
            "language": language,                                                                            
            "location": location_info                                                                        
        }                                                                                                    
        json_data = json.dumps(data_package_for_mcp).encode('utf-8')                                         
                                                                                                             
        # Prep the HTTP request                                                                              
        req = urllib.request.Request(MCP_HUB_URL, data=json_data,                                            
                                        headers={'Content-Type': 'application/json'},                        
                                        method='POST') # Specify POST explicitly                             
                                                                                                             
        # --- FIX: Changed f-strings to .format() for Python 3.3 compatibility ---                           
        sublime.status_message("Peacock EIP: Sending '{}' request for {}...".format(command_type,os.path.basename(location_info['filepath'])))                                                                
        print("Peacock EIP: Sending data for '{}' command...".format(command_type)) # Log what's being sent  
        # --- END FIX ---                                                                                    
                                                                                                             
        try:                                                                                                 
            # Send the request and get the response from the MCP                                             
            # MCP is expected to return JSON, containing status, command, and IRP's parsed internal data     
            with urllib.request.urlopen(req) as response:                                                    
                mcp_response_json = response.read().decode('utf-8')                                          
                mcp_response = json.loads(mcp_response_json)                                                 
                # --- FIX: Changed f-string to .format() ---                                                 
                # print("Peacock EIP: Received response from MCP:\n---\n{}\n---".format(mcp_response)) #     
Verbose logging                                                                                              
                # --- END FIX ---                                                                            
                sublime.status_message("Peacock EIP: MCP response received.")                                
                                                                                                             
                # Hand off the MCP's reliable JSON response to the handler                                   
                self.handle_mcp_response(mcp_response)                                                       
                                                                                                             
        except urllib.error.URLError as e:                                                                   
            # --- FIX: Changed f-strings to .format() ---                                                    
            print("Peacock EIP ERROR: Could not connect to MCP hub at {}. Is the MCP service running?".format(MCP_HUB_URL))                                                                               
            sublime.error_message("Peacock EIP Error: Connection failed. Is MCP service running at {}? Error:{}".format(MCP_HUB_URL, e))                                                                                  
            # --- END FIX ---                                                                                
        except Exception as e:                                                                               
            # --- FIX: Changed f-strings to .format() ---                                                    
            print("Peacock EIP ERROR: An unexpected error occurred during communication: {}".format(e))      
            sublime.error_message("Peacock EIP Error: An unexpected error occurred: {}".format(e))           
            # --- END FIX ---                                                                                
                                                                                                             
                                                                                                             
    def handle_mcp_response(self, response_data):                                                            
        """                                                                                                  
        Handles the reliable JSON data received from the MCP's IRP.                                          
        This is how Peacock shows the result to the user in the editor.                                      
        """                                                                                                  
        # --- FIX: Changed f-string to .format() ---                                                         
        print("Peacock EIP: Handling MCP response (Status: {})...".format(response_data.get('status')))      
        # --- END FIX ---                                                                                    
                                                                                                             
        # Check the status from the MCP's response                                                           
        if response_data.get("status") == "success":                                                         
            command = response_data.get("command", "unknown")                                                
            # Get the internal, reliable structured data from the MCP's IRP output                           
            internal_structured_data = response_data.get("internal_data", {}) # Default to empty dict if     
missing                                                                                                      
                                                                                                             
            # --- FIX: Changed f-string to .format() ---                                                     
            sublime.status_message("Peacock EIP: Command '{}' successful.".format(command))                  
            # --- END FIX ---                                                                                
                                                                                                             
            # --- Display Logic based on Command Type ---                                                    
            if command == "explain":                                                                         
                pass  # Expecting a structured explanation from IRP (e.g., functions list, or just text)     
                # Let's display this in a new tab or an output panel for clarity.                            
                # Output panel is good for explanations.ns.                                                  
    ####1/2 MARKER####                                                                                       
                    explanation_text = internal_structured_data.get('explanation_text', 'No explanation provided.')                                                                                                  
                    # Check if there's structured data like functions breakdown from IRP                     
                    if 'functions' in internal_structured_data:                                              
                        # Build a simple summary from structured data for the panel title/start              
                        # --- FIX: Changed f-strings to .format() ---                                        
                        summary_lines = ["Explanation for{}:".format(os.path.basename(response_data.get('location', {}).get('filepath', 'selection')))]               
                        for func in internal_structured_data['functions']:                                   
                            summary_lines.append("---")                                                      
                            summary_lines.append("Name: {}".format(func.get('name', 'N/A')))                 
                            summary_lines.append("Description: {}".format(func.get('description', 'N/A')))   
                            calls = func.get('calls', [])                                                    
                            summary_lines.append("Calls: {}".format(', '.join(calls) if calls else 'None'))  
                            # Note: Line/Col info is in internal_structured_data but not shown here, could   
add later                                                                                                    
                        # --- END FIX ---                                                                    
                        explanation_text = "\n".join(summary_lines)                                          
                    elif 'result_text' in internal_structured_data: # Fallback to raw text if IRP just gave  
text                                                                                                         
                        explanation_text = internal_structured_data['result_text']                           
                    else:                                                                                    
                        explanation_text = "No explanation data in response."                                
                                                                                                             
                                                                                                             
                    panel.set_read_only(False)                                                               
                    panel_edit_token = panel.begin_edit()                                                    
                    panel.erase(panel_edit_token, panel.size()) # Clear panel content                        
                    panel.insert(panel_edit_token, explanation_text) # Insert new content                    
                    panel.end_edit(panel_edit_token)                                                         
                    panel.set_read_only(True)                                                                
                                                                                                             
                                                                                                             
                elif command == "fix" or command == "rewrite":                                               
                    # Expecting suggested code changes from IRP                                              
                    suggested_change = internal_structured_data.get("suggested_change")                      
                    if suggested_change and suggested_change.get("type") == "replace":                       
                        replacement_code = suggested_change.get("replacement_code", "ERROR: No code provided")                                                                                                   
                    panel = self.view.window().create_output_panel("peacock_explain")                        
                    self.view.window().run_command("show_panel", {"panel": "output.peacock_explain"}         
start_line_1based = suggested_change.get("start_line_1based", "??")                                          
                        end_line_1based = suggested_change.get("end_line_1based", "??")                      
                        filepath = response_data.get('location', {}).get('filepath', 'selected text') # Get  
filepath from response location                                                                              
                        explanation = suggested_change.get("explanation", "No explanation provided.")        
                                                                                                             
                        # Display patch suggestion in an output panel                                        
                        panel = self.view.window().create_output_panel("peacock_patch")                      
                        self.view.window().run_command("show_panel", {"panel": "output.peacock_patch"})      
                        panel.set_read_only(False)                                                           
                        panel_edit_token = panel.begin_edit()                                                
                        panel.erase(panel_edit_token, panel.size()) # Clear panel content                    
                        # --- FIX: Changed f-string to .format() for Python 3.3 compatibility and escaped \n as \\n ---                                                                                                   
                        panel.insert(panel_edit_token, "Suggested change for {} lines{}-{}:\\n\\nExplanation: {}\\n---\\nReplace with:\\n---\\n{}".format(os.path.basename(filepath),             
start_line_1based, end_line_1based, explanation, replacement_code))                                          
                        # --- END FIX ---                                                                    
                        panel.end_edit(panel_edit_token)                                                     
                        # TODO: Add button or command to apply the patch easily (CRM advanced)!              
                        panel.set_read_only(True)                                                            
                                                                                                             
                    else:                                                                                    
                        # --- FIX: Changed f-string to .format() and escaped \n as \\n ---                   
                        sublime.message_dialog("Peacock EIP: Command '{}' successful, but no valid change suggestion received from MCP. Raw data:\\n{}".format(command, json.dumps(internal_structured_data,           
indent=2)))                                                                                                  
                        # --- END FIX ---                                                                    
                                                                                                             
                elif command == "alternatives":                                                              
                    # Expecting a list of alternatives from IRP                                              
                    alternatives_list = internal_structured_data.get('alternatives', [])                     
                    if alternatives_list:                                                                    
                        output_text = "Alternatives:\\n---\\n" + "\\n---\\n".join(alternatives_list) # FIX:  
escaped \n as \\n                                                                                            
                    else:                                                                                    
                        output_text = internal_structured_data.get('result_text', 'No alternatives provided.') # Fallback to raw text                                                                           
                        if not output_text or output_text == 'No alternatives provided.':                    
                            output_text = "No alternatives data in response."                                
                                                                                                             
                                                                                                             
                    panel = self.view.window().create_output_panel("peacock_alternatives")                   
                    self.view.window().run_command("show_panel", {"panel": "output.peacock_alternatives"})   
                    panel.set_read_only(False)                                                               
                    panel_edit_token = panel.begin_edit()                                                    
                    panel.erase(panel_edit_token, panel.size()) # Clear panel content                        
                    panel.insert(panel_edit_token, output_text)                                              
                    panel.end_edit(panel_edit_token)                                                         
                    panel.set_read_only(True)                                                                
                                                                                                             
                elif command == "question":                                                                  
                    # Expecting an answer to a question from IRP                                             
                    answer_text = internal_structured_data.get('answer_text', 'No answer provided.')         
                    if not answer_text or answer_text == 'No answer provided.':                              
                        answer_text = internal_structured_data.get('result_text', 'No answer data in response.') # Fallback                                                                                       
                                                                                                             
                                                                                                             
                                                                                                             
    ####3/4 MARKER####                                                                                       
                    panel = self.view.window().create_output_panel("peacock_question")                       
                    self.view.window().run_command("show_panel", {"panel": "output.peacock_question"})       
                    panel.set_read_only(False)                                                               
                    panel_edit_token = panel.begin_edit()                                                    
                    panel.erase(panel_edit_token, panel.size()) # Clear panel content                        
                    # --- FIX: Changed f-string to .format() and escaped \n as \\n ---                       
                    panel.insert(panel_edit_token, "Answer about selected text:\\n---\\n{}\\n---".format(answer_text))                                                                 
                    # --- END FIX ---                                                                        
                    panel.end_edit(panel_edit_token)                                                         
                    panel.set_read_only(True)                                                                
                                                                                                             
                # Handling for opening HTML reports generated by MCP (e.g. for 'document' command if added   
later)                                                                                                       
                # The MCP response for a command that generates HTML would include 'report_filepath'         
                report_filepath = response_data.get("report_filepath")                                       
                if report_filepath:                                                                          
                    # Open the saved HTML report in a browser (common Sublime pattern)                       
                    # --- FIX: Changed f-string to .format() ---                                             
                    sublime.status_message("Peacock EIP: Opening report: {}".format(report_filepath))        
                    # --- END FIX ---                                                                        
                    try:                                                                                     
                        # Use file:// protocol for local files - ensure path is absolute and correctly       
formatted for OS                                                                                             
                        abs_report_filepath = os.path.abspath(report_filepath)                               
                        # --- FIX: Changed f-string to .format() ---                                         
                        webbrowser.open('file://{}'.format(abs_report_filepath))                             
                        # --- END FIX ---                                                                    
                    except Exception as e:                                                                   
                        # --- FIX: Changed f-string to .format() ---                                         
                        sublime.error_message("Peacock EIP Error: Could not open report file {}. Error:{}".format(report_filepath, e))                                                                              
                        # --- END FIX ---                                                                    
                                                                                                             
                                                                                                             
            elif response_data.get("status") == "error":                                                     
                error_message = response_data.get("message", "Unknown error from MCP.")                      
                # --- FIX: Changed f-strings to .format() ---                                                
                print("Peacock EIP ERROR: MCP reported an error: {}".format(error_message))                  
                sublime.error_message("Peacock EIP Error: {}".format(error_message))                         
                # --- END FIX ---                                                                            
            else:                                                                                            
                # Handle unexpected response structure from MCP                                              
                # --- FIX: Changed f-strings to .format() ---                                                
                print("Peacock EIP ERROR: Unexpected response format from MCP: {}".format(response_data))    
                # --- END FIX ---                                                                            
                sublime.error_message("Peacock EIP Error: Unexpected response from MCP. Check console for details.")                                                                                                   
                                                                                                             
                                                                                                             
        def run(self, edit):                                                                                 
            """                                                                                              
            The main entry point for Sublime commands. Captures intel and sends to MCP.                      
            """                                                                                              
            # 1. Capture Intel: Text, Command (implicit in class), Language, LOCATION                        
            text_to_process = self.get_selected_text()                                                       
            # Get command name automatically from class name (LlmHustleExplainCommand -> explain)            
            command_type = self.__class__.__name__.replace("LlmHustle", "").replace("Command", "").lower()   
            file_language = self.get_file_language()                                                         
            location_info = self.get_location_info() # Capture location info!                                
                                                                                                             
            # Basic validation - need selected text and a saved file with a path                             
            if text_to_process is None: # get_selected_text returns None if no text                          
                # sublime.status_message message already handled in get_selected_text                        
                return                                                                                       
            if location_info is None: # get_location_info returns None if no path                            
                # sublime.status_message message already handled in get_location_info                        
                return                                                                                       
                                                                                                             
            # 2. Send package to MCP (includes location_info)                                                
            self.send_to_mcp(text_to_process, command_type, file_language, location_info)                    
                                                                                                             
    # FINISH ### BASE EIP COMMAND CLASS (LlmHustleCommand) ###                                               
    # START ### SPECIFIC EIP COMMAND CLASSES ###                                                             
    # These now just inherit and the main run method handles the workflow.                                   
    # Add pass statement to each to make it valid Python.                                                    
    class LlmHustleExplainCommand(LlmHustleCommand): pass                                                    
    class LlmHustleFixCommand(LlmHustleFixCommand): pass                                                     
    class LlmHustleRewriteCommand(LlmHustleRewriteCommand): pass                                             
    class LlmHustleAlternativesCommand(LlmHustleAlternativesCommand): pass                                   
    class LlmHustleQuestionCommand(LlmHustleQuestionCommand): pass                                           
    # FINISH ### SPECIFIC EIP COMMAND CLASSES ###                                                            
                                                                                                             
    # START ### EIP MENU CONFIGURATION (Conceptual) ###                                                      
    # The actual menu definition goes into Context.sublime-menu                                              
    # Commands defined here implicitly by class names:                                                       
    # llm_hustle_explain                                                                                     
    # llm_hustle_fix                                                                                         
    # llm_hustle_rewrite                                                                                     
    # llm_hustle_alternatives                                                                                
    # llm_hustle_question                                                                                    
    # FINISH ### EIP MENU CONFIGURATION (Conceptual) ###                                                     
                                                                                                             
    ####END OF DOCUMENT#### # print("Peacock EIP: Captured location info: {}".format(location_info)) #       
Verbose logging                                                                                              
        return location_info                                                                                 
                                                                                                             
                                                                                                             
    def send_to_mcp(self, text, command_type, language, location_info):                                      
        """                                                                                                  
        Packages intel and sends request to the MCP hub via HTTP POST.                                       
        """                                                                                                  
        if location_info is None:                                                                            
            # Error handled in get_location_info and run                                                     
            return                                                                                           
                                                                                                             
        # Prep the package (data) as a dictionary - this is the AIP payload content!                         
        # The MCP will build the full AIP JSON payload around this content.                                  
        data_package_for_mcp = {                                                                             
            "text": text,                                                                                    
            "command": command_type,                                                                         
            "language": language,                                                                            
            "location": location_info                                                                        
        }                                                                                                    
        json_data = json.dumps(data_package_for_mcp).encode('utf-8')                                         
                                                                                                             
        # Prep the HTTP request                                                                              
        req = urllib.request.Request(MCP_HUB_URL, data=json_data,                                            
                                        headers={'Content-Type': 'application/json'},                        
                                        method='POST') # Specify POST explicitly                             
                                                                                                             
        # --- FIX: Changed f-strings to .format() for Python 3.3 compatibility ---                           
        sublime.status_message("Peacock EIP: Sending '{}' request for {}...".format(command_type,            
os.path.basename(location_info['filepath'])))                                                                
        print("Peacock EIP: Sending data for '{}' command...".format(command_type)) # Log what's being sent  
        # --- END FIX ---                                                                                    
                                                                                                             
        try:                                                                                                 
            # Send the request and get the response from the MCP                                             
            # MCP is expected to return JSON, containing status, command, and IRP's parsed internal data     
            with urllib.request.urlopen(req) as response:                                                    
                mcp_response_json = response.read().decode('utf-8')                                          
                mcp_response = json.loads(mcp_response_json)                                                 
                # --- FIX: Changed f-string to .format() ---                                                 
                # print("Peacock EIP: Received response from MCP:\n---\n{}\n---".format(mcp_response)) #     
Verbose logging                                                                                              
                # --- END FIX ---                                                                            
                sublime.status_message("Peacock EIP: MCP response received.")                                
                                                                                                             
                # Hand off the MCP's reliable JSON response to the handler                                   
                self.handle_mcp_response(mcp_response)                                                       
                                                                                                             
        except urllib.error.URLError as e:                                                                   
            # --- FIX: Changed f-strings to .format() ---                                                    
            print("Peacock EIP ERROR: Could not connect to MCP hub at {}. Is the MCP service running?".format(MCP_HUB_URL))                                                                               
            sublime.error_message("Peacock EIP Error: Connection failed. Is MCP service running at {}? Error{}".format(MCP_HUB_URL, e))                                                                                  
            # --- END FIX ---                                                                                
        except Exception as e:                                                                               
            # --- FIX: Changed f-strings to .format() ---                                                    
            print("Peacock EIP ERROR: An unexpected error occurred during communication: {}".format(e))      
            sublime.error_message("Peacock EIP Error: An unexpected error occurred: {}".format(e))           
            # --- END FIX ---                                                                                
                                                                                                             
                                                                                                             
    def handle_mcp_response(self, response_data):                                                            
        """                                                                                                  
        Handles the reliable JSON data received from the MCP's IRP.                                          
        This is how Peacock shows the result to the user in the editor.                                      
        """                                                                                                  
        # --- FIX: Changed f-string to .format() ---                                                         
        print("Peacock EIP: Handling MCP response (Status: {})...".format(response_data.get('status')))      
        # --- END FIX ---                                                                                    
                                                                                                             
        # Check the status from the MCP's response                                                           
        if response_data.get("status") == "success":                                                         
            command = response_data.get("command", "unknown")                                                
            # Get the internal, reliable structured data from the MCP's IRP output                           
            internal_structured_data = response_data.get("internal_data", {}) # Default to empty dict if     
missing                                                                                                      
                                                                                                             
            # --- FIX: Changed f-string to .format() ---                                                     
            sublime.status_message("Peacock EIP: Command '{}' successful.".format(command))                  
            # --- END FIX ---                                                                                
                                                                                                             
            # --- Display Logic based on Command Type ---                                                    
            if command == "explain":                                                                         
                # Expecting a structured explanation from IRP (e.g., functions list, or just text)           
                # Let's display this in a new tab or an output panel for clarity.                            
                # Output panel is good for explanations.                                                     
                panel = self.view.window().create_output_panel("peacock_explain")                            
                self.view.window().run_command("show_panel", {"panel": "output.peacock_explain"})            
                                                                                                             
                explanation_text = internal_structured_data.get('explanation_text', 'No explanation provided.')                                                                                                  
                # Check if there's structured data like functions breakdown from IRP                         
                if 'functions' in internal_structured_data:                                                  
                    # Build a simple summary from structured data for the panel title/start                  
                    # --- FIX: Changed f-strings to .format() ---                                            
                    summary_lines = ["Explanation for {}:".format(os.path.basename(response_data.get('location', {}).get('filepath', 'selection')))]               
                    for func in internal_structured_data['functions']:                                       
                        summary_lines.append("---")                                                          
                        summary_lines.append("Name: {}".format(func.get('name', 'N/A')))                     
                        summary_lines.append("Description: {}".format(func.get('description', 'N/A')))       
                        calls = func.get('calls', [])                                                        
                        summary_lines.append("Calls: {}".format(', '.join(calls) if calls else 'None'))      
                        # Note: Line/Col info is in internal_structured_data but not shown here, could add   
later                                                                                                        
                    # --- END FIX ---                                                                        
                    explanation_text = "\n".join(summary_lines)                                              
                elif 'result_text' in internal_structured_data: # Fallback to raw text if IRP just gave text 
                    explanation_text = internal_structured_data['result_text']                               
                else:                                                                                        
                    explanation_text = "No explanation data in response."                                    
                                                                                                             
                                                                                                             
                panel.set_read_only(False)                                                                   
                panel_edit_token = panel.begin_edit()                                                        
                panel.erase(panel_edit_token, panel.size()) # Clear panel content                            
                panel.insert(panel_edit_token, explanation_text) # Insert new content                        
                panel.end_edit(panel_edit_token)                                                             
                panel.set_read_only(True)                                                                    
>>>>>>> REPLACE 


			elif command == "fix" or command == "rewrite":                                               
                    # Expecting suggested code changes from IRP                                              
                    suggested_change = internal_structured_data.get("suggested_change")                      
                    if suggested_change and suggested_change.get("type") == "replace":                       
                        replacement_code = suggested_change.get("replacement_code", "ERROR: No code provided")                                                                                                   
                    panel = self.view.window().create_output_panel("peacock_explain")                        
                    self.view.window().run_command("show_panel", {"panel": "output.peacock_explain"}         
start_line_1based = suggested_change.get("start_line_1based", "??")                                          
                        end_line_1based = suggested_change.get("end_line_1based", "??")                      
                        filepath = response_data.get('location', {}).get('filepath', 'selected text') # Get  
filepath from response location                                                                              
                        explanation = suggested_change.get("explanation", "No explanation provided.")        
                                                                                                             
                        # Display patch suggestion in an output panel                                        
                        panel = self.view.window().create_output_panel("peacock_patch")                      
                        self.view.window().run_command("show_panel", {"panel": "output.peacock_patch"})      
                        panel.set_read_only(False)                                                           
                        panel_edit_token = panel.begin_edit()                                                
                        panel.erase(panel_edit_token, panel.size()) # Clear panel content                    
                        # --- FIX: Changed f-string to .format() for Python 3.3 compatibility and escaped \n 
as \\n ---                                                                                                   
                        panel.insert(panel_edit_token, "Suggested change for {} lines {}-{}:\\n\\nExplanation: {}\\n---\\nReplace with:\\n---\\n{}".format(os.path.basename(filepath),             
start_line_1based, end_line_1based, explanation, replacement_code))                                          
                        # --- END FIX ---                                                                    
                        panel.end_edit(panel_edit_token)                                                     
                        # TODO: Add button or command to apply the patch easily (CRM advanced)!              
                        panel.set_read_only(True)                                                            
                                                                                                             
                    else:                                                                                    
                        # --- FIX: Changed f-string to .format() and escaped \n as \\n ---                   
                        sublime.message_dialog("Peacock EIP: Command '{}' successful, but no valid change suggestion received from MCP. Raw data:\\n{}".format(command, json.dumps(internal_structured_data,           
indent=2)))                                                                                                  
                        # --- END FIX ---                                                                    
                                                                                                             
                elif command == "alternatives":                                                              
                    # Expecting a list of alternatives from IRP                                              
                    alternatives_list = internal_structured_data.get('alternatives', [])                     
                    if alternatives_list:                                                                    
                        output_text = "Alternatives:\\n---\\n" + "\\n---\\n".join(alternatives_list) # FIX:  
escaped \n as \\n                                                                                            
                    else:                                                                                    
                        output_text = internal_structured_data.get('result_text', 'No alternatives provided.') # Fallback to raw text                                                                           
                        if not output_text or output_text == 'No alternatives provided.':                    
                            output_text = "No alternatives data in response."                                
                                                                                                             
                                                                                                             
                    panel = self.view.window().create_output_panel("peacock_alternatives")                   
                    self.view.window().run_command("show_panel", {"panel": "output.peacock_alternatives"})   
                    panel.set_read_only(False)                                                               
                    panel_edit_token = panel.begin_edit()                                                    
                    panel.erase(panel_edit_token, panel.size()) # Clear panel content                        
                    panel.insert(panel_edit_token, output_text)                                              
                    panel.end_edit(panel_edit_token)                                                         
                    panel.set_read_only(True)                                                                
                                                                                                             
                elif command == "question":                                                                  
                    # Expecting an answer to a question from IRP                                             
                    answer_text = internal_structured_data.get('answer_text', 'No answer provided.')         
                    if not answer_text or answer_text == 'No answer provided.':                              
                        answer_text = internal_structured_data.get('result_text', 'No answer data in response.') # Fallback                                                                                       
                                                                                                             
                                                                                                             
                                                                                                             
    ####3/4 MARKER####                                                                                       
                    panel = self.view.window().create_output_panel("peacock_question")                       
                    self.view.window().run_command("show_panel", {"panel": "output.peacock_question"})       
                    panel.set_read_only(False)                                                               
                    panel_edit_token = panel.begin_edit()                                                    
                    panel.erase(panel_edit_token, panel.size()) # Clear panel content                        
                    # --- FIX: Changed f-string to .format() and escaped \n as \\n ---                       
                    panel.insert(panel_edit_token, "Answer about selected text:\\n---\\n{}\\n---".format(answer_text))                                                                 
                    # --- END FIX ---                                                                        
                    panel.end_edit(panel_edit_token)                                                         
                    panel.set_read_only(True)                                                                
                                                                                                             
                # Handling for opening HTML reports generated by MCP (e.g. for 'document' command if added   
later)                                                                                                       
                # The MCP response for a command that generates HTML would include 'report_filepath'         
                report_filepath = response_data.get("report_filepath")                                       
                if report_filepath:                                                                          
                    # Open the saved HTML report in a browser (common Sublime pattern)                       
                    # --- FIX: Changed f-string to .format() ---                                             
                    sublime.status_message("Peacock EIP: Opening report: {}".format(report_filepath))        
                    # --- END FIX ---                                                                        
                    try:                                                                                     
                        # Use file:// protocol for local files - ensure path is absolute and correctly       
formatted for OS                                                                                             
                        abs_report_filepath = os.path.abspath(report_filepath)                               
                        # --- FIX: Changed f-string to .format() ---                                         
                        webbrowser.open('file://{}'.format(abs_report_filepath))                             
                        # --- END FIX ---                                                                    
                    except Exception as e:                                                                   
                        # --- FIX: Changed f-string to .format() ---                                         
                        sublime.error_message("Peacock EIP Error: Could not open report file {}. Error: {}".format(report_filepath, e))                                                                              
                        # --- END FIX ---                                                                    
                                                                                                             
                                                                                                             
            elif response_data.get("status") == "error":                                                     
                error_message = response_data.get("message", "Unknown error from MCP.")                      
                # --- FIX: Changed f-strings to .format() ---                                                
                print("Peacock EIP ERROR: MCP reported an error: {}".format(error_message))                  
                sublime.error_message("Peacock EIP Error: {}".format(error_message))                         
                # --- END FIX ---                                                                            
            else:                                                                                            
                # Handle unexpected response structure from MCP                                              
                # --- FIX: Changed f-strings to .format() ---                                                
                print("Peacock EIP ERROR: Unexpected response format from MCP: {}".format(response_data))    
                # --- END FIX ---                                                                            
                sublime.error_message("Peacock EIP Error: Unexpected response from MCP. Check console for details.")                                                                                                   
                                                                                                             
                                                                                                             
        def run(self, edit):                                                                                 
            """                                                                                              
            The main entry point for Sublime commands. Captures intel and sends to MCP.                      
            """                                                                                              
            # 1. Capture Intel: Text, Command (implicit in class), Language, LOCATION                        
            text_to_process = self.get_selected_text()                                                       
            # Get command name automatically from class name (LlmHustleExplainCommand -> explain)            
            command_type = self.__class__.__name__.replace("LlmHustle", "").replace("Command", "").lower()   
            file_language = self.get_file_language()                                                         
            location_info = self.get_location_info() # Capture location info!                                
                                                                                                             
            # Basic validation - need selected text and a saved file with a path                             
            if text_to_process is None: # get_selected_text returns None if no text                          
                # sublime.status_message message already handled in get_selected_text                        
                return                                                                                       
            if location_info is None: # get_location_info returns None if no path                            
                # sublime.status_message message already handled in get_location_info                        
                return                                                                                       
                                                                                                             
            # 2. Send package to MCP (includes location_info)                                                
            self.send_to_mcp(text_to_process, command_type, file_language, location_info)                    
                                                                                                             
    # FINISH ### BASE EIP COMMAND CLASS (LlmHustleCommand) ###                                               
    # START ### SPECIFIC EIP COMMAND CLASSES ###                                                             
    # These now just inherit and the main run method handles the workflow.                                   
    # Add pass statement to each to make it valid Python.                                                    
    class LlmHustleExplainCommand(LlmHustleCommand): pass                                                    
    class LlmHustleFixCommand(LlmHustleFixCommand): pass                                                     
    class LlmHustleRewriteCommand(LlmHustleRewriteCommand): pass                                             
    class LlmHustleAlternativesCommand(LlmHustleAlternativesCommand): pass                                   
    class LlmHustleQuestionCommand(LlmHustleQuestionCommand): pass                                           
    # FINISH ### SPECIFIC EIP COMMAND CLASSES ###                                                            
                                                                                                             
    # START ### EIP MENU CONFIGURATION (Conceptual) ###                                                      
    # The actual menu definition goes into Context.sublime-menu                                              
    # Commands defined here implicitly by class names:                                                       
    # llm_hustle_explain                                                                                     
    # llm_hustle_fix                                                                                         
    # llm_hustle_rewrite                                                                                     
    # llm_hustle_alternatives                                                                                
    # llm_hustle_question                                                                                    
    # FINISH ### EIP MENU CONFIGURATION (Conceptual) ###                                                     
                                                                                                             
    ####END OF DOCUMENT#### # print("Peacock EIP: Captured location info: {}".format(location_info)) #       
Verbose logging                                                                                              
        return location_info                                                                                 
                                                                                                             
                                                                                                             
    def send_to_mcp(self, text, command_type, language, location_info):                                      
        """                                                                                                  
        Packages intel and sends request to the MCP hub via HTTP POST.                                       
        """                                                                                                  
        if location_info is None:                                                                            
            # Error handled in get_location_info and run                                                     
            return                                                                                           
                                                                                                             
        # Prep the package (data) as a dictionary - this is the AIP payload content!                         
        # The MCP will build the full AIP JSON payload around this content.                                  
        data_package_for_mcp = {                                                                             
            "text": text,                                                                                    
            "command": command_type,                                                                         
            "language": language,                                                                            
            "location": location_info                                                                        
        }                                                                                                    
        json_data = json.dumps(data_package_for_mcp).encode('utf-8')                                         
                                                                                                             
        # Prep the HTTP request                                                                              
        req = urllib.request.Request(MCP_HUB_URL, data=json_data,                                            
                                        headers={'Content-Type': 'application/json'},                        
                                        method='POST') # Specify POST explicitly                             
                                                                                                             
        # --- FIX: Changed f-strings to .format() for Python 3.3 compatibility ---                           
        sublime.status_message("Peacock EIP: Sending '{}' request for {}...".format(command_type,            
os.path.basename(location_info['filepath'])))                                                                
        print("Peacock EIP: Sending data for '{}' command...".format(command_type)) # Log what's being sent  
        # --- END FIX ---                                                                                    
                                                                                                             
        try:                                                                                                 
            # Send the request and get the response from the MCP                                             
            # MCP is expected to return JSON, containing status, command, and IRP's parsed internal data     
            with urllib.request.urlopen(req) as response:                                                    
                mcp_response_json = response.read().decode('utf-8')                                          
                mcp_response = json.loads(mcp_response_json)                                                 
                # --- FIX: Changed f-string to .format() ---                                                 
                # print("Peacock EIP: Received response from MCP:\n---\n{}\n---".format(mcp_response)) #     
Verbose logging                                                                                              
                # --- END FIX ---                                                                            
                sublime.status_message("Peacock EIP: MCP response received.")                                
                                                                                                             
                # Hand off the MCP's reliable JSON response to the handler                                   
                self.handle_mcp_response(mcp_response)                                                       
                                                                                                             
        except urllib.error.URLError as e:                                                                   
            # --- FIX: Changed f-strings to .format() ---                                                    
            print("Peacock EIP ERROR: Could not connect to MCP hub at {}. Is the MCP service running?".format(MCP_HUB_URL))                                                                               
            sublime.error_message("Peacock EIP Error: Connection failed. Is MCP service running at {}? Error {}".format(MCP_HUB_URL, e))                                                                                  
            # --- END FIX ---                                                                                
        except Exception as e:                                                                               
            # --- FIX: Changed f-strings to .format() ---                                                    
            print("Peacock EIP ERROR: An unexpected error occurred during communication: {}".format(e))      
            sublime.error_message("Peacock EIP Error: An unexpected error occurred: {}".format(e))           
            # --- END FIX ---                                                                                
                                                                                                             
                                                                                                             
    def handle_mcp_response(self, response_data):                                                            
        """                                                                                                  
        Handles the reliable JSON data received from the MCP's IRP.                                          
        This is how Peacock shows the result to the user in the editor.                                      
        """                                                                                                  
        # --- FIX: Changed f-string to .format() ---                                                         
        print("Peacock EIP: Handling MCP response (Status: {})...".format(response_data.get('status')))      
        # --- END FIX ---                                                                                    
                                                                                                             
        # Check the status from the MCP's response                                                           
        if response_data.get("status") == "success":                                                         
            command = response_data.get("command", "unknown")                                                
            # Get the internal, reliable structured data from the MCP's IRP output                           
            internal_structured_data = response_data.get("internal_data", {}) # Default to empty dict if     
missing                                                                                                      
                                                                                                             
            # --- FIX: Changed f-string to .format() ---                                                     
            sublime.status_message("Peacock EIP: Command '{}' successful.".format(command))                  
            # --- END FIX ---                                                                                
                                                                                                             
            # --- Display Logic based on Command Type ---                                                    
            if command == "explain":                                                                         
                # Expecting a structured explanation from IRP (e.g., functions list, or just text)           
                # Let's display this in a new tab or an output panel for clarity.                            
                # Output panel is good for explanations.                                                     
                panel = self.view.window().create_output_panel("peacock_explain")                            
                self.view.window().run_command("show_panel", {"panel": "output.peacock_explain"})            
                                                                                                             
                explanation_text = internal_structured_data.get('explanation_text', 'No explanation provided.')                                                                                                  
                # Check if there's structured data like functions breakdown from IRP                         
                if 'functions' in internal_structured_data:                                                  
                    # Build a simple summary from structured data for the panel title/start                  
                    # --- FIX: Changed f-strings to .format() ---                                            
                    summary_lines = ["Explanation for{}:".format(os.path.basename(response_data.get('location', {}).get('filepath', 'selection')))]               
                    for func in internal_structured_data['functions']:                                       
                        summary_lines.append("---")                                                          
                        summary_lines.append("Name: {}".format(func.get('name', 'N/A')))                     
                        summary_lines.append("Description: {}".format(func.get('description', 'N/A')))       
                        calls = func.get('calls', [])                                                        
                        summary_lines.append("Calls: {}".format(', '.join(calls) if calls else 'None'))      
                        # Note: Line/Col info is in internal_structured_data but not shown here, could add   
later                                                                                                        
                    # --- END FIX ---                                                                        
                    explanation_text = "\n".join(summary_lines)                                              
                elif 'result_text' in internal_structured_data: # Fallback to raw text if IRP just gave text 
                    explanation_text = internal_structured_data['result_text']                               
                else:                                                                                        
                    explanation_text = "No explanation data in response."                                    
                                                                                                             
                                                                                                             
                panel.set_read_only(False)                                                                   
                panel_edit_token = panel.begin_edit()                                                        
                panel.erase(panel_edit_token, panel.size()) # Clear panel content                            
                panel.insert(panel_edit_token, explanation_text) # Insert new content                        
                panel.end_edit(panel_edit_token)                                                             
                panel.set_read_only(True)                                                                    
                                                                                                             
                                                                                                             
            elif command == "fix" or command == "rewrite":                                                   
                # Expecting suggested code changes from IRP                                                  
                suggested_change = internal_structured_data.get("suggested_change")                          
                if suggested_change and suggested_change.get("type") == "replace":                           
                    replacement_code = suggested_change.get("replacement_code", "ERROR: No code provided")   
                    start_line_1based = suggested_change.get("start_line_1based", "??")                      
                    end_line_1based = suggested_change.get("end_line_1based", "??")                          
                    filepath = response_data.get('location', {}).get('filepath', 'selected text') # Get      
filepath from response location                                                                              
                    explanation = suggested_change.get("explanation", "No explanation provided.")            
                                                                                                             
                    # Display patch suggestion in an output panel                                            
                    panel = self.view.window().create_output_panel("peacock_patch")                          
                    self.view.window().run_command("show_panel", {"panel": "output.peacock_patch"})          
                    panel.set_read_only(False)                                                               
                    panel_edit_token = panel.begin_edit()                                                    
                    panel.erase(panel_edit_token, panel.size()) # Clear panel content                        
                    # --- FIX: Changed f-string to .format() for Python 3.3 compatibility and escaped \n as  
\\n ---                                                                                                      
                    panel.insert(panel_edit_token, "Suggested change for {} lines {}-{}:\\n\\nExplanation:{}\\n---\\nReplace with:\\n---\\n{}".format(os.path.basename(filepath), start_line_1based, end_line_1based,  
explanation, replacement_code))                                                                              
                    # --- END FIX ---                                                                        
                    panel.end_edit(panel_edit_token)                                                         
                    # TODO: Add button or command to apply the patch easily (CRM advanced)!                  
                    panel.set_read_only(True)                                                                
                                                                                                             
                else:                                                                                        
                    # --- FIX: Changed f-string to .format() and escaped \n as \\n ---                       
                    sublime.message_dialog("Peacock EIP: Command '{}' successful, but no valid change suggestion received from MCP. Raw data:\\n{}".format(command, json.dumps(internal_structured_data,           
indent=2)))                                                                                                  
                    # --- END FIX ---                                                                        
                                                                                                             
            elif command == "alternatives":                                                                  
                # Expecting a list of alternatives from IRP                                                  
                alternatives_list = internal_structured_data.get('alternatives', [])                         
                if alternatives_list:                                                                        
                    output_text = "Alternatives:\\n---\\n" + "\\n---\\n".join(alternatives_list) # FIX:      
escaped \n as \\n                                                                                            
                else:                                                                                        
                    output_text = internal_structured_data.get('result_text', 'No alternatives provided.') # 
Fallback to raw text                                                                                         
                    if not output_text or output_text == 'No alternatives provided.':                        
                        output_text = "No alternatives data in response."                                    
                                                                                                             
                                                                                                             
                panel = self.view.window().create_output_panel("peacock_alternatives")                       
                self.view.window().run_command("show_panel", {"panel": "output.peacock_alternatives"})       
                panel.set_read_only(False)                                                                   
                    panel_edit_token = panel.begin_edit()                                                    
                    panel.erase(panel_edit_token, panel.size()) # Clear panel content                        
                    panel.insert(panel_edit_token, output_text)                                              
                    panel.end_edit(panel_edit_token)                                                         
                    panel.set_read_only(True)                                                                
                                                                                                             
                elif command == "question":                                                                  
                    # Expecting an answer to a question from IRP                                             
                    answer_text = internal_structured_data.get('answer_text', 'No answer provided.')         
                    if not answer_text or answer_text == 'No answer provided.':                              
                        answer_text = internal_structured_data.get('result_text', 'No answer data in response.') # Fallback                                                                                       
                                                                                                                                                                                                                                                                                                                 
    ####3/4 MARKER####                                                                                       
                    panel = self.view.window().create_output_panel("peacock_question")                       
                    self.view.window().run_command("show_panel", {"panel": "output.peacock_question"})       
                    panel.set_read_only(False)                                                               
                    panel_edit_token = panel.begin_edit()                                                    
                    panel.erase(panel_edit_token, panel.size()) # Clear panel content                        
                    # --- FIX: Changed f-string to .format() and escaped \n as \\n ---                       
                    panel.insert(panel_edit_token, "Answer about selected text:\\n---\\n{}\\n---".format(answer_text))                                                                 
                    # --- END FIX ---                                                                        
                    panel.end_edit(panel_edit_token)                                                         
                    panel.set_read_only(True)                                                                
                                                                                                             
                # Handling for opening HTML reports generated by MCP (e.g. for 'document' command if added   
later)                                                                                                       
                # The MCP response for a command that generates HTML would include 'report_filepath'         
                report_filepath = response_data.get("report_filepath")                                       
                if report_filepath:                                                                          
                    # Open the saved HTML report in a browser (common Sublime pattern)                       
                    # --- FIX: Changed f-string to .format() ---                                             
                    sublime.status_message("Peacock EIP: Opening report: {}".format(report_filepath))        
                    # --- END FIX ---                                                                        
                    try:                                                                                     
                        # Use file:// protocol for local files - ensure path is absolute and correctly       
formatted for OS                                                                                             
                        abs_report_filepath = os.path.abspath(report_filepath)                               
                        # --- FIX: Changed f-string to .format() ---                                         
                        webbrowser.open('file://{}'.format(abs_report_filepath))                             
                        # --- END FIX ---                                                                    
                    except Exception as e:                                                                   
                        # --- FIX: Changed f-string to .format() ---                                         
                        sublime.error_message("Peacock EIP Error: Could not open report file {}. Error:{}".format(report_filepath, e))                                                                              
                        # --- END FIX ---                                                                    
                                                                                                             
                                                                                                             
            elif response_data.get("status") == "error":                                                     
                error_message = response_data.get("message", "Unknown error from MCP.")                      
                # --- FIX: Changed f-strings to .format() ---                                                
                print("Peacock EIP ERROR: MCP reported an error: {}".format(error_message))                  
                sublime.error_message("Peacock EIP Error: {}".format(error_message))                         
                # --- END FIX ---                                                                            
            else:                                                                                            
                # Handle unexpected response structure from MCP                                              
                # --- FIX: Changed f-strings to .format() ---                                                
                print("Peacock EIP ERROR: Unexpected response format from MCP: {}".format(response_data))    
                # --- END FIX ---                                                                            
                sublime.error_message("Peacock EIP Error: Unexpected response from MCP. Check console for details.")                                                                         


	        def run(self, edit):                                                                                 
            """                                                                                              
            The main entry point for Sublime commands. Captures intel and sends to MCP.                      
            """                                                                                              
            # 1. Capture Intel: Text, Command (implicit in class), Language, LOCATION                        
            text_to_process = self.get_selected_text()                                                       
            # Get command name automatically from class name (LlmHustleExplainCommand -> explain)            
            command_type = self.__class__.__name__.replace("LlmHustle", "").replace("Command", "").lower()   
            file_language = self.get_file_language()                                                         
            location_info = self.get_location_info() # Capture location info!                                
                                                                                                             
            # Basic validation - need selected text and a saved file with a path                             
            if text_to_process is None: # get_selected_text returns None if no text                          
                # sublime.status_message message already handled in get_selected_text                        
                return                                                                                       
            if location_info is None: # get_location_info returns None if no path                            
                # sublime.status_message message already handled in get_location_info                        
                return                                                                                       
                                                                                                             
            # 2. Send package to MCP (includes location_info)                                                
            self.send_to_mcp(text_to_process, command_type, file_language, location_info)                    
                                                                                                             
    # FINISH ### BASE EIP COMMAND CLASS (LlmHustleCommand) ###                                               
    # START ### SPECIFIC EIP COMMAND CLASSES ###                                                             
    # These now just inherit and the main run method handles the workflow.                                   
    # Add pass statement to each to make it valid Python.                                                    
    class LlmHustleExplainCommand(LlmHustleCommand): pass                                                    
    class LlmHustleFixCommand(LlmHustleFixCommand): pass                                                     
    class LlmHustleRewriteCommand(LlmHustleRewriteCommand): pass                                             
    class LlmHustleAlternativesCommand(LlmHustleAlternativesCommand): pass                                   
    class LlmHustleQuestionCommand(LlmHustleQuestionCommand): pass                                           
    # FINISH ### SPECIFIC EIP COMMAND CLASSES ###                                                            
                                                                                                             
    # START ### EIP MENU CONFIGURATION (Conceptual) ###                                                      
    # The actual menu definition goes into Context.sublime-menu                                              
    # Commands defined here implicitly by class names:                                                       
    # llm_hustle_explain                                                                                     
    # llm_hustle_fix                                                                                         
    # llm_hustle_rewrite                                                                                     
    # llm_hustle_alternatives                                                                                
    # llm_hustle_question                                                                                    
    # FINISH ### EIP MENU CONFIGURATION (Conceptual) ###                                                     
                                                                                                             
    ####END OF DOCUMENT#### # print("Peacock EIP: Captured location info: {}".format(location_info)) #       
Verbose logging                                                                                              
        return location_info                                                                                 
                                                                                                             
                                                                                                             
    def send_to_mcp(self, text, command_type, language, location_info):                                      
        """                                                                                                  
        Packages intel and sends request to the MCP hub via HTTP POST.                                       
        """                                                                                                  
        if location_info is None:                                                                            
            # Error handled in get_location_info and run                                                     
            return                                                                                           
                                                                                                             
        # Prep the package (data) as a dictionary - this is the AIP payload content!                         
        # The MCP will build the full AIP JSON payload around this content.                                  
        data_package_for_mcp = {                                                                             
            "text": text,                                                                                    
            "command": command_type,                                                                         
            "language": language,                                                                            
            "location": location_info                                                                        
        }                                                                                                    
        json_data = json.dumps(data_package_for_mcp).encode('utf-8')                                         
                                                                                                             
        # Prep the HTTP request                                                                              
        req = urllib.request.Request(MCP_HUB_URL, data=json_data,                                            
                                        headers={'Content-Type': 'application/json'},                        
                                        method='POST') # Specify POST explicitly                             
                                                                                                             
        # --- FIX: Changed f-strings to .format() for Python 3.3 compatibility ---                           
        sublime.status_message("Peacock EIP: Sending '{}' request for {}...".format(command_type,            
os.path.basename(location_info['filepath'])))                                                                
        print("Peacock EIP: Sending data for '{}' command...".format(command_type)) # Log what's being sent  
        # --- END FIX ---                                                                                    
                                                                                                             
        try:                                                                                                 
            # Send the request and get the response from the MCP                                             
            # MCP is expected to return JSON, containing status, command, and IRP's parsed internal data     
            with urllib.request.urlopen(req) as response:                                                    
                mcp_response_json = response.read().decode('utf-8')                                          
                mcp_response = json.loads(mcp_response_json)                                                 
                # --- FIX: Changed f-string to .format() ---                                                 
                # print("Peacock EIP: Received response from MCP:\n---\n{}\n---".format(mcp_response)) #     
Verbose logging                                                                                              
                # --- END FIX ---                                                                            
                sublime.status_message("Peacock EIP: MCP response received.")                                
                                                                                                             
                # Hand off the MCP's reliable JSON response to the handler                                   
                self.handle_mcp_response(mcp_response)                                                       
                                                                                                             
        except urllib.error.URLError as e:                                                                   
            # --- FIX: Changed f-strings to .format() ---                                                    
            print("Peacock EIP ERROR: Could not connect to MCP hub at {}. Is the MCP service running?".format(MCP_HUB_URL))                                                                               
            sublime.error_message("Peacock EIP Error: Connection failed. Is MCP service running at {}? Error:{}".format(MCP_HUB_URL, e))                                                                                  
            # --- END FIX ---                                                                                
        except Exception as e:                                                                               
            # --- FIX: Changed f-strings to .format() ---                                                    
            print("Peacock EIP ERROR: An unexpected error occurred during communication: {}".format(e))      
            sublime.error_message("Peacock EIP Error: An unexpected error occurred: {}".format(e))           
            # --- END FIX ---                                                                                
                                                                                                             
                                                                                                             
    def handle_mcp_response(self, response_data):                                                            
        """                                                                                                  
        Handles the reliable JSON data received from the MCP's IRP.                                          
        This is how Peacock shows the result to the user in the editor.                                      
        """                                                                                                  
        # --- FIX: Changed f-string to .format() ---                                                         
        print("Peacock EIP: Handling MCP response (Status: {})...".format(response_data.get('status')))      
        # --- END FIX ---                                                                                    
                                                                                                             
        # Check the status from the MCP's response                                                           
        if response_data.get("status") == "success":                                                         
            command = response_data.get("command", "unknown")                                                
            # Get the internal, reliable structured data from the MCP's IRP output                           
            internal_structured_data = response_data.get("internal_data", {}) # Default to empty dict if     
missing                                                                                                      
                                                                                                             
            # --- FIX: Changed f-string to .format() ---                                                     
            sublime.status_message("Peacock EIP: Command '{}' successful.".format(command))                  
            # --- END FIX ---                                                                                
                                                                                                             
            # --- Display Logic based on Command Type ---                                                    
            if command == "explain":                                                                         
                pass  # Expecting a structured explanation from IRP (e.g., functions list, or just text)     
                # Let's display this in a new tab or an output panel for clarity.                            
                # Output panel is good for explanations.                                                     
                panel = self.view.window().create_output_panel("peacock_explain")                            
                self.view.window().run_command("show_panel", {"panel": "output.peacock_explain"})            
                                                                                                             
                explanation_text = internal_structured_data.get('explanation_text', 'No explanation provided.')                                                                                                  
                # Check if there's structured data like functions breakdown from IRP                         
                if 'functions' in internal_structured_data:                                                  
                    # Build a simple summary from structured data for the panel title/start                  
                    # --- FIX: Changed f-strings to .format() ---                                            
                    summary_lines = ["Explanation for{}:".format(os.path.basename(response_data.get('location', {}).get('filepath', 'selection')))]               
                    for func in internal_structured_data['functions']:                                       
                        summary_lines.append("---")                                                          
                        summary_lines.append("Name: {}".format(func.get('name', 'N/A')))                     
                        summary_lines.append("Description: {}".format(func.get('description', 'N/A')))       
                        calls = func.get('calls', [])                                                        
                        summary_lines.append("Calls: {}".format(', '.join(calls) if calls else 'None'))      
                        # Note: Line/Col info is in internal_structured_data but not shown here, could add   
later                                                                                                        
                    # --- END FIX ---                                                                        
                    explanation_text = "\n".join(summary_lines)                                              
                elif 'result_text' in internal_structured_data: # Fallback to raw text if IRP just gave text 
                    explanation_text = internal_structured_data['result_text']                               
                else:                                                                                        
                    explanation_text = "No explanation data in response."                                    
                                                                                                             
                                                                                                             
                panel.set_read_only(False)                                                                   
                panel_edit_token = panel.begin_edit()                                                        
                panel.erase(panel_edit_token, panel.size()) # Clear panel content                            
                panel.insert(panel_edit_token, explanation_text) # Insert new content                        
                panel.end_edit(panel_edit_token)                                                             
                panel.set_read_only(True)                                                                    
                                                                                                             
                                                                                                             
            elif command == "fix" or command == "rewrite":                                                   
                # Expecting suggested code changes from IRP                                                  
                suggested_change = internal_structured_data.get("suggested_change")                          
                if suggested_change and suggested_change.get("type") == "replace":                           
                    replacement_code = suggested_change.get("replacement_code", "ERROR: No code provided")   
                    start_line_1based = suggested_change.get("start_line_1based", "??")                      
                    end_line_1based = suggested_change.get("end_line_1based", "??")                          
                    filepath = response_data.get('location', {}).get('filepath', 'selected text') # Get      
filepath from response location                                                                              
                    explanation = suggested_change.get("explanation", "No explanation provided.")            
                                                                                                             
                    # Display patch suggestion in an output panel                                            
                    panel = self.view.window().create_output_panel("peacock_patch")                          
                    self.view.window().run_command("show_panel", {"panel": "output.peacock_patch"})          
                    panel.set_read_only(False)                                                               
                    panel_edit_token = panel.begin_edit()                                                    
                    panel.erase(panel_edit_token, panel.size()) # Clear panel content                        
                    # --- FIX: Changed f-string to .format() for Python 3.3 compatibility and escaped \n as  
\\n ---                                                                                                      
                    panel.insert(panel_edit_token, "Suggested change for {} lines {}-{}:\\n\\nExplanation:{}\\n---\\nReplace with:\\n---\\n{}".format(os.path.basename(filepath), start_line_1based, end_line_1based,  
explanation, replacement_code))                                                                              
                    # --- END FIX ---                                                                        
                    panel.end_edit(panel_edit_token)                                                         
                    # TODO: Add button or command to apply the patch easily (CRM advanced)!                  
                    panel.set_read_only(True)                                                                
                                                                                                             
                else:                                                                                        
                    # --- FIX: Changed f-string to .format() and escaped \n as \\n ---                       
                    sublime.message_dialog("Peacock EIP: Command '{}' successful, but no valid change suggestion received from MCP. Raw data:\\n{}".format(command, json.dumps(internal_structured_data,           
indent=2)))                                                                                                  
                    # --- END FIX ---                                                                        
                                                                                                             
            elif command == "alternatives":                                                                  
                # Expecting a list of alternatives from IRP                                                  
                alternatives_list = internal_structured_data.get('alternatives', [])                         
                if alternatives_list:                                                                        
                    output_text = "Alternatives:\\n---\\n" + "\\n---\\n".join(alternatives_list) # FIX:      
escaped \n as \\n                                                                                            
                else:                                                                                        
                    output_text = internal_structured_data.get('result_text', 'No alternatives provided.') # 
Fallback to raw text                                                                                         
                    if not output_text or output_text == 'No alternatives provided.':                        
                        output_text = "No alternatives data in response."                                    
                                                                                                             
                                                                                                             
                panel = self.view.window().create_output_panel("peacock_alternatives")                       
                self.view.window().run_command("show_panel", {"panel": "output.peacock_alternatives"})       
                panel.set_read_only(False)                                                                   
                panel_edit_token = panel.begin_edit()                                                        
                panel.erase(panel_edit_token, panel.size()) # Clear panel content                            
                panel.insert(panel_edit_token, output_text)                                                  
                panel.end_edit(panel_edit_token)                                                             
                panel.set_read_only(True)                                                                    
                                                                                                             
            elif command == "question":                                                                      
                # Expecting an answer to a question from IRP                                                 
                answer_text = internal_structured_data.get('answer_text', 'No answer provided.')             
                if not answer_text or answer_text == 'No answer provided.':                                  
                    answer_text = internal_structured_data.get('result_text', 'No answer data in response.') 
# Fallback                                                                                                   
                                                                                                             
                                                                                                             
                                                                                                             
####3/4 MARKER####                                                                                           
                panel = self.view.window().create_output_panel("peacock_question")                           
                self.view.window().run_command("show_panel", {"panel": "output.peacock_question"})           
                panel.set_read_only(False)                                                                   
                panel_edit_token = panel.begin_edit()                                                        
                panel.erase(panel_edit_token, panel.size()) # Clear panel content                            
                # --- FIX: Changed f-string to .format() and escaped \n as \\n ---                           
                panel.insert(panel_edit_token, "Answer about selected text:\\n---\\n{}\\n---".format(answer_text))                                                                 
                # --- END FIX ---                                                                            
                panel.end_edit(panel_edit_token)                                                             
                panel.set_read_only(True)                                                                    
                                                                                                             
                # Handling for opening HTML reports generated by MCP (e.g. for 'document' command if added   
later)                                                                                                       
                # The MCP response for a command that generates HTML would include 'report_filepath'         
                report_filepath = response_data.get("report_filepath")                                       
                if report_filepath:                                                                          
                    # Open the saved HTML report in a browser (common Sublime pattern)                       
                    # --- FIX: Changed f-string to .format() ---                                             
                    sublime.status_message("Peacock EIP: Opening report: {}".format(report_filepath))        
                    # --- END FIX ---                                                                        
                    try:                                                                                     
                        # Use file:// protocol for local files - ensure path is absolute and correctly       
formatted for OS                                                                                             
                        abs_report_filepath = os.path.abspath(report_filepath)                               
                        # --- FIX: Changed f-string to .format() ---                                         
                        webbrowser.open('file://{}'.format(abs_report_filepath))                             
                        # --- END FIX ---                                                                    
                    except Exception as e:                                                                   
                        # --- FIX: Changed f-string to .format() ---                                         
                        sublime.error_message("Peacock EIP Error: Could not open report file {}. Error:{}".format(report_filepath, e))                                                                              
                        # --- END FIX ---                                                                    
                                                                                                             
                                                                                                             
            elif response_data.get("status") == "error":                                                     
                error_message = response_data.get("message", "Unknown error from MCP.")                      
                # --- FIX: Changed f-strings to .format() ---                                                
                print("Peacock EIP ERROR: MCP reported an error: {}".format(error_message))                  
                sublime.error_message("Peacock EIP Error: {}".format(error_message))                         
                # --- END FIX ---                                                                            
            else:                                                                                            
                # Handle unexpected response structure from MCP                                              
                # --- FIX: Changed f-strings to .format() ---                                                
                print("Peacock EIP ERROR: Unexpected response format from MCP: {}".format(response_data))    
                # --- END FIX ---                                                                            
                sublime.error_message("Peacock EIP Error: Unexpected response from MCP. Check console for details.")                                                                                                   
                                                                                                                                                                                                                  
        def run(self, edit):                                                                                 
            """                                                                                              
            The main entry point for Sublime commands. Captures intel and sends to MCP.                      
            """                                                                                              
            # 1. Capture Intel: Text, Command (implicit in class), Language, LOCATION                        
            text_to_process = self.get_selected_text()                                                       
            # Get command name automatically from class name (LlmHustleExplainCommand -> explain)            
            command_type = self.__class__.__name__.replace("LlmHustle", "").replace("Command", "").lower()   
            file_language = self.get_file_language()                                                         
            location_info = self.get_location_info() # Capture location info!                                
                                                                                                             
            # Basic validation - need selected text and a saved file with a path                             
            if text_to_process is None: # get_selected_text returns None if no text                          
                # sublime.status_message message already handled in get_selected_text                        
                return                                                                                       
            if location_info is None: # get_location_info returns None if no path                            
                # sublime.status_message message already handled in get_location_info                        
                return                                                                                       
                                                                                                             
            # 2. Send package to MCP (includes location_info)                                                
            self.send_to_mcp(text_to_process, command_type, file_language, location_info)                    
                                                                                                             
    # FINISH ### BASE EIP COMMAND CLASS (LlmHustleCommand) ###                                               
    # START ### SPECIFIC EIP COMMAND CLASSES ###                                                             
    # These now just inherit and the main run method handles the workflow.                                   
    # Add pass statement to each to make it valid Python.                                                    
    class LlmHustleExplainCommand(LlmHustleCommand): pass                                                    
    class LlmHustleFixCommand(LlmHustleFixCommand): pass                                                     
    class LlmHustleRewriteCommand(LlmHustleRewriteCommand): pass                                             
    class LlmHustleAlternativesCommand(LlmHustleAlternativesCommand): pass                                   
    class LlmHustleQuestionCommand(LlmHustleQuestionCommand): pass                                           
    # FINISH ### SPECIFIC EIP COMMAND CLASSES ###                                                            
                                                                                                             
    # START ### EIP MENU CONFIGURATION (Conceptual) ###                                                      
    # The actual menu definition goes into Context.sublime-menu                                              
    # Commands defined here implicitly by class names:                                                       
    # llm_hustle_explain                                                                                     
    # llm_hustle_fix                                                                                         
    # llm_hustle_rewrite                                                                                     
    # llm_hustle_alternatives                                                                                
    # llm_hustle_question                                                                                    
    # FINISH ### EIP MENU CONFIGURATION (Conceptual) ###                                                     
                                                                                                             
    ####END OF DOCUMENT#### 
####END OF DOCUMENT####

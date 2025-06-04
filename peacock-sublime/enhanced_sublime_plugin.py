# Enhanced Sublime Plugin with Peacock 4-Stage Integration
import sublime
import sublime_plugin
import json
import urllib.request
import os
import webbrowser
import subprocess
import shutil
import datetime

# --- CONFIGURATION ---
MCP_HUB_URL = "http://127.0.0.1:8000/process"
MARKING_SCRIPT_PATH = os.path.join(sublime.packages_path(), "peacock-sublime", "mark_code.py")

# --- BASE ENHANCED COMMAND CLASS ---
class PeacockCommand(sublime_plugin.TextCommand):
    """Enhanced base class for all Peacock commands"""

    def get_selected_text(self):
        """Gets the text from the primary selection"""
        selected_text = ""
        for region in self.view.sel():
            if not region.empty():
                selected_text = self.view.substr(region)
                break

        if not selected_text:
            sublime.status_message("Peacock: No text selected.")
            return None

        return selected_text.strip()

    def get_file_language(self):
        """Gets the detected language (syntax) of the current file"""
        syntax_setting = self.view.settings().get('syntax')
        if not syntax_setting:
            return "unknown"

        language_name = "unknown"
        parts = syntax_setting.split('/')
        if len(parts) > 1:
            file_part = parts[-1]
            language_name = file_part.split('.')[0]

        return language_name.lower()

    def get_location_info(self):
        """Gets file path and selected region details"""
        file_path = self.view.file_name()
        if not file_path:
            sublime.status_message("Peacock: Operation requires a saved file.")
            return None

        primary_region = None
        for region in self.view.sel():
            if not region.empty():
                primary_region = region
                break
        
        if not primary_region:
            sublime.status_message("Peacock: No text selected for location info.")
            return None

        start_row, start_col = self.view.rowcol(primary_region.begin())
        end_row, end_col = self.view.rowcol(primary_region.end())

        location_info = {
            "filepath": file_path,
            "selected_region": {
                "start": {"row": start_row, "col": start_col, "line_1based": start_row + 1, "col_1based": start_col + 1},
                "end": {"row": end_row, "col": end_col, "line_1based": end_row + 1, "col_1based": end_col + 1}
            }
        }

        return location_info

    def is_enabled(self):
        """Base enablement - most commands need selection and saved file"""
        has_selection = any(not region.empty() for region in self.view.sel())
        has_filepath = self.view.file_name() is not None
        return has_selection and has_filepath

    def send_to_mcp(self, text, command_type, language, location_info):
        """Enhanced MCP communication with Peacock stage support"""
        if location_info is None and command_type not in ["create_project", "mark_file", "initial_analysis", "spark_analysis", "falcon_architecture", "eagle_implementation", "hawk_qa", "peacock_full"]:
            sublime.status_message("Peacock: Operation requires a saved file.")
            return

        if text is None and command_type not in ["mark_file", "initial_analysis"]:
            sublime.status_message("Peacock: Operation requires text selection.")
            return

        # Enhanced data package for Peacock stages
        data_package_for_mcp = {
            "text": text,
            "command": command_type,
            "language": language,
            "location": location_info,
            "filepath": location_info.get('filepath') if location_info else None,
            "timestamp": datetime.datetime.now().isoformat(),
            "peacock_version": "2.0"
        }
        
        json_data = json.dumps(data_package_for_mcp).encode('utf-8')
        req = urllib.request.Request(MCP_HUB_URL, data=json_data,
                                   headers={'Content-Type': 'application/json'},
                                   method='POST')

        sublime.status_message("Peacock: Sending '{}' request...".format(command_type))
        print("Peacock: Sending data for '{}' command...".format(command_type))

        try:
            with urllib.request.urlopen(req) as response:
                mcp_response_json = response.read().decode('utf-8')
                mcp_response = json.loads(mcp_response_json)
                sublime.status_message("Peacock: Response received.")
                self.handle_mcp_response(mcp_response)

        except urllib.error.URLError as e:
            print("Peacock ERROR: Could not connect to MCP hub at {}. Error: {}".format(MCP_HUB_URL, e))
            sublime.error_message("Peacock Error: Connection failed. Is MCP service running at {}? Error: {}".format(MCP_HUB_URL, e))
        except Exception as e:
            print("Peacock ERROR: Unexpected error: {}".format(e))
            sublime.error_message("Peacock Error: Unexpected error: {}".format(e))

    def handle_mcp_response(self, response_data):
        """Enhanced response handler for Peacock stages and traditional commands"""
        print("Peacock: Handling response (Status: {})...".format(response_data.get('status')))

        if response_data.get("status") == "success":
            command = response_data.get("command", "unknown")
            internal_structured_data = response_data.get("internal_data", {})

            sublime.status_message("Peacock: Command '{}' successful.".format(command))

            # Handle HTML reports for Peacock stages
            report_filepath = response_data.get("report_filepath")
            if report_filepath:
                sublime.status_message("Peacock: Opening report: {}".format(os.path.basename(report_filepath)))
                try:
                    abs_report_filepath = os.path.abspath(report_filepath)
                    if os.path.exists(abs_report_filepath):
                        webbrowser.open('file://{}'.format(abs_report_filepath))
                        print("Peacock: Opened report in browser: file://{}".format(abs_report_filepath))
                    else:
                        sublime.error_message("Peacock Error: Report file not found at '{}'.".format(report_filepath))
                except Exception as e:
                    sublime.error_message("Peacock Error: Could not open report file. Error: {}".format(e))
                return  # Don't show panel if report opened

            # Handle Peacock stage outputs in panels if no report
            if command in ["spark_analysis", "falcon_architecture", "eagle_implementation", "hawk_qa", "peacock_full"]:
                stage_name = command.replace("_", " ").title()
                panel = self.view.window().create_output_panel("peacock_{}".format(command))
                self.view.window().run_command("show_panel", {"panel": "output.peacock_{}".format(command)})
                
                result_text = internal_structured_data.get('result_text', 'No analysis provided.')
                
                panel.set_read_only(False)
                panel_edit_token = panel.begin_edit()
                panel.erase(panel_edit_token, panel.size())
                
                header = "=== PEACOCK {} ===\n\n".format(stage_name.upper())
                panel.insert(panel_edit_token, header + result_text)
                
                panel.end_edit(panel_edit_token)
                panel.set_read_only(True)

            # Traditional code commands
            elif command == "explain":
                if not report_filepath:
                    panel = self.view.window().create_output_panel("peacock_explain")
                    self.view.window().run_command("show_panel", {"panel": "output.peacock_explain"})
                    explanation_text = internal_structured_data.get('explanation_text', internal_structured_data.get('result_text', 'No explanation provided.'))
                    panel.set_read_only(False)
                    panel_edit_token = panel.begin_edit()
                    panel.erase(panel_edit_token, panel.size())
                    panel.insert(panel_edit_token, explanation_text)
                    panel.end_edit(panel_edit_token)
                    panel.set_read_only(True)

            elif command in ["fix", "rewrite"]:
                suggested_change = internal_structured_data.get("suggested_change")
                if suggested_change and suggested_change.get("type") == "replace":
                    replacement_code = suggested_change.get("replacement_code", "ERROR: No code provided")
                    start_line_1based = suggested_change.get("start_line_1based", "??")
                    end_line_1based = suggested_change.get("end_line_1based", "??")
                    filepath = response_data.get('location', {}).get('filepath', self.view.file_name() if self.view.file_name() else 'selected text')
                    explanation = suggested_change.get("explanation", "No explanation provided.")

                    panel = self.view.window().create_output_panel("peacock_patch")
                    self.view.window().run_command("show_panel", {"panel": "output.peacock_patch"})
                    panel.set_read_only(False)
                    panel_edit_token = panel.begin_edit()
                    panel.erase(panel_edit_token, panel.size())
                    
                    output_text = "Suggested change for {} lines {}-{}:\n\nExplanation: {}\n---\n####START_SUGGESTED_CHANGE####\n{}\n####END_SUGGESTED_CHANGE####\n---".format(
                        os.path.basename(filepath) if filepath else 'current file',
                        start_line_1based,
                        end_line_1based,
                        explanation,
                        replacement_code
                    )
                    panel.insert(panel_edit_token, output_text)
                    panel.end_edit(panel_edit_token)
                    panel.set_read_only(True)
                else:
                    sublime.message_dialog("Peacock: Command '{}' successful, but no valid change suggestion received.".format(command))

            elif command == "alternatives":
                if not report_filepath:
                    panel = self.view.window().create_output_panel("peacock_alternatives")
                    self.view.window().run_command("show_panel", {"panel": "output.peacock_alternatives"})
                    output_text = internal_structured_data.get('result_text', 'No alternatives provided.')
                    panel.set_read_only(False)
                    panel_edit_token = panel.begin_edit()
                    panel.erase(panel_edit_token, panel.size())
                    panel.insert(panel_edit_token, output_text)
                    panel.end_edit(panel_edit_token)
                    panel.set_read_only(True)

            elif command == "question":
                if not report_filepath:
                    panel = self.view.window().create_output_panel("peacock_question")
                    self.view.window().run_command("show_panel", {"panel": "output.peacock_question"})
                    answer_text = internal_structured_data.get('answer_text', internal_structured_data.get('result_text', 'No answer provided.'))
                    panel.set_read_only(False)
                    panel_edit_token = panel.begin_edit()
                    panel.erase(panel_edit_token, panel.size())
                    panel.insert(panel_edit_token, "Answer about selected text:\n---\n{}\n---".format(answer_text))
                    panel.end_edit(panel_edit_token)
                    panel.set_read_only(True)

            elif command == "create_project":
                if not report_filepath:
                    project_plan_text = internal_structured_data.get('project_plan_text', internal_structured_data.get('result_text', 'No project plan received.'))
                    new_view = self.view.window().new_file()
                    new_view.set_name("Project Plan")
                    new_view.set_syntax_by_selector('text.plain')
                    edit_token = new_view.begin_edit()
                    new_view.insert(edit_token, project_plan_text)
                    new_view.end_edit(edit_token)
                    new_view.set_scratch(True)

        elif response_data.get("status") == "error":
            error_message = response_data.get("message", "Unknown error from MCP.")
            print("Peacock ERROR: MCP reported an error: {}".format(error_message))
            sublime.error_message("Peacock Error: {}".format(error_message))
        else:
            print("Peacock ERROR: Unexpected response format: {}".format(response_data))
            sublime.error_message("Peacock Error: Unexpected response from MCP.")

    def run(self, edit):
        """Main entry point for text-processing commands"""
        text_to_process = self.get_selected_text()
        command_type = self.__class__.__name__.replace("Peacock", "").replace("Command", "").lower()
        
        # Convert class names to proper command names
        command_mapping = {
            "spark": "spark_analysis",
            "falcon": "falcon_architecture", 
            "eagle": "eagle_implementation",
            "hawk": "hawk_qa",
            "full": "peacock_full"
        }
        command_type = command_mapping.get(command_type, command_type)
        
        file_language = self.get_file_language()
        location_info = self.get_location_info()

        if text_to_process is None:
            return
        if location_info is None and command_type not in ["peacock_full"]:
            return

        self.send_to_mcp(text_to_process, command_type, file_language, location_info)


# --- PEACOCK STAGE COMMANDS ---

class PeacockSparkCommand(PeacockCommand):
    """Spark - Requirements Analysis Stage"""
    pass

class PeacockFalconCommand(PeacockCommand):
    """Falcon - Architecture Design Stage"""
    pass

class PeacockEagleCommand(PeacockCommand):
    """Eagle - Implementation Stage"""
    pass

class PeacockHawkCommand(PeacockCommand):
    """Hawk - Quality Assurance Stage"""
    pass

class PeacockFullCommand(PeacockCommand):
    """Complete 4-stage Peacock analysis"""
    
    def is_enabled(self):
        """Full analysis only needs text selection"""
        return any(not region.empty() for region in self.view.sel())


# --- TRADITIONAL CODE COMMANDS (Enhanced) ---

class PeacockExplainCommand(PeacockCommand):
    """Traditional explain command"""
    pass

class PeacockFixCommand(PeacockCommand):
    """Traditional fix command"""
    pass

class PeacockRewriteCommand(PeacockCommand):
    """Traditional rewrite command"""
    pass

class PeacockAlternativesCommand(PeacockCommand):
    """Traditional alternatives command"""
    pass

class PeacockQuestionCommand(PeacockCommand):
    """Traditional question command"""
    pass

class PeacockCreateProjectCommand(PeacockCommand):
    """Traditional create project command"""
    pass


# --- FILE MARKING COMMAND (Enhanced) ---

class PeacockMarkFilesCommand(PeacockCommand):
    """Enhanced file marking with Peacock integration"""
    
    def is_enabled(self):
        """File marking doesn't require text selection"""
        return self.view.window() is not None

    def run(self, edit):
        """Enhanced file marking workflow"""
        window = self.view.window()
        if window is None:
            sublime.error_message("Peacock Error: No active window.")
            return

        window.show_input_panel(
            "Enter file path to mark:",
            "",
            self.on_file_path_entered,
            None,
            None
        )

    def on_file_path_entered(self, file_path):
        """Enhanced callback with Peacock analysis"""
        if not file_path:
            sublime.status_message("Peacock: No file path entered.")
            return

        abs_file_path = os.path.abspath(os.path.expanduser(file_path))

        if not os.path.isfile(abs_file_path):
            sublime.error_message("Peacock Error: File not found at '{}'.".format(abs_file_path))
            return

        sublime.status_message("Peacock: Marking file '{}'...".format(os.path.basename(abs_file_path)))
        print("Peacock: Processing file for marking: {}".format(abs_file_path))

        # Backup original file
        backup_path = "{}.peacock_backup_{}".format(abs_file_path, datetime.datetime.now().strftime('%Y%m%d_%H%M%S'))

        try:
            shutil.copy2(abs_file_path, backup_path)
            print("Peacock: Original file backed up to {}".format(backup_path))
            sublime.status_message("Peacock: File backed up.")
        except Exception as e:
            print("Peacock Error: Failed to backup file {}: {}".format(abs_file_path, e))
            sublime.error_message("Peacock Error: Failed to backup file. Error: {}".format(e))
            return

        # Call marking script
        try:
            script_output_path = "{}-marked{}".format(os.path.splitext(abs_file_path)[0], os.path.splitext(abs_file_path)[1])
            
            print("Peacock: Calling marking script: {} 1 \"{}\"".format(MARKING_SCRIPT_PATH, abs_file_path))
            process_result = subprocess.run([MARKING_SCRIPT_PATH, "1", abs_file_path], 
                                          capture_output=True, text=True, check=True, shell=True)

            print("Marking script stdout:\n", process_result.stdout)
            
            if os.path.exists(script_output_path):
                print("Peacock: Marked file created at {}".format(script_output_path))
                sublime.status_message("Peacock: File marked successfully.")
            else:
                print("Peacock Error: Marking script did not create expected file at '{}'".format(script_output_path))
                sublime.error_message("Peacock Error: Marking script failed.")
                return

        except FileNotFoundError:
            print("Peacock Error: Marking script not found at '{}'".format(MARKING_SCRIPT_PATH))
            sublime.error_message("Peacock Error: Marking script not found.")
            return
        except subprocess.CalledProcessError as e:
            print("Peacock Error: Marking script failed with code {}".format(e.returncode))
            sublime.error_message("Peacock Error: Marking script failed.")
            return
        except Exception as e:
            print("Peacock Error: Unexpected error running marking script: {}".format(e))
            sublime.error_message("Peacock Error: Marking script error: {}".format(e))
            return

        # Replace original with marked version
        try:
            shutil.move(script_output_path, abs_file_path)
            print("Peacock: Replaced original file with marked version.")
            sublime.status_message("Peacock: File marking complete.")

            # Optional: Open marked file
            window.open_file(abs_file_path)

        except Exception as e:
            print("Peacock Error: Failed to replace original file: {}".format(e))
            sublime.error_message("Peacock Error: Failed to replace file: {}".format(e))
            return

        # Send marked content to MCP for initial analysis
        try:
            with open(abs_file_path, 'r', encoding='utf-8') as f:
                marked_file_content = f.read()

            print("Peacock: File marked and ready for Peacock analysis.")
            print("Peacock: Marked content length: {} characters".format(len(marked_file_content)))

            # Auto-trigger Spark analysis on marked file
            location_info = {
                "filepath": abs_file_path,
                "selected_region": {
                    "start": {"row": 0, "col": 0, "line_1based": 1, "col_1based": 1},
                    "end": {"row": 0, "col": 0, "line_1based": 1, "col_1based": 1}
                }
            }
            
            self.send_to_mcp(marked_file_content[:1000], "spark_analysis", "python", location_info)

        except Exception as e:
            print("Peacock Error: Failed to read marked file: {}".format(e))
            sublime.error_message("Peacock Error: Failed to analyze marked file.")


# --- QUICK ACTIONS COMMAND ---

class PeacockQuickActionsCommand(PeacockCommand):
    """Quick actions menu for Peacock operations"""
    
    def is_enabled(self):
        """Always enabled if window exists"""
        return self.view.window() is not None
    
    def run(self, edit):
        """Show quick actions menu"""
        items = [
            ["🦚 Full Peacock Analysis", "Complete 4-stage project analysis"],
            ["⚡ Spark - Requirements", "Analyze project requirements"],
            ["🦅 Falcon - Architecture", "Design system architecture"],
            ["🦅 Eagle - Implementation", "Generate implementation code"],
            ["🦅 Hawk - Quality Assurance", "Create QA strategy"],
            ["---", ""],
            ["🔧 Fix Code", "Fix issues in selected code"],
            ["📖 Explain Code", "Explain selected code"],
            ["✨ Rewrite Code", "Improve selected code"],
            ["🔀 Alternatives", "Show alternative approaches"],
            ["❓ Ask Question", "Ask about selected code"],
            ["---", ""],
            ["📁 Mark Files", "Mark files with Peacock sections"],
            ["📊 Open Reports Folder", "Open Peacock reports directory"]
        ]
        
        def on_select(index):
            if index == -1:
                return
            
            item = items[index]
            if item[0] == "---":
                return
            
            command_map = {
                "🦚 Full Peacock Analysis": "peacock_full",
                "⚡ Spark - Requirements": "peacock_spark", 
                "🦅 Falcon - Architecture": "peacock_falcon",
                "🦅 Eagle - Implementation": "peacock_eagle",
                "🦅 Hawk - Quality Assurance": "peacock_hawk",
                "🔧 Fix Code": "peacock_fix",
                "📖 Explain Code": "peacock_explain",
                "✨ Rewrite Code": "peacock_rewrite",
                "🔀 Alternatives": "peacock_alternatives",
                "❓ Ask Question": "peacock_question",
                "📁 Mark Files": "peacock_mark_files",
                "📊 Open Reports Folder": self.open_reports_folder
            }
            
            selected = item[0]
            if selected in command_map:
                if callable(command_map[selected]):
                    command_map[selected]()
                else:
                    self.view.run_command(command_map[selected])
        
        self.view.window().show_quick_panel(items, on_select)
    
    def open_reports_folder(self):
        """Open the Peacock reports directory"""
        reports_dir = os.path.expanduser("~/peacock_reports")
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)
        
        if sublime.platform() == "windows":
            os.startfile(reports_dir)
        elif sublime.platform() == "osx":
            subprocess.run(["open", reports_dir])
        else:
            subprocess.run(["xdg-open", reports_dir])


# --- PEACOCK STATUS COMMAND ---

class PeacockStatusCommand(sublime_plugin.WindowCommand):
    """Show Peacock system status"""
    
    def run(self):
        """Display Peacock system status"""
        try:
            # Test MCP connection
            test_data = {"test": "connection"}
            json_data = json.dumps(test_data).encode('utf-8')
            req = urllib.request.Request(MCP_HUB_URL, data=json_data,
                                       headers={'Content-Type': 'application/json'},
                                       method='POST')
            
            with urllib.request.urlopen(req, timeout=5) as response:
                mcp_status = "✅ Connected"
        except:
            mcp_status = "❌ Disconnected"
        
        # Check reports directory
        reports_dir = os.path.expanduser("~/peacock_reports")
        reports_exist = os.path.exists(reports_dir)
        report_count = len([f for f in os.listdir(reports_dir) if f.endswith('.html')]) if reports_exist else 0
        
        status_info = """
PEACOCK SYSTEM STATUS

🦚 Peacock Version: 2.0 Enhanced
📡 MCP Server: {}
📁 Reports Directory: {} ({} reports)
🔧 Plugin Location: {}

AVAILABLE COMMANDS:
• Full Peacock Analysis (4 stages)
• Individual Stage Analysis
• Traditional Code Operations
• File Marking System
• Quick Actions Menu

Use Ctrl+Shift+P → "Peacock" to access commands
""".format(
            mcp_status,
            "✅ Ready" if reports_exist else "⚠️ Will be created",
            report_count,
            sublime.packages_path()
        )
        
        sublime.message_dialog(status_info)
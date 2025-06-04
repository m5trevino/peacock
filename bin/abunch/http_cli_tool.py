# START ### IMPORTS ###
import os
import json
import datetime
import re
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog, Checkbutton, IntVar, Frame, Label, Button, Toplevel, Listbox, Scrollbar, END, MULTIPLE
import requests
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text
from rich.table import Table
import getpass
import time
import traceback # For detailed error printing
# FINISH ### IMPORTS ###

# START ### CONFIG SETUP ###
CONSOLE = Console() # Let rich figure out the best theme by default
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESPONSES_DIR = os.path.join(BASE_DIR, "responses")
REQUESTS_DIR = os.path.join(BASE_DIR, "requests")
LOG_STATE_FILE = os.path.join(BASE_DIR, ".log_state.json")

# Ensure log directories exist
os.makedirs(RESPONSES_DIR, exist_ok=True)
os.makedirs(REQUESTS_DIR, exist_ok=True)

# Global state for request counter
REQUEST_COUNTER = {}
# FINISH ### CONFIG SETUP ###

# START ### LOGGING UTILITIES ###
def load_log_state():
    """Loads the hourly request counter state."""
    global REQUEST_COUNTER
    if os.path.exists(LOG_STATE_FILE):
        try:
            with open(LOG_STATE_FILE, 'r') as f:
                REQUEST_COUNTER = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            CONSOLE.print(f"[bold red]Error loading log state:[/bold red] {e}. Resetting state.")
            REQUEST_COUNTER = {}
    else:
        REQUEST_COUNTER = {}

def save_log_state():
    """Saves the hourly request counter state."""
    try:
        with open(LOG_STATE_FILE, 'w') as f:
            json.dump(REQUEST_COUNTER, f)
    except IOError as e:
        CONSOLE.print(f"[bold red]Error saving log state:[/bold red] {e}")

def get_next_request_number():
    """Gets the next sequential request number, resetting hourly."""
    now = datetime.datetime.now()
    hour_key = now.strftime('%Y-%U-%H') # Year-WeekOfYear-Hour

    load_log_state() # Load fresh state each time

    current_count = REQUEST_COUNTER.get(hour_key, 0)
    next_count = current_count + 1
    REQUEST_COUNTER[hour_key] = next_count

    # Clean up old keys (older than current hour) - simple cleanup
    current_keys = list(REQUEST_COUNTER.keys())
    for key in current_keys:
        if key != hour_key:
            del REQUEST_COUNTER[key]

    save_log_state() # Save updated state
    return next_count

def generate_log_filename():
    """Generates request/response log filenames."""
    now = datetime.datetime.now()
    req_num = get_next_request_number()
    week_num = now.strftime('%U') # Week number (00-53)
    hour_min = now.strftime('%H%M') # HourMinute (HHMM)

    base_filename = f"{req_num:02d}-{week_num}-{hour_min}"
    req_filename = f"req-{base_filename}.json"
    res_filename = f"res-{base_filename}.json"
    return req_filename, res_filename

def log_request(request_data, filename):
    """Logs the request details to a JSON file, excluding password."""
    filepath = os.path.join(REQUESTS_DIR, filename)
    try:
        # Create a copy to modify for logging
        log_data = request_data.copy()

        # Ensure headers are serializable
        if 'headers' in log_data and log_data['headers']:
             # Make sure it's a plain dict
             log_data['headers'] = dict(log_data['headers'])

        # Ensure password is NEVER logged from top-level or common body structures
        if 'password' in log_data:
            # If password somehow ended up top-level (it shouldn't), remove it
            del log_data['password']

        # Specifically check the body for username/password structure if it exists
        if 'body' in log_data and isinstance(log_data['body'], str):
             try:
                 body_json = json.loads(log_data['body'])
                 if isinstance(body_json, dict) and 'password' in body_json:
                     # Log the body structure but mask password
                     body_json['password'] = '*** MASKED IN LOG ***'
                     log_data['body'] = json.dumps(body_json) # Store modified JSON string
             except (json.JSONDecodeError, TypeError):
                 # Ignore if body is not JSON or not a dict
                 pass
        elif 'body' in log_data and isinstance(log_data['body'], dict):
            # If body is already a dict (less likely with current flow, but possible)
            if 'password' in log_data['body']:
                log_data['body']['password'] = '*** MASKED IN LOG ***'


        with open(filepath, 'w') as f:
            json.dump(log_data, f, indent=4)
        CONSOLE.print(f"[green]Request logged:[/green] [cyan]{filepath}[/cyan]")
    except (IOError, TypeError) as e:
        CONSOLE.print(f"[bold red]Error logging request:[/bold red] {e}")
        CONSOLE.print("Offending log_data:", log_data) # Print data that caused error

def log_response(response, filename):
    """Logs the response details to a JSON file."""
    filepath = os.path.join(RESPONSES_DIR, filename)
    try:
        response_data = {
            'status_code': response.status_code,
            'headers': dict(response.headers), # Convert to regular dict
            'elapsed_time_ms': response.elapsed.total_seconds() * 1000,
            'url': response.url, # Final URL after redirects
            'history': [resp.url for resp in response.history], # Redirect history
        }
        # Try to decode JSON body, otherwise store raw text
        try:
             # Use response.json() which handles decoding based on headers
            response_data['body'] = response.json()
        except json.JSONDecodeError:
            # Fallback for non-JSON or empty responses
            response_data['body'] = response.text

        with open(filepath, 'w') as f:
            # Use pretty printing for the log file itself
            json.dump(response_data, f, indent=4, sort_keys=True)
        CONSOLE.print(f"[green]Response logged:[/green] [cyan]{filepath}[/cyan]")
    except (IOError, TypeError, AttributeError) as e:
        CONSOLE.print(f"[bold red]Error logging response:[/bold red] {e} - Response type: {type(response)}")

# FINISH ### LOGGING UTILITIES ###

# START ### GUI UTILITIES ###

def get_headers_from_gui():
    """Opens a Tkinter window to paste and process headers."""
    headers_dict = {}
    processed = False

    # Need a hidden root for the Toplevel window if not run from main Tk loop
    root_gui = tk.Tk()
    root_gui.withdraw()

    def process_headers():
        nonlocal headers_dict, processed
        raw_headers = text_area.get("1.0", tk.END).strip()
        headers_dict = parse_headers(raw_headers)
        if headers_dict is None: # Parsing failed
             messagebox.showerror("Parsing Error", "Could not parse headers. Check format.\nExpected 'Key: Value' or similar per line.")
             headers_dict = {} # Reset
        else:
            processed = True
            window.destroy() # Close this specific window

    def parse_headers(raw_text):
        """Parses multi-format headers into a dictionary."""
        parsed = {}
        lines = raw_text.splitlines()
        for line_num, line in enumerate(lines):
            line = line.strip()
            if not line or line.startswith('#'): # Skip empty lines and comments
                continue
            key, value = None, None
            # Try: Key: Value (most common)
            match_colon = re.match(r'^\s*([^:]+?)\s*:\s*(.*)\s*$', line)
            # Try: "Key": "Value" (JSON-like)
            match_quoted = re.match(r'^\s*"([^"]+?)"\s*:\s*"([^"]*?)"\s*,?\s*$', line)
             # Try: Key Value (Less common, use as fallback)
            match_space = re.match(r'^\s*([\w-]+)\s+(.+)\s*$', line)

            if match_quoted:
                key = match_quoted.group(1).strip()
                value = match_quoted.group(2).strip()
                # CONSOLE.print(f"[dim]Parsed header (quoted):[/dim] '{key}': '{value}'")
            elif match_colon:
                key = match_colon.group(1).strip()
                value = match_colon.group(2).strip().rstrip(',') # Remove trailing commas
                # CONSOLE.print(f"[dim]Parsed header (colon):[/dim] '{key}': '{value}'")
            elif match_space:
                 # Only use space separation if no colon was found
                 if ':' not in line:
                     key = match_space.group(1).strip()
                     value = match_space.group(2).strip().rstrip(',')
                     # CONSOLE.print(f"[dim]Parsed header (space):[/dim] '{key}': '{value}'")
                 else:
                    CONSOLE.print(f"[yellow]Warning:[/yellow] Line {line_num+1} skipped (contains ':' but not standard format): '{line}'")
                    continue
            else:
                 CONSOLE.print(f"[yellow]Warning:[/yellow] Line {line_num+1} skipped (unparseable): '{line}'")
                 continue

            if key:
                 # Overwrite duplicate keys, last one wins (standard HTTP behavior)
                 parsed[key] = value

        return parsed # Return dict (empty if nothing parsed)

    window = Toplevel(root_gui) # Attach to hidden root
    window.title("Paste Headers")
    window.geometry("500x400")
    window.configure(bg='#1e1e1e') # Dark background

    label = tk.Label(window, text="Paste headers below (e.g., Key: Value per line):", fg='#00ffcc', bg='#1e1e1e', font=("Consolas", 12))
    label.pack(pady=10)

    text_area = scrolledtext.ScrolledText(window, wrap=tk.WORD, height=15, width=60, bg='#2d2d2d', fg='#cccccc', insertbackground='white', font=("Consolas", 11))
    text_area.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
    text_area.focus_set() # Put cursor in text area

    submit_button = tk.Button(window, text="Process Headers", command=process_headers, bg='#00ffcc', fg='#1e1e1e', font=("Consolas", 12, "bold"), relief=tk.FLAT)
    submit_button.pack(pady=10)

    # Center the window
    window.eval('tk::PlaceWindow . center')

    # Make modal - waits until window is closed
    window.grab_set()
    root_gui.wait_window(window) # Wait for this Toplevel window specifically
    root_gui.destroy() # Clean up hidden root after Toplevel closes

    return headers_dict if processed else {} # Return empty if window closed without processing

def select_variables_from_log_gui(log_data):
    """Opens a Tkinter window to select key-value pairs from log data."""
    selected_variables = {}
    processed = False
    log_data_flat = {} # Store flat structure key -> value

    # Need a hidden root for the Toplevel window
    root_gui = tk.Tk()
    root_gui.withdraw()

    def on_select():
        nonlocal selected_variables, processed
        selected_indices = listbox.curselection()
        # Retrieve full key from listbox, then get original value from flat dict
        selected_variables = {listbox.get(i).split(':', 1)[0]: log_data_flat[listbox.get(i).split(':', 1)[0]] for i in selected_indices}
        processed = True
        window.destroy()

    # Flatten the log data (simple flattening for now)
    def flatten_dict(d, parent_key='', sep='.'):
        items = {}
        if isinstance(d, dict):
            for k, v in d.items():
                new_key = parent_key + sep + k if parent_key else k
                if isinstance(v, (dict, list)):
                    # items.update(flatten_dict(v, new_key, sep=sep)) # Recursive flatten (optional)
                    # For simplicity, just stringify complex types for now
                    items[new_key] = json.dumps(v)
                else:
                    items[new_key] = str(v) # Convert simple types to string
        elif isinstance(d, list):
             # Handle lists by index or stringify
             items[parent_key] = json.dumps(d) # Stringify whole list for now
        else:
             # Handle non-dict/list data (e.g. raw body)
             if parent_key: # Only if it has a key (e.g. 'body')
                items[parent_key] = str(d)
        return items

    if isinstance(log_data.get('headers'), dict):
         log_data_flat.update(flatten_dict(log_data['headers'], parent_key='header'))

    if 'body' in log_data:
         log_data_flat.update(flatten_dict(log_data['body'], parent_key='body'))

    # --- GUI Setup ---
    window = Toplevel(root_gui) # Attach to hidden root
    window.title("Select Variables from Log")
    window.geometry("700x550") # Slightly larger window
    window.configure(bg='#1e1e1e')

    label = Label(window, text="Select values to use as variables (prefix indicates source):", fg='#00ffcc', bg='#1e1e1e', font=("Consolas", 12))
    label.pack(pady=10)

    frame = Frame(window, bg='#1e1e1e')
    frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

    scrollbar_y = Scrollbar(frame, orient=tk.VERTICAL)
    scrollbar_x = Scrollbar(frame, orient=tk.HORIZONTAL)
    listbox = Listbox(frame, selectmode=MULTIPLE,
                      yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set,
                      bg='#2d2d2d', fg='#cccccc', selectbackground='#00ffcc', selectforeground='#1e1e1e',
                      font=("Consolas", 11), height=20, width=80) # Added width
    scrollbar_y.config(command=listbox.yview)
    scrollbar_x.config(command=listbox.xview)

    scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
    scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X) # Add horizontal scrollbar
    listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # Populate listbox from flattened data
    if log_data_flat:
        # Sort keys for consistent display
        sorted_keys = sorted(log_data_flat.keys())
        for key in sorted_keys:
            value = log_data_flat[key]
            # Truncate long values for display in listbox
            display_value = (str(value)[:100] + '...') if len(str(value)) > 100 else str(value)
            # Remove newlines from display value for listbox
            display_value = display_value.replace('\n', ' ').replace('\r', '')
            listbox.insert(END, f"{key}: {display_value}")
    else:
        listbox.insert(END, "No extractable key-value pairs found in log (Headers/Body).")
        listbox.config(state=tk.DISABLED)

    submit_button = Button(window, text="Use Selected Variables", command=on_select, bg='#00ffcc', fg='#1e1e1e', font=("Consolas", 12, "bold"), relief=tk.FLAT, state=tk.NORMAL if log_data_flat else tk.DISABLED)
    submit_button.pack(pady=15)

    # Center the window
    window.eval('tk::PlaceWindow . center')

    # Make it modal
    window.grab_set()
    root_gui.wait_window(window)
    root_gui.destroy() # Clean up hidden root

    return selected_variables if processed else {}

# FINISH ### GUI UTILITIES ###

# START ### CLI INTERACTION ###
def get_cli_input(prompt, default=None, is_password=False):
    """Gets input from CLI with styling."""
    prompt_text = Text(f"{prompt} ", style="bold cyan")
    if default:
        prompt_text.append(f"({default})", style="dim white") # No space before colon if default exists
    prompt_text.append(": ", style="bold cyan")

    if is_password:
        # getpass used for true password hiding
        user_input = getpass.getpass(prompt=str(prompt_text))
    else:
        user_input = CONSOLE.input(prompt_text)

    return user_input.strip() if user_input else default

def get_multiline_cli_input(prompt):
    """Gets potentially multi-line input from CLI."""
    CONSOLE.print(Panel(f"[bold yellow]{prompt}[/bold yellow]\n[dim]Enter content below. Type 'EOF' or 'END' on a new line when done.[/dim]", border_style="yellow"))
    lines = []
    while True:
        try:
            # Use rich's input for consistency, although it's single-line reads
            line = CONSOLE.input("") # Empty prompt for multi-line input feel
            if line.strip().upper() in ["EOF", "END"]:
                break
            lines.append(line)
        except EOFError: # Handle Ctrl+D
            break
        except KeyboardInterrupt: # Handle Ctrl+C
            CONSOLE.print("\n[yellow]Input cancelled.[/yellow]")
            return None # Indicate cancellation
    return "\n".join(lines)

def display_request_summary(url, method, headers, username, variables, body):
    """Displays a summary of the request parameters in the CLI."""
    summary = Text()
    summary.append("--- REQUEST SUMMARY ---\n", style="bold magenta underline")
    summary.append(f"URL    : {url}\n", style="green")
    summary.append(f"Method : {method}\n", style="yellow")

    if username:
        summary.append(f"User   : {username} ([i]Password Provided[/i])\n", style="bold yellow")

    summary.append("Headers:\n", style="bold cyan")
    if headers:
        # Sort headers for consistent display
        for key in sorted(headers.keys()):
            value = headers[key]
            summary.append(f"  {key}: {value}\n", style="cyan")
    else:
        summary.append("  (None)\n", style="dim cyan")

    if variables:
        summary.append("Variables (from log - applied):\n", style="bold blue")
        # Sort variables for consistent display
        for key in sorted(variables.keys()):
            value = variables[key]
            display_value = (str(value)[:70] + '...') if len(str(value)) > 70 else str(value)
            summary.append(f"  {key}: {display_value}\n", style="blue")

    # Display Body separately using Panel for better formatting
    CONSOLE.print(Panel(summary, title="Review Request Details", border_style="magenta", expand=False))

    CONSOLE.print("Body   :", style="bold orange3")
    if body:
        try:
            # Check if body is a JSON string
            parsed_body = json.loads(body) if isinstance(body, str) else body
            # Pretty print JSON if parsing worked
            body_syntax = Syntax(json.dumps(parsed_body, indent=2), "json", theme="monokai", line_numbers=False, word_wrap=True)
            CONSOLE.print(Panel(body_syntax, title="Request Body (JSON)", border_style="orange3"))
        except (json.JSONDecodeError, TypeError):
             # Print as raw text if not valid JSON
             CONSOLE.print(Panel(str(body), title="Request Body (Raw)", border_style="orange3"))
    else:
        CONSOLE.print("  (None)", style="dim orange3")


def display_response(response):
    """Displays the response details in the CLI with rich formatting."""
    CONSOLE.print(Panel(f"[bold green]RESPONSE RECEIVED[/bold green]", border_style="green", title_align="left"))

    # Status Code
    status_style = "bold green" if 200 <= response.status_code < 300 else "bold yellow" if 300 <= response.status_code < 400 else "bold red"
    CONSOLE.print(Panel(f"Status Code: [{status_style}]{response.status_code}[/{status_style}] ({response.reason})", title="Status", border_style="blue"))

    # Headers
    if response.headers:
        header_table = Table(title="Response Headers", show_header=True, header_style="bold cyan", border_style="cyan", box=None)
        header_table.add_column("Header", style="dim white", no_wrap=True)
        header_table.add_column("Value", style="white")
        # Sort headers for consistent display
        for key in sorted(response.headers.keys()):
            value = response.headers[key]
            header_table.add_row(key, value)
        CONSOLE.print(header_table)
    else:
         CONSOLE.print("[dim]No headers in response.[/dim]")


    # Body
    CONSOLE.print(Panel("[bold yellow]Response Body:[/bold yellow]", border_style="yellow"))
    try:
        # Try parsing as JSON for syntax highlighting
        response_body = response.json()
        # Pretty print JSON with indent=4, each value on new line implicitly
        pretty_body = json.dumps(response_body, indent=4, sort_keys=True)
        syntax = Syntax(pretty_body, "json", theme="monokai", line_numbers=True, word_wrap=True)
        CONSOLE.print(syntax)
    except json.JSONDecodeError:
        # If not JSON, print plain text, check content type for potential XML/HTML
        content_type = response.headers.get("Content-Type", "").lower()
        if "xml" in content_type:
            syntax = Syntax(response.text, "xml", theme="monokai", line_numbers=True, word_wrap=True)
            CONSOLE.print(syntax)
        elif "html" in content_type:
             syntax = Syntax(response.text, "html", theme="monokai", line_numbers=True, word_wrap=True)
             CONSOLE.print(syntax)
        elif response.text:
            CONSOLE.print(response.text)
        else:
            CONSOLE.print("[dim](Empty Response Body)[/dim]")

    # Timing
    CONSOLE.print(f"\n[dim]Request Time: {response.elapsed.total_seconds():.3f}s[/dim]")

# FINISH ### CLI INTERACTION ###

# START ### CORE LOGIC ###

def build_and_send_request(initial_variables=None):
    """Guides the user through building and sending an HTTP request via CLI."""
    current_request_state = {
        "url": "",
        "method": "GET",
        "headers": {},
        "username": None,
        "password": None,
        "variables": initial_variables if initial_variables else {},
        "body": None
    }

    restart_input = True
    while restart_input:
        restart_input = False # Assume we complete this loop unless user chooses to edit

        # 1. Get URL
        current_request_state["url"] = ""
        while not current_request_state["url"]:
            url_input = get_cli_input("Enter Target URL", default=current_request_state.get("url") or None)
            if not (url_input.startswith("http://") or url_input.startswith("https://")):
                 CONSOLE.print("[bold red]Invalid URL format. Must start with http:// or https://[/bold red]")
            else:
                 current_request_state["url"] = url_input

        # 2. Get Method
        current_request_state["method"] = ""
        valid_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
        while current_request_state["method"] not in valid_methods:
            method_input = get_cli_input(f"Enter HTTP Method ({'/'.join(valid_methods)})", default=current_request_state.get("method") or "GET").upper()
            if method_input not in valid_methods:
                CONSOLE.print(f"[bold red]Invalid method. Choose from: {', '.join(valid_methods)}[/bold red]")
            else:
                current_request_state["method"] = method_input

        # 3. Get Headers via GUI
        CONSOLE.print("[yellow]Opening Header Input window...[/yellow]")
        # Add existing headers to GUI? Maybe too complex for now. Start fresh.
        header_input = get_headers_from_gui()
        if not header_input:
             CONSOLE.print("[yellow]No headers provided or window closed.[/yellow]")
             current_request_state["headers"] = {} # Ensure it's an empty dict
        else:
             CONSOLE.print(f"[green]Processed {len(header_input)} headers.[/green]")
             current_request_state["headers"] = header_input

        # 3b. Ask for Credentials (Optional)
        requires_creds = get_cli_input("Does this request require credentials (e.g., username/password)? (y/N)", default="N").lower()
        if requires_creds == 'y':
            current_request_state["username"] = get_cli_input("Enter Username/Email")
            password_prompt_str = str(Text("Enter Password: ", style="bold cyan"))
            current_request_state["password"] = getpass.getpass(prompt=password_prompt_str)
            if current_request_state["username"] and current_request_state["password"]:
                 CONSOLE.print(f"[green]Credentials captured for user:[/green] [bold yellow]{current_request_state['username']}[/bold yellow]")
            else:
                 CONSOLE.print("[yellow]Warning: Credentials requested but input incomplete.[/yellow]")
                 current_request_state["username"] = None
                 current_request_state["password"] = None
        else:
             current_request_state["username"] = None
             current_request_state["password"] = None


        # 4. Ask to use logged variables (if not already provided)
        if not current_request_state["variables"]:
            use_logs = get_cli_input("Use variables from a logged response? (y/N)", default="N").lower()
            if use_logs == 'y':
                current_request_state["variables"] = choose_and_extract_variables()

        # Apply selected variables to headers immediately (simple strategy)
        final_headers = current_request_state["headers"].copy()
        applied_vars = {}
        if current_request_state["variables"]:
            CONSOLE.print("[blue]Applying selected variables...[/blue]")
            for key, value in current_request_state["variables"].items():
                 # Simple logic: if starts with 'header.', add/overwrite headers
                 if key.startswith('header.'):
                     header_key = key.split('.', 1)[1]
                     final_headers[header_key] = value
                     applied_vars[key] = value # Track applied vars for summary
                     CONSOLE.print(f"  [dim]Set header '{header_key}' from variable '{key}'[/dim]")
                 # Placeholder: Add logic here if variables should modify URL or body

        current_request_state["headers"] = final_headers # Update state with applied vars


        # 5. Initial Review (without body yet)
        display_request_summary(
            current_request_state["url"],
            current_request_state["method"],
            current_request_state["headers"],
            current_request_state["username"],
            applied_vars, # Show only applied variables in this summary
            None)

        # 6. Option to Edit or Continue
        action = get_cli_input("Press [1] to Edit (Restart Input), [Enter] to Continue", default="").lower()
        if action == '1':
            CONSOLE.print("[yellow]Restarting request input...[/yellow]")
            restart_input = True
            continue # Go back to the start of the while loop


        # 7. Handle Body
        current_request_state["body"] = None # Reset body each time we pass this point
        auto_body_created = False
        if current_request_state["username"] and current_request_state["password"] and current_request_state["method"] in ["POST", "PUT", "PATCH"]:
            auto_create = get_cli_input("Auto-format JSON body with username/password? (Y/n)", default="Y").lower()
            if auto_create == 'y':
                body_data = {"username": current_request_state["username"], "password": current_request_state["password"]}
                try:
                    current_request_state["body"] = json.dumps(body_data)
                    CONSOLE.print("[green]Auto-created JSON body with credentials.[/green]")
                    # Ensure Content-Type is set for JSON
                    if 'Content-Type' not in current_request_state["headers"] or not str(current_request_state["headers"].get('Content-Type', '')).lower().strip().endswith('json'):
                        current_request_state["headers"]['Content-Type'] = 'application/json'
                        CONSOLE.print("[dim]Set Content-Type to application/json[/dim]")
                    auto_body_created = True
                except Exception as e:
                     CONSOLE.print(f"[bold red]Error creating JSON body:[/bold red] {e}")
                     current_request_state["body"] = None

        if not auto_body_created and current_request_state["method"] in ["POST", "PUT", "PATCH"]:
            add_body = get_cli_input("Add request body manually? (y/N)", default="N").lower()
            if add_body == 'y':
                body_type = get_cli_input("Body type (e.g., json, xml, raw, urlencoded)", default="json").lower()
                # Set Content-Type header automatically if not already set
                if body_type == 'json' and ('Content-Type' not in current_request_state["headers"] or not str(current_request_state["headers"].get('Content-Type', '')).lower().strip().endswith('json')):
                    current_request_state["headers"]['Content-Type'] = 'application/json'
                    CONSOLE.print("[dim]Automatically set Content-Type to application/json[/dim]")
                elif body_type == 'urlencoded' and ('Content-Type' not in current_request_state["headers"] or not str(current_request_state["headers"].get('Content-Type', '')).lower().strip().startswith('application/x-www-form-urlencoded')):
                     current_request_state["headers"]['Content-Type'] = 'application/x-www-form-urlencoded'
                     CONSOLE.print("[dim]Automatically set Content-Type to application/x-www-form-urlencoded[/dim]")

                current_request_state["body"] = get_multiline_cli_input(f"Enter {body_type.upper()} Body Content")
                if current_request_state["body"] is None: # Handle Ctrl+C during input
                    CONSOLE.print("[yellow]Body input cancelled. Restarting request input...[/yellow]")
                    restart_input = True
                    continue


        # 8. Final Review
        display_request_summary(
             current_request_state["url"],
             current_request_state["method"],
             current_request_state["headers"], # Show final headers
             current_request_state["username"],
             applied_vars, # Show applied vars again for clarity
             current_request_state["body"])


        # 9. Option to Edit or Send
        action = get_cli_input("Press [1] to Edit (Restart Input), [Enter] to Send Request", default="").lower()
        if action == '1':
            CONSOLE.print("[yellow]Restarting request input...[/yellow]")
            restart_input = True
            continue # Go back to start of while

        # If we reach here, user confirmed sending

    # --- End of Input Loop ---

    # 10. Send Request
    CONSOLE.print(f"[bold yellow]Sending {current_request_state['method']} request to {current_request_state['url']}...[/bold yellow]")
    req_filename, res_filename = generate_log_filename()

    # Prepare data for logging, ensuring password isn't directly included if possible
    # log_request function is responsible for final masking
    request_log_data = {
        'timestamp': datetime.datetime.now().isoformat(),
        'url': current_request_state['url'],
        'method': current_request_state['method'],
        'username': current_request_state['username'], # Log username
        'headers': current_request_state['headers'],
        'variables_used': current_request_state['variables'], # Log all potential vars
        'variables_applied': applied_vars, # Log vars actually applied
        'body': current_request_state['body']
    }
    log_request(request_log_data, req_filename)

    try:
        kwargs = {'headers': current_request_state['headers'], 'timeout': 30}
        body_to_send = current_request_state['body']

        if body_to_send:
            content_type = current_request_state['headers'].get('Content-Type', '').lower()
            if 'application/json' in content_type and isinstance(body_to_send, str):
                try:
                    # requests prefers dict for json kwarg
                    kwargs['json'] = json.loads(body_to_send)
                except json.JSONDecodeError:
                     CONSOLE.print("[bold red]Warning:[/bold red] Body Content-Type is JSON but failed to parse. Sending as raw data.")
                     kwargs['data'] = body_to_send
            else:
                 # Send as form data or raw bytes for other types or if body is not string
                 kwargs['data'] = body_to_send

        # THE ACTUAL REQUEST
        response = requests.request(current_request_state['method'], current_request_state['url'], **kwargs)

        # Check for HTTP errors (4xx, 5xx) AFTER getting the response
        response.raise_for_status()

        # Success path
        CONSOLE.print("[bold green]Request Successful![/bold green]")
        display_response(response)
        log_response(response, res_filename)

    except requests.exceptions.HTTPError as e:
        # Handle HTTP errors specifically (4xx, 5xx)
        CONSOLE.print(Panel(f"[bold red]HTTP Error:[/bold red] {e.response.status_code} {e.response.reason}", border_style="red", title="Request Failed"))
        if e.response is not None:
            # Display the error response from the server
            display_response(e.response)
            log_response(e.response, res_filename) # Log the error response too
        else:
            # Should not happen with HTTPError but good practice
            CONSOLE.print("[red]No response object available for HTTP error.[/red]")

    except requests.exceptions.RequestException as e:
        # Handle other request errors (Connection, Timeout, DNS issues, etc.)
        CONSOLE.print(Panel(f"[bold red]REQUEST FAILED:[/bold red]\n{type(e).__name__}: {e}", border_style="red", title="Network/Request Error"))
        # Log a basic error since there's no HTTP response
        error_data = {'error': type(e).__name__, 'message': str(e), 'details': 'No HTTP response object available.'}
        error_filepath = os.path.join(RESPONSES_DIR, res_filename)
        try:
            with open(error_filepath, 'w') as f:
                json.dump(error_data, f, indent=4)
            CONSOLE.print(f"[yellow]Error details logged to:[/yellow] [cyan]{error_filepath}[/cyan]")
        except IOError as log_err:
            CONSOLE.print(f"[bold red]Failed to log error details: {log_err}[/bold red]")

    except Exception as e:
         # Catch any other unexpected errors during request/processing
         CONSOLE.print(Panel(f"[bold red]UNEXPECTED SCRIPT ERROR:[/bold red]", border_style="red", title="Critical Error"))
         # Print detailed traceback for debugging
         CONSOLE.print_exception(show_locals=False) # show_locals=True can be verbose


def choose_and_extract_variables():
    """Lists logged responses and allows user to select one and extract variables via GUI."""
    CONSOLE.print("\n[bold cyan]--- Select Logged Response for Variables ---[/bold cyan]")
    try:
        log_files = sorted(
            [f for f in os.listdir(RESPONSES_DIR) if f.startswith('res-') and f.endswith('.json')],
            key=lambda f: os.path.getmtime(os.path.join(RESPONSES_DIR, f)),
            reverse=True
        )
    except OSError as e:
        CONSOLE.print(f"[bold red]Error accessing responses directory:[/bold red] {e}")
        return {}

    if not log_files:
        CONSOLE.print(f"[yellow]No response logs found in '[cyan]{RESPONSES_DIR}[/cyan]'[/yellow]")
        return {}

    CONSOLE.print("[dim]Available response logs (newest first):[/dim]")
    table = Table(title="Logged Responses", show_header=True, header_style="bold magenta", box=None)
    table.add_column("#", style="dim", width=4)
    table.add_column("File Name", style="cyan", no_wrap=True)
    table.add_column("Timestamp", style="green", no_wrap=True)
    table.add_column("URL (from log)", style="yellow") # Allow wrap
    table.add_column("Status", style="blue", no_wrap=True)

    displayed_logs = log_files[:20] # Show latest 20 logs
    log_details = [] # Store details for selection

    for i, filename in enumerate(displayed_logs):
        filepath = os.path.join(RESPONSES_DIR, filename)
        try:
            with open(filepath, 'r') as f:
                log_data = json.load(f)
            # Use file modification time as the timestamp
            timestamp = datetime.datetime.fromtimestamp(os.path.getmtime(filepath)).strftime('%Y-%m-%d %H:%M:%S')
            # Handle potential missing keys gracefully
            url = log_data.get('url', '[URL Missing]')
            status = str(log_data.get('status_code', '[Status Missing]'))
            log_details.append({'file': filename, 'path': filepath, 'data': log_data})
            # Truncate long URLs for display in table if needed
            display_url = (url[:60] + '...') if len(url) > 60 else url
            table.add_row(str(i + 1), filename, timestamp, display_url, status)
        except (IOError, json.JSONDecodeError, KeyError) as e:
            # Log read errors more informatively
            timestamp = '[Timestamp N/A]'
            if os.path.exists(filepath):
                try:
                    timestamp = datetime.datetime.fromtimestamp(os.path.getmtime(filepath)).strftime('%Y-%m-%d %H:%M:%S')
                except Exception: pass # Ignore errors getting timestamp if file is bad
            table.add_row(str(i + 1), filename, timestamp, f"[red]Error: {type(e).__name__}[/red]", "")
            log_details.append(None) # Placeholder for invalid log

    CONSOLE.print(table)

    selected_log_index = -1
    while selected_log_index < 0 or selected_log_index >= len(displayed_logs):
        try:
            choice = get_cli_input(f"Enter number of log to use (1-{len(displayed_logs)}), or 0 to cancel", default="0")
            selected_log_index = int(choice) - 1
            if selected_log_index == -1: # User chose 0 to cancel
                 CONSOLE.print("[yellow]Variable selection cancelled.[/yellow]")
                 return {}
            # Validate index range AND check if the log detail entry is valid
            if not (0 <= selected_log_index < len(displayed_logs)):
                CONSOLE.print("[bold red]Invalid selection number.[/bold red]")
                selected_log_index = -1 # Force re-selection
            elif log_details[selected_log_index] is None:
                 CONSOLE.print("[bold red]Cannot select a log with read errors.[/bold red]")
                 selected_log_index = -1 # Force re-selection

        except ValueError:
            CONSOLE.print("[bold red]Invalid input. Please enter a number.[/bold red]")
            selected_log_index = -1 # Reset index

    # Valid log selected
    selected_log_info = log_details[selected_log_index]
    CONSOLE.print(f"[green]Selected log:[/green] [cyan]{selected_log_info['file']}[/cyan]")
    CONSOLE.print("[yellow]Opening Variable Selector window...[/yellow]")

    # Pass the loaded log data to the GUI selector
    selected_vars = select_variables_from_log_gui(selected_log_info['data'])

    if selected_vars:
        CONSOLE.print(f"[green]Selected {len(selected_vars)} variables:[/green]")
        # Sort for consistent display
        for k in sorted(selected_vars.keys()):
            v = selected_vars[k]
            display_v = (str(v)[:70] + '...') if len(str(v)) > 70 else str(v)
            CONSOLE.print(f"  [blue]{k}[/blue]: {display_v}")
    else:
        CONSOLE.print("[yellow]No variables selected or window closed.[/yellow]")

    return selected_vars

# FINISH ### CORE LOGIC ###

# START ### MAIN FUNCTION ###
def main():
    """Main function to run the CLI application."""
    # No need for hidden Tk root here, GUI utils create their own temporary roots

    CONSOLE.print(Panel("[bold cyan]HTTP CLI Toolkit v1.0[/bold cyan]\n[dim]Your Cyberpunk Swiss Army Knife for HTTP Requests[/dim]", border_style="blue", title="Welcome, Hustler"))

    while True:
        CONSOLE.print("\n" + "=" * CONSOLE.width) # Separator
        CONSOLE.print("[bold magenta]What's the move, Big Dawg?[/bold magenta]")
        CONSOLE.print(" [1] Make New Request")
        CONSOLE.print(" [2] Select Variables from Log (then build request)")
        CONSOLE.print(" [0] Exit")

        choice = get_cli_input("Enter choice", default="1")

        if choice == '1':
            # Build request without pre-selected variables
            build_and_send_request()
        elif choice == '2':
            # Call the function that handles log selection first
            initial_variables = choose_and_extract_variables()
            if initial_variables:
                 CONSOLE.print("\n[magenta]--- Now, let's build the request using these variables ---[/magenta]")
                 # Pass the selected variables to the main builder function
                 build_and_send_request(initial_variables=initial_variables)
            else:
                 CONSOLE.print("[yellow]No variables selected from log. Starting fresh request builder.[/yellow]")
                 build_and_send_request() # Start without initial vars
        elif choice == '0':
            CONSOLE.print("[bold yellow]Aight, keepin' it 100. Exiting.[/bold yellow]")
            break
        else:
            CONSOLE.print("[bold red]Invalid choice, playa. Run that back.[/bold red]")

        # Optional pause or clear screen can go here
        # time.sleep(1)

# FINISH ### MAIN FUNCTION ###

# START ### SCRIPT RUNNER ###
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        CONSOLE.print("\n[bold yellow]Ctrl+C detected. Hustle interrupted. Exiting.[/bold yellow]")
    except Exception as e:
         # Catch-all for unexpected errors in main execution flow
         CONSOLE.print(Panel("[bold red]FATAL SCRIPT ERROR[/bold red]", border_style="red", title="Critical Failure"))
         CONSOLE.print_exception(show_locals=False)
# FINISH ### SCRIPT RUNNER ###

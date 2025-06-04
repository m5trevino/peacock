#!/usr/bin/env python3
import json
import os
import sys
import re # Need this G for the filename cleanup

# Try importing tkinter for the GUI option, but don't fail if it's not there
try:
    import tkinter as tk
    from tkinter import filedialog
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

# START ### UTILITY FUNCTIONS ###
def sanitize_filename(filename):
    """
    Cleans a filename: lowercase, replaces spaces with underscores,
    removes characters other than letters, numbers, underscores, hyphens.
    Like laundering filenames, keepin' it clean.
    """
    # 1. Get rid of the extension for sanitization, we add it back later
    name_part, ext_part = os.path.splitext(filename)

    # 2. Lowercase that shit
    clean_name = name_part.lower()

    # 3. Swap spaces for underscores
    clean_name = clean_name.replace(' ', '_')

    # 4. Boot out anything that ain't alphanumeric, underscore, or hyphen
    clean_name = re.sub(r'[^\w\-]+', '', clean_name)

    # 5. Make sure it ain't empty after stripping
    if not clean_name:
        clean_name = 'unnamed_file' # Default if everything got stripped

    # 6. Tack on the standard output extension
    return f"{clean_name}-formatted.txt"
# FINISH ### UTILITY FUNCTIONS ###


# START ### FORMATTING FUNCTION ###
def format_conversation(json_string):
    """
    Parses a JSON string containing conversation chunks and formats it
    into a specific text layout. Same solid logic as before.
    Will throw errors if input ain't valid JSON.
    """
    try:
        data = json.loads(json_string)
        # Navigate safely to the chunks list, defaulting to empty list if keys are missing
        chunks = data.get('chunkedPrompt', {}).get('chunks', [])
    except json.JSONDecodeError as e:
        # This is where non-JSON files will likely fail.
        # Return the error message so the calling function knows it failed.
        # Keep the error message concise for clarity when processing many files.
        return f"Error: Invalid JSON format ({e})"
    except AttributeError:
         # This means it was JSON, but not the expected structure.
         return "Error: JSON structure incorrect (missing 'chunkedPrompt' or 'chunks')."
    except Exception as e:
        # Catch any other unexpected parsing issues
        return f"Error: Unexpected issue parsing JSON ({e})"


    output_parts = []

    for chunk in chunks:
        role = chunk.get('role')
        text = chunk.get('text', '') # Default to empty string if text is missing
        is_thought = chunk.get('isThought', False)

        # Skip chunks that are missing essential role or text
        if not role or text is None:
            continue

        formatted_block = ""
        if role == 'user':
            formatted_block = f"""
██╗   ██╗███████╗███████╗██████╗ 
██║   ██║██╔════╝██╔════╝██╔══██╗
██║   ██║███████╗█████╗  ██████╔╝
██║   ██║╚════██║██╔══╝  ██╔══██╗
╚██████╔╝███████║███████╗██║  ██║
 ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝
{text}
above is from - user
██╗   ██╗███████╗███████╗██████╗ 
██║   ██║██╔════╝██╔════╝██╔══██╗
██║   ██║███████╗█████╗  ██████╔╝
██║   ██║╚════██║██╔══╝  ██╔══██╗
╚██████╔╝███████║███████╗██║  ██║
 ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝
                                 """
        elif role == 'model':
            if is_thought:
                formatted_block = f"""
ooooooooooooo ooooo   ooooo ooooo ooooo      ooo oooo    oooo ooooo ooooo      ooo   .oooooo.    
8'   888   `8 `888'   `888' `888' `888b.     `8' `888   .8P'  `888' `888b.     `8'  d8P'  `Y8b   
     888       888     888   888   8 `88b.    8   888  d8'     888   8 `88b.    8  888           
     888       888ooooo888   888   8   `88b.  8   88888[       888   8   `88b.  8  888           
     888       888     888   888   8     `88b.8   888`88b.     888   8     `88b.8  888     ooooo 
     888       888     888   888   8       `888   888  `88b.   888   8       `888  `88.    .88'  
    o888o     o888o   o888o o888o o8o        `8  o888o  o888o o888o o8o        `8   `Y8bood8P'   
                                                                                                 
                                                                                               
{text}
above is the thoughts of the model
ooooooooooooo ooooo   ooooo ooooo ooooo      ooo oooo    oooo ooooo ooooo      ooo   .oooooo.    
8'   888   `8 `888'   `888' `888' `888b.     `8' `888   .8P'  `888' `888b.     `8'  d8P'  `Y8b   
     888       888     888   888   8 `88b.    8   888  d8'     888   8 `88b.    8  888           
     888       888ooooo888   888   8   `88b.  8   88888[       888   8   `88b.  8  888           
     888       888     888   888   8     `88b.8   888`88b.     888   8     `88b.8  888     ooooo 
     888       888     888   888   8       `888   888  `88b.   888   8       `888  `88.    .88'  
    o888o     o888o   o888o o888o o8o        `8  o888o  o888o o888o o8o        `8   `Y8bood8P'   
                                                                                                 
                                                                                                 
                                                                                                 

"""
            else:
                formatted_block = f""" _______    ______   ________ 
/       \  /      \ /        |
$$$$$$$  |/$$$$$$  |$$$$$$$$/ 
$$ |__$$ |$$ |  $$ |   $$ |   
$$    $$< $$ |  $$ |   $$ |   
$$$$$$$  |$$ |  $$ |   $$ |   
$$ |__$$ |$$ \__$$ |   $$ |   
$$    $$/ $$    $$/    $$ |   
$$$$$$$/   $$$$$$/     $$/    
                              
                              
                              


{text}
 ____ ____ ____ 
 _______    ______   ________ 
/       \  /      \ /        |
$$$$$$$  |/$$$$$$  |$$$$$$$$/ 
$$ |__$$ |$$ |  $$ |   $$ |   
$$    $$< $$ |  $$ |   $$ |   
$$$$$$$  |$$ |  $$ |   $$ |   
$$ |__$$ |$$ \__$$ |   $$ |   
$$    $$/ $$    $$/    $$ |   
$$$$$$$/   $$$$$$/     $$/    
                              
                              
                              



"""
        else:
            continue # Skip appending if role is unexpected

        if formatted_block:
             output_parts.append(formatted_block)

    if not output_parts and chunks:
         # This is less of an error, more of a notice. Still return it.
         return "Warning: JSON valid, but no processable chunks found."
    elif not output_parts and not chunks:
         return "Warning: Input JSON contained no processable chunks."

    return "\n\n".join(output_parts)
# FINISH ### FORMATTING FUNCTION ###


# START ### INPUT HANDLING ###
def get_input_path():
    """
    Asks user for a file or directory path, via CLI or GUI.
    Returns a tuple: (path_type, selected_path) where path_type is 'file', 'directory', or None.
    """
    print("Choose the operation type:")
    print("  1. Process a single file (must be valid JSON)")
    print("  2. Process all files in a directory (attempts JSON format)")

    while True:
        choice = input("Enter choice (1 or 2): ").strip()
        if choice in ['1', '2']:
            break
        else:
            print("Invalid choice, my boy. Enter 1 or 2.")

    use_gui = False
    if GUI_AVAILABLE:
        gui_choice = input("Use GUI file/folder picker? (y/n, default n): ").strip().lower()
        if gui_choice == 'y':
            use_gui = True

    if use_gui:
        root = tk.Tk()
        root.withdraw() # Keepin' it low profile
        selected_path = None
        try:
            if choice == '1':
                print("Opening file picker...")
                selected_path = filedialog.askopenfilename(
                    title="Select SINGLE file (must be JSON)",
                    # Keep JSON filter here for single file selection for user clarity
                    filetypes=(("JSON files", "*.json"), ("All files", "*.*"))
                )
                if selected_path:
                    return 'file', selected_path
                else:
                    print("File selection cancelled.")
                    return None, None
            elif choice == '2':
                print("Opening directory picker...")
                selected_path = filedialog.askdirectory(
                    title="Select Directory Containing Files to Process"
                )
                if selected_path:
                    return 'directory', selected_path
                else:
                    print("Directory selection cancelled.")
                    return None, None
        finally:
            root.destroy() # Clean up the GUI window

    else: # Use command line input
        prompt = "Enter path to the JSON file: " if choice == '1' else "Enter path to the directory: "
        while True:
            path_input = input(prompt).strip()
            if not path_input:
                print("Path cannot be empty, fucker. Try again.")
                continue

            # Check if path exists
            if not os.path.exists(path_input):
                print(f"Error: Path not found: '{path_input}'. Check yourself.")
                continue

            # Check if it matches the choice type
            if choice == '1':
                if os.path.isfile(path_input):
                    # No strict .json check here anymore, rely on processing failure
                    return 'file', path_input
                else:
                    print(f"Error: '{path_input}' is not a file. You chose single file mode.")
            elif choice == '2':
                if os.path.isdir(path_input):
                    return 'directory', path_input
                else:
                    print(f"Error: '{path_input}' is not a directory. You chose directory mode.")
# FINISH ### INPUT HANDLING ###


# START ### FILE PROCESSING LOGIC ###
def process_single_file(filepath, output_dir):
    """Handles reading, formatting, and writing for one file. Returns True on success, False on failure."""
    print(f"--- Attempting file: {filepath} ---")
    input_content = None
    formatted_output = None
    success = False # Track if this specific file worked out

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            input_content = f.read()
    except Exception as e:
        print(f"  Error reading file '{os.path.basename(filepath)}': {e}. Skipping.", file=sys.stderr)
        return success # Return False on read error

    if input_content:
        # format_conversation now returns error/warning strings directly
        formatted_output = format_conversation(input_content)

        # Check if formatting returned an error message string
        if formatted_output.startswith("Error:"):
            print(f"  Processing failed for '{os.path.basename(filepath)}': {formatted_output}", file=sys.stderr)
        # Check if formatting returned a warning message string
        elif formatted_output.startswith("Warning:"):
             print(f"  Warning for file '{os.path.basename(filepath)}': {formatted_output}")
             # Decide if warnings should still create a file (e.g., empty file if no chunks)
             # For now, let's treat warnings that produce no output as failures for file creation
             if "no processable chunks" in formatted_output and not "\n\n" in formatted_output: # Check if only warning exists
                 print("    (No output file generated due to warning)")
             else: # Warning but some output generated (unlikely with current warnings, but future-proof)
                 success = True # Treat as success if *some* output exists despite warning

        # If no error/warning prefix, assume success
        else:
            success = True

        # Only try to write if formatting was considered successful
        if success:
            try:
                input_basename = os.path.basename(filepath)
                output_filename = sanitize_filename(input_basename)
                output_filepath = os.path.join(output_dir, output_filename)

                # Prevent overwriting the input file
                if os.path.abspath(output_filepath) == os.path.abspath(filepath):
                     name, _ = os.path.splitext(output_filename)
                     output_filename = f"{name}_output.txt"
                     output_filepath = os.path.join(output_dir, output_filename)
                     print(f"  Warning: Output filename clashed with input. Using '{output_filename}' instead.", file=sys.stderr)

                with open(output_filepath, 'w', encoding='utf-8') as f:
                    f.write(formatted_output)
                print(f"  Formatted output saved to: {output_filepath}")

            except Exception as e:
                print(f"  Error writing output for '{os.path.basename(filepath)}' to '{output_filepath}': {e}", file=sys.stderr)
                success = False # Writing failed, so overall not successful

    else: # File was empty
        print(f"  Skipping empty file: {os.path.basename(filepath)}")

    return success # Return True only if read, format, and write all succeeded
# FINISH ### FILE PROCESSING LOGIC ###


# START ### SCRIPT RUNNER ###
def main():
    path_type, selected_path = get_input_path()

    if not selected_path:
        print("No path provided. Exiting.", file=sys.stderr)
        sys.exit(1)

    if path_type == 'file':
        # For single file, be stricter. Error out if it fails.
        output_directory = os.path.dirname(selected_path)
        if not process_single_file(selected_path, output_directory):
             print("\nProcessing failed for the specified file.", file=sys.stderr)
             # sys.exit(1) # Optional: exit if the single file fails

    elif path_type == 'directory':
        print(f"\nScanning directory for all files: {selected_path}")
        files_attempted_count = 0
        files_succeeded_count = 0
        for item in os.listdir(selected_path):
            item_path = os.path.join(selected_path, item)
            # Process *any* file, rely on process_single_file to handle errors
            if os.path.isfile(item_path):
                files_attempted_count += 1
                if process_single_file(item_path, selected_path): # Output in the same directory
                     files_succeeded_count +=1
            else:
                # Optional: print skipped subdirs
                 # print(f"Skipping non-file item (e.g., sub-directory): {item}")
                pass

        print(f"\n--- Directory Scan Summary ---")
        if files_attempted_count == 0:
             print("No files found to attempt processing in the specified directory.")
        else:
             print(f"Attempted processing: {files_attempted_count} files.")
             print(f"Successfully processed and saved: {files_succeeded_count} files.")
             failed_count = files_attempted_count - files_succeeded_count
             if failed_count > 0:
                 print(f"Failed or skipped (due to errors/format): {failed_count} files.")
        print("-----------------------------")


if __name__ == "__main__":
    main()
# FINISH ### SCRIPT RUNNER ###

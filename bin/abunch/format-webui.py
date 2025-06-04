# START ### IMPORTS ###
import json
import os
import re
import html
import argparse
import tkinter as tk
from tkinter import filedialog, messagebox
# FINISH ### IMPORTS ###

# START ### CONFIG ###
# Define minimum length and minimum letter count for a message
# after cleaning to not be considered garbled. Adjust if needed.
# Set these thresholds based on what you consider "garbage" vs real (even short) text.
MIN_CLEANED_MSG_LEN = 15 # Reduced slightly, some real replies might be short
MIN_CLEANED_MSG_LETTERS = 4 # Require a few actual letters
# FINISH ### CONFIG ###

# START ### CLEANING_FUNCTIONS ###
def clean_message(text):
    """
    Strips HTML entities, specific tags, code blocks, and cleans up whitespace
    to make the message human-readable.
    """
    if not isinstance(text, str):
        return "" # Handle non-string input gracefully

    # 1. Unescape standard HTML entities (" -> ", > -> >, etc.)
    # This also handles ' -> '
    cleaned_text = html.unescape(text)

    # 2. Remove <think> and </think> tags (case-insensitive)
    cleaned_text = re.sub(r'<think>', '', cleaned_text, flags=re.IGNORECASE)
    cleaned_text = re.sub(r'</think>', '', cleaned_text, flags=re.IGNORECASE)

    # 3. Remove markdown code blocks (```...```) including content
    # Using DOTALL flag to match across lines
    cleaned_text = re.sub(r'```.*?```', '', cleaned_text, flags=re.DOTALL)

    # 4. Remove HTML code blocks (<pre><code>...</code></pre>) including content
    # Using DOTALL flag to match across lines, non-greedy match for content
    cleaned_text = re.sub(r'<pre><code.*?>(.*?)</code></pre>', '', cleaned_text, flags=re.DOTALL | re.IGNORECASE)

    # 5. Clean up multiple newlines and leading/trailing whitespace
    # Replace multiple newlines with at most two (to keep paragraphs separate)
    cleaned_text = re.sub(r'\n\s*\n+', '\n\n', cleaned_text)
    # Strip whitespace from the start and end of the whole block
    cleaned_text = cleaned_text.strip()

    return cleaned_text

def is_potentially_garbled(cleaned_text):
    """
    Checks if a message is potentially garbled based on length and letter count
    after initial cleaning. This is a heuristic.
    """
    if not isinstance(cleaned_text, str):
        return True # Treat non-strings as garbled

    stripped_text = cleaned_text.strip()

    # If the text is very short, check if it contains enough actual letters
    if len(stripped_text) < MIN_CLEANED_MSG_LEN:
        letter_count = len(re.findall(r'[a-zA-Z]', stripped_text))
        if letter_count < MIN_CLEANED_MSG_LETTERS:
             # Examples of things this might catch: "", " ", "```", "<think>", "!@#$%"
            return True

    # Add other heuristics here if needed based on observed garbage patterns
    # e.g., check for extremely high ratio of symbols/numbers to letters, etc.

    return False

def process_conversation_data(data):
    """
    Processes the raw JSON conversation data (expected to be a dictionary),
    extracts the message list (from "visible" key), cleans messages, and formats
    them into a human-readable transcript string. Skips potentially garbled pairs.
    """
    transcript_parts = []
    skipped_count = 0

    # EXPECTING the input data to be a dictionary like {"internal": [...], "visible": [...]}
    if not isinstance(data, dict):
        print("[!] Input JSON data structure unexpected. Expected a dictionary.")
        return "Error processing data: Unexpected JSON format.", 0

    # Get the list of message pairs, trying "visible" first, then "internal", else empty list
    # Assuming "visible" holds the cleaned conversation we want.
    message_pairs = data.get("visible")
    if message_pairs is None:
        print("[!] 'visible' key not found in JSON. Trying 'internal' key.")
        message_pairs = data.get("internal")

    if not isinstance(message_pairs, list):
        print("[!] Neither 'visible' nor 'internal' key contained a list. Cannot process messages.")
        return "Error processing data: No message list found in JSON.", 0

    print(f"[*] Found {len(message_pairs)} message pairs to process.")


    for i, pair in enumerate(message_pairs):
        if not isinstance(pair, list) or len(pair) != 2:
            print(f"[!] Skipping pair {i+1}: Unexpected pair format.")
            skipped_count += 1
            continue

        user_msg_raw, ai_msg_raw = pair

        # Clean both messages
        user_msg_cleaned = clean_message(user_msg_raw)
        ai_msg_cleaned = clean_message(ai_msg_raw)

        # Check if the pair is potentially garbled (primarily checking the AI's response, as that's where the garbage was observed)
        # We can also check the user message if needed, but often user messages are just short questions.
        if is_potentially_garbled(ai_msg_cleaned):
            print(f"[!] Skipping pair {i+1} due to potential garbled AI content.")
            skipped_count += 1
            continue # Skip this pair

        # If the user message *also* looks garbled after cleaning, maybe skip it too?
        # Let's keep the pair if the AI response seems valid, but maybe refine this later if needed.
        # For now, we just skip if AI response is garbled.

        # Add the cleaned pair to the transcript parts
        # Only add if there's actual content after cleaning
        if user_msg_cleaned or ai_msg_cleaned:
             transcript_parts.append(f"User: {user_msg_cleaned}")
             transcript_parts.append(f"\n\nAI: {ai_msg_cleaned}")
             transcript_parts.append("\n\n---\n\n") # Separator between pairs
        else:
             # If both cleaned messages are empty, skip the pair entirely
             print(f"[!] Skipping pair {i+1}: Both messages were empty after cleaning.")
             skipped_count += 1


    # Join all parts to form the final transcript string
    # Remove the last separator if the list isn't empty
    transcript = "".join(transcript_parts)
    if transcript.endswith("\n\n---\n\n"):
        transcript = transcript[:-len("\n\n---\n\n")]

    return transcript, skipped_count
# FINISH ### CLEANING_FUNCTIONS ###

# START ### FILE_HANDLING ###
def select_file_gui():
    """
    Opens a GUI file dialog to select a JSON file.
    Returns the selected file path or None if canceled.
    """
    # We need a root window for the file dialog, but we hide the main one
    root = tk.Tk()
    root.withdraw() # Hide the main window

    # Make sure the dialog appears on top
    root.attributes('-topmost', True)

    file_path = filedialog.askopenfilename(
        title="Select the JSON conversation file",
        filetypes=(("JSON files", "*.json"), ("All files", "*.*"))
    )

    root.destroy() # Clean up the Tkinter root window
    return file_path if file_path else None

def get_input_file_path():
    """
    Gets the input file path either from command line arguments or a GUI dialog.
    """
    # Check command line args first
    parser = argparse.ArgumentParser(description="Clean up JSON conversation data into a human-readable transcript.")
    parser.add_argument("json_file", nargs='?', help="Path to the input JSON file.")
    args = parser.parse_args()

    if args.json_file:
        print(f"[*] Using file path from command line: {args.json_file}")
        return args.json_file
    else:
        print("[*] No file path provided via command line. Opening file browser GUI...")
        # If no arg, fall back to GUI
        return select_file_gui()

def load_json_data(file_path):
    """
    Loads JSON data from the specified file path.
    Handles file not found and JSON decoding errors.
    """
    if not file_path: # Handle case where GUI was canceled
        print("[!] No file path provided.")
        return None

    if not os.path.exists(file_path):
        print(f"[!] Error: File not found at '{file_path}'.")
        return None
    # Optional warning if extension isn't json, but we'll try loading it anyway
    if not file_path.lower().endswith('.json'):
         print(f"[!] Warning: Selected file '{file_path}' does not have a .json extension. Attempting to load anyway.")

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            print(f"[*] Successfully loaded JSON data from '{file_path}'.")
            return data
    except json.JSONDecodeError as e:
        print(f"[!] Error decoding JSON from '{file_path}': {e}")
        messagebox.showerror("JSON Error", f"Error decoding JSON from file:\n{e}\nCheck file format.")
        return None
    except Exception as e:
        print(f"[!] An unexpected error occurred while reading '{file_path}': {e}")
        messagebox.showerror("File Read Error", f"An unexpected error occurred while reading file:\n{e}")
        return None

def save_transcript(transcript_string, original_file_path):
    """
    Saves the cleaned transcript string to a new file based on the original file name.
    """
    if not original_file_path:
         print("[!] Cannot save transcript: Original file path is missing.")
         return None

    directory = os.path.dirname(original_file_path)
    filename_without_ext = os.path.splitext(os.path.basename(original_file_path))[0]
    output_filename = f"{filename_without_ext}_cleaned.txt"
    output_file_path = os.path.join(directory, output_filename)

    try:
        with open(output_file_path, 'w', encoding='utf-8') as f:
            f.write(transcript_string)
        print(f"[*] Successfully saved cleaned transcript to '{output_file_path}'.")
        return output_file_path
    except Exception as e:
        print(f"[!] Error saving transcript to '{output_file_path}': {e}")
        messagebox.showerror("Save Error", f"Error saving cleaned transcript:\n{e}")
        return None
# FINISH ### FILE_HANDLING ###

# START ### MAIN_EXECUTION ###
if __name__ == "__main__":
    print("--- Conversation Cleaning Hustle Commencing ---")

    json_file_path = get_input_file_path()

    if not json_file_path:
        print("[*] Operation cancelled or no file provided. Exiting.")
    else:
        data = load_json_data(json_file_path)

        if data is not None:
            print("[*] Data loaded. Processing conversation pairs...")
            cleaned_transcript, skipped_count = process_conversation_data(data)

            if cleaned_transcript is not None:
                # Add a header to the output file indicating the source and skipped items
                header = f"--- Cleaned Transcript from: {os.path.basename(json_file_path)} ---\n"
                if skipped_count > 0:
                    header += f"--- Skipped {skipped_count} potentially garbled or empty message pairs ---\n"
                header += "\n" # Add a blank line before the conversation starts

                final_output = header + cleaned_transcript

                print("[*] Processing complete. Saving transcript...")
                saved_path = save_transcript(final_output, json_file_path)

                if saved_path:
                    print(f"[*] Hustle successful! Cleaned transcript saved to:\n{saved_path}")
                    if skipped_count > 0:
                         print(f"[*] Note: {skipped_count} pairs were skipped as potentially garbled.")
                    messagebox.showinfo("Success", f"Cleaning complete!\nTranscript saved to:\n{saved_path}\n(Skipped {skipped_count} pairs)")
                else:
                    print("[!] Failed to save the cleaned transcript.")
                    messagebox.showerror("Save Failed", "Failed to save the cleaned transcript.")

            else:
                print("[!] Failed to process conversation data.")
                messagebox.showerror("Processing Failed", "Failed to process conversation data.")
        else:
            print("[!] Could not load data. Check error messages above.")
            # load_json_data already showed a message box

    print("--- Conversation Cleaning Hustle Finished ---")
# FINISH ### MAIN_EXECUTION ###
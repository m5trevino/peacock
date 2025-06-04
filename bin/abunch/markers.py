import os
import sys

def create_marked_filename(original_path):
    """Create filename with -marked suffix"""
    base, ext = os.path.splitext(original_path)
    return f"{base}-marked{ext}"

def create_unmarked_filename(original_path):
    """Create filename with -unmarked suffix"""
    base, ext = os.path.splitext(original_path)
    return f"{base}-unmarked{ext}"

def insert_markers(file_path):
    """Insert the 5 strategic markers in the file"""
    try:
        # Read the original file
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        total_lines = len(lines)
        if total_lines < 4:
            print("File too small for markers")
            return False

        # Calculate marker positions
        q1 = total_lines // 4
        q2 = total_lines // 2
        q3 = (total_lines * 3) // 4

        # Create new file content with markers
        new_lines = []

        # Start marker (before any code)
        new_lines.append("\n####START OF DOCUMENT####\n")

        # Add first quarter of code
        for i in range(q1):
            new_lines.append(lines[i])

        # Quarter marker
        new_lines.append("\n####1/4 MARKER####\n")

        # Add second quarter of code
        for i in range(q1, q2):
            new_lines.append(lines[i])

        # Half marker
        new_lines.append("\n####1/2 MARKER####\n")

        # Add third quarter of code
        for i in range(q2, q3):
            new_lines.append(lines[i])

        # Three-quarter marker
        new_lines.append("\n####3/4 MARKER####\n")

        # Add final quarter of code
        for i in range(q3, total_lines):
            new_lines.append(lines[i])

        # End marker (after all code)
        new_lines.append("\n####END OF DOCUMENT####\n")

        # Write to new file
        new_file_path = create_marked_filename(file_path)
        with open(new_file_path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)

        print(f"\nCreated marked version at: {new_file_path}")
        print_instructions()
        return True

    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False

def remove_markers(file_path):
    """Remove all markers from a file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        # Filter out marker lines and surrounding empty lines
        clean_lines = []
        skip_next = False
        for line in lines:
            if "####" in line:
                skip_next = True
                continue
            if skip_next and line.strip() == "":
                skip_next = False
                continue
            clean_lines.append(line)

        # Write to new file
        new_file_path = create_unmarked_filename(file_path)
        with open(new_file_path, 'w', encoding='utf-8') as f:
            f.writelines(clean_lines)

        print(f"\nCreated clean version at: {new_file_path}")
        return True

    except Exception as e:
        print(f"Error removing markers from {file_path}: {e}")
        return False

def print_instructions():
    """Print instructions for using the marker system"""
    instructions = """
Overview

The marker system is designed to help you modify specific sections of code while ensuring that all relevant code is preserved. Each section of code is enclosed between five distinct markers, which must remain unchanged. Follow these instructions carefully to make your edits correctly.
The 5 Markers

You will use the following markers to indicate the sections of code you want to modify:

    ####START OF DOCUMENT####
    ####1/4 MARKER####
    ####1/2 MARKER####
    ####3/4 MARKER####
    ####END OF DOCUMENT####

How to Make Changes

    Copy the Entire Section: When you want to modify a section of code, copy the entire block of code, including the markers above and below the section you want to edit. This ensures that you have the complete context.

    Make Your Edits:
        You can add, remove, or modify lines of code as needed.
        Ensure that any changes you make are within the markers you copied.

    Preserve the Markers:
        Do not change the text or formatting of the markers.
        Do not add or remove any # symbols or spaces around the markers.
        Always include both the marker above and the marker below the section you are editing.

    Return the Complete Section: After making your changes, paste the entire section back, including the markers. This means you will return the original code, along with your modifications, in the same format as it was copied.

    Avoid Common Mistakes:
        Do not copy code without the markers.
        Do not modify the marker text or formatting.
        Do not paste without including both markers.
        Do not add or remove blank lines around markers.

Example of Correct Usage

    Original Code:

    ####1/4 MARKER####
    def original_function():
        print("Hello World")
        return True
    ####1/2 MARKER####

    Make Edits:

    ####1/4 MARKER####
    def modified_function():
        print("Hello Modified World")
        return True
    ####1/2 MARKER####

    Return the Complete Section:

    ####1/4 MARKER####
    def modified_function():
        print("Hello Modified World")
        return True
    ####1/2 MARKER####

Final Notes

    Always double-check that you have included all code between the markers when making changes.
    If you are unsure about any changes, feel free to ask for clarification before proceeding.

By following these revised instructions, you should be able to use the marker system effectively without misunderstandings.
"""
    print(instructions)

def main():
    """Main function to handle command line usage"""
    print("\n=== Code Section Marker Tool ===")
    print("1. Add markers to a file")
    print("2. Remove markers from a file")
    print("3. Exit")

    while True:
        choice = input("\nEnter your choice (1-3): ").strip()

        if choice == "1":
            file_path = input("Enter the path to the file: ").strip()
            if os.path.isfile(file_path):
                insert_markers(file_path)
            else:
                print("Invalid file path")

        elif choice == "2":
            file_path = input("Enter the path to the marked file: ").strip()
            if os.path.isfile(file_path):
                remove_markers(file_path)
            else:
                print("Invalid file path")

        elif choice == "3":
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
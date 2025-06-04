import os

# Supported text-based file extensions
EXTENSIONS = {".py", ".ts", ".js", ".sh", ".txt", ".json", ".yaml", ".md"}

# Marker patterns to remove
MARKERS = {
    "#################1st line#####################\n",
    "#################2nd line#####################\n",
    "#################3rd line#####################\n"
}

##############################################

def count_lines(file_path):
    """Count the number of lines in a file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.readlines()
    except Exception as e:
        print(f"Skipping {file_path}: {e}")
        return None

##############################################

def remove_markers(file_path, lines):
    """Remove markers from the file."""
    new_lines = [line for line in lines if line not in MARKERS]

    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)
    
    print(f"Updated {file_path} by removing markers.")

##############################################

def process_directory(directory):
    """Process all valid files in the given directory and subdirectories."""
    for root, _, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in EXTENSIONS):
                file_path = os.path.join(root, file)
                lines = count_lines(file_path)
                if lines is not None:
                    remove_markers(file_path, lines)

##############################################

if __name__ == "__main__":
    dir_path = input("Enter the directory to process: ").strip()
    if os.path.isdir(dir_path):
        process_directory(dir_path)
    else:
        print("Invalid directory.")
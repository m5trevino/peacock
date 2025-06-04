import os
import random
from tkinter import Tk, filedialog
from colorama import Fore, Style, init
init(autoreset=True)

def display_banner():
    """Display a random ASCII banner from the file."""
    try:
        with open('rottenascii.txt', 'r') as f:
            banners = f.read().split("\n\n\n")
        print(Fore.MAGENTA + random.choice(banners) + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"Error loading banner: {e}" + Style.RESET_ALL)

def recent_txt_files(search_dir='.'):
    """Return a list of recent .txt files in the given directory."""
    try:
        txt_files = [os.path.join(search_dir, f) for f in os.listdir(search_dir) if f.endswith('.txt')]
        txt_files.sort(key=os.path.getmtime, reverse=True)
        return txt_files
    except Exception as e:
        print(Fore.RED + f"Error finding recent files: {e}" + Style.RESET_ALL)
        return []

def split_text_file(file_path, words_per_file, output_dir, base_name):
    """Split the text file into smaller parts."""
    try:
        with open(file_path, 'r') as f:
            content = f.read()

        words = content.split()
        lines = content.splitlines()
        total_words = len(words)
        total_lines = len(lines)
        print(Fore.GREEN + f"\nThe document has {total_words} words and {total_lines} lines.\n" + Style.RESET_ALL)

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        num_files = (total_words + words_per_file - 1) // words_per_file
        start = 0
        for i in range(num_files):
            end = min(start + words_per_file, total_words)
            part_content = ' '.join(words[start:end])
            file_name = os.path.join(output_dir, f"{base_name}_{i + 1:03}.txt")

            with open(file_name, 'w') as part_file:
                part_file.write(part_content)

            print(Fore.CYAN + f"Created file: {file_name} ({end - start} words)" + Style.RESET_ALL)
            start = end

        print(Fore.GREEN + f"\nSplitting complete. Files saved in: {os.path.abspath(output_dir)}\n" + Style.RESET_ALL)

    except Exception as e:
        print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)

def main():
    display_banner()

    # Select file
    print(Fore.GREEN + "Welcome to RottenLimits - Text Splitter!" + Style.RESET_ALL)
    print(Fore.YELLOW + "\nOptions to select a file:" + Style.RESET_ALL)
    print("1. List recent .txt files")
    print("2. Type full file path")
    print("3. Open file dialog (GUI)")

    while True:
        choice = input(Fore.MAGENTA + "\nChoose an option (1/2/3): " + Style.RESET_ALL).strip()
        if choice == '1':
            search_dir = input(Fore.CYAN + "\nEnter directory to search (default: current): " + Style.RESET_ALL).strip() or '.'
            txt_files = recent_txt_files(search_dir)
            if txt_files:
                print(Fore.YELLOW + "\nRecent .txt files:" + Style.RESET_ALL)
                for idx, file in enumerate(txt_files[:10], start=1):
                    print(f"{idx}. {file}")
                try:
                    file_idx = int(input(Fore.MAGENTA + "\nSelect a file by number: " + Style.RESET_ALL)) - 1
                    file_path = txt_files[file_idx]
                    break
                except (IndexError, ValueError):
                    print(Fore.RED + "Invalid selection. Try again." + Style.RESET_ALL)
            else:
                print(Fore.RED + "No .txt files found. Try another option." + Style.RESET_ALL)
        elif choice == '2':
            file_path = input(Fore.CYAN + "\nEnter the full file path: " + Style.RESET_ALL).strip()
            if os.path.isfile(file_path):
                break
            else:
                print(Fore.RED + "Invalid file path. Try again." + Style.RESET_ALL)
        elif choice == '3':
            Tk().withdraw()
            file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
            if file_path:
                break
            else:
                print(Fore.RED + "No file selected. Try again." + Style.RESET_ALL)
        else:
            print(Fore.RED + "Invalid choice. Try again." + Style.RESET_ALL)

    # Load file content
    with open(file_path, 'r') as f:
        content = f.read()
    total_words = len(content.split())
    total_lines = len(content.splitlines())
    print(Fore.GREEN + f"\nThe document has {total_words} words and {total_lines} lines.\n" + Style.RESET_ALL)

    # Suggested splits
    print(Fore.YELLOW + "Suggested splits:" + Style.RESET_ALL)
    for parts in [2, 4, 6, 8, 10, 12, 14, 16]:
        words_per_part = total_words // parts
        lines_per_part = total_lines // parts
        print(f"{parts} parts: ~{words_per_part} words, ~{lines_per_part} lines per part")

    # Custom split choice
    parts = int(input(Fore.MAGENTA + "\nEnter the number of parts to split into (e.g., 2, 4, 6, etc.): " + Style.RESET_ALL).strip())
    words_per_file = total_words // parts

    # Output directory and file naming
    base_name = os.path.splitext(os.path.basename(file_path))[0] + "-split"
    output_dir = os.path.join(os.path.dirname(file_path), "split")
    custom_name = input(Fore.CYAN + "\nEnter a custom base name for split files (or press Enter to use default): " + Style.RESET_ALL).strip()
    if custom_name:
        base_name = custom_name
    custom_dir = input(Fore.CYAN + "\nEnter a custom output directory (or press Enter to use default): " + Style.RESET_ALL).strip()
    if custom_dir:
        output_dir = custom_dir

    print(Fore.GREEN + f"\nSplitting the file into {parts} parts (~{words_per_file} words each)...\n" + Style.RESET_ALL)
    split_text_file(file_path, words_per_file, output_dir, base_name)

if __name__ == "__main__":
    main()

import os

# Path to the main directory containing all repositories
main_dir = "/home/flintx/flow/convo/"

# List of file extensions to include
valid_extensions = ['.js', '.py', '.md', '.txt']

# Iterate over each directory inside the main directory (representing each repo)
for repo_name in os.listdir(main_dir):
    repo_path = os.path.join(main_dir, repo_name)

    # Skip if it's not a directory (it's not a repo)
    if not os.path.isdir(repo_path):
        continue

    # Name for the output file
    output_file = os.path.join(main_dir, f"{repo_name}-merged.txt")

    # Open the output file for writing
    with open(output_file, 'w') as merged_file:
        # Walk through the repository's directory
        for root, dirs, files in os.walk(repo_path):
            for file in files:
                # Check if the file has a valid extension
                if any(file.endswith(ext) for ext in valid_extensions):
                    file_path = os.path.join(root, file)

                    # Write the start separator with the filename
                    merged_file.write(f"▂▃▅▇█▓▒░ START -{file} ░▒▓█▇▅▃▂\n")
                    
                    # Open and write the content of the file
                    with open(file_path, 'r') as f:
                        merged_file.write(f.read())
                    
                    # Write the end separator with the filename
                    merged_file.write(f"\n▂▃▅▇█▓▒░ END -{file} ░▒▓█▇▅▃▂\n")
                    
                    # Add a line break between files
                    merged_file.write("\n")

    print(f"Successfully merged files for repo: {repo_name}")


import os

# Clear the output file if it exists
output_file = "merged_files.txt"
with open(output_file, "w"):
    pass

# Get all text files in the current directory
text_files = [file for file in os.listdir() if file.endswith(".txt")]

# Loop through each text file
for file in text_files:
    # Add separator lines
    with open(output_file, "a") as f:
        f.write("==================================================\n")
        # Print the filename below the separator
        f.write(f"                              [{file}]\n")
        f.write("==================================================\n")
    # Append the content of the current file to the output file
    with open(file, "r") as f:
        content = f.read()
        with open(output_file, "a") as out_f:
            out_f.write(content)

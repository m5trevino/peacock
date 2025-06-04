#!/bin/bash

# Directory containing the files
input_dir="./"  # Directory where your files are located
output_file="merged_output.txt"

# Clear or create the output file
> "$output_file"

# Loop through all files in the directory
for file in "$input_dir"*.sh; do
    if [[ -f "$file" ]]; then
        # Get the file name without the path
        filename=$(basename "$file")

        # Add the separator with the file name
        printf -- "----------------------------------------------------------------------\n" >> "$output_file"
        printf -- "----------------------%s------------------------------\n" "$filename" >> "$output_file"
        printf -- "----------------------------------------------------------------------\n" >> "$output_file"

        # Append the file content
        if ! cat "$file" >> "$output_file"; then
            echo "Error reading $file. Skipping." >&2
        fi

        # Add a newline at the end for separation
        printf "\n" >> "$output_file"
    else
        echo "No files found matching *.sh in $input_dir." >&2
    fi
done

echo "All files have been merged into $output_file"

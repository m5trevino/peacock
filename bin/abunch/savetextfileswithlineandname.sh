#!/bin/bash

# Clear the output file if it exists
> merged_files.txt

# Loop through each text file in the current directory
for file in *.; do
    # Add separator lines
    echo "==================================================" >> merged_files.txt
    # Print the filename below the separator
    echo "                              [$file]" >> merged_files.txt
    echo "==================================================" >> merged_files.txt
    # Append the content of the current file to the output file
    cat "$file" >> merged_files.txt
done

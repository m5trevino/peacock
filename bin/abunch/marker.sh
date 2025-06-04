#!/bin/bash

# Script to add quarter-point markers to a text file.
# Usage: ./add_markers.sh <filename>

# --- Config ---
MARKER_ONE="##########one###########"
MARKER_TWO="##########two###########"
MARKER_THREE="##########three#########"
MARKER_FOUR="##########four##########"
MIN_LINES=4 # Require at least 4 lines to add all markers meaningfully

# --- Input Validation ---
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <filename>"
    exit 1
fi

filename="$1"

if [ ! -f "$filename" ]; then
    echo "Error: File '$filename' not found or is not a regular file."
    exit 1
fi

# --- Line Calculation ---
total_lines=$(wc -l < "$filename")

if [ "$total_lines" -lt "$MIN_LINES" ]; then
    echo "File '$filename' has only $total_lines lines. Need at least $MIN_LINES lines to add all markers."
    # Optionally, add logic here to handle small files differently if needed
    exit 1
fi

# Calculate marker line numbers (integer division)
# Ensure line numbers are at least 1
line_one=$(( total_lines / 4 ))
[ "$line_one" -eq 0 ] && line_one=1

line_two=$(( total_lines / 2 ))
[ "$line_two" -eq 0 ] && line_two=1

line_three=$(( total_lines * 3 / 4 ))
[ "$line_three" -eq 0 ] && line_three=1

# The last line is always the total number of lines
line_four=$total_lines

echo "Processing '$filename' ($total_lines lines):"
echo "  Marker 1 -> Line $line_one"
echo "  Marker 2 -> Line $line_two"
echo "  Marker 3 -> Line $line_three"
echo "  Marker 4 -> After Line $line_four"

# --- Marker Insertion using awk ---
# Create a secure temporary file
tmp_file=$(mktemp)
if [ -z "$tmp_file" ]; then
    echo "Error: Could not create temporary file."
    exit 1
fi

# Use awk to insert markers *before* the target line number,
# except for the last marker which goes *after* the last line.
awk \
    -v l1="$line_one" -v m1="$MARKER_ONE" \
    -v l2="$line_two" -v m2="$MARKER_TWO" \
    -v l3="$line_three" -v m3="$MARKER_THREE" \
    -v l4="$line_four" -v m4="$MARKER_FOUR" \
    '
    # Insert marker *before* printing the line content
    NR == l1 {print m1}
    NR == l2 {print m2}
    NR == l3 {print m3}

    # Always print the original line
    { print $0 }

    # Insert the last marker *after* the last line content
    NR == l4 {print m4}
    ' "$filename" > "$tmp_file"

# --- Replace Original File ---
if [ $? -eq 0 ] && [ -s "$tmp_file" ]; then
    # awk succeeded and produced output, replace original
    mv "$tmp_file" "$filename"
    echo "Markers added successfully to '$filename'."
else
    # awk failed or produced empty output, clean up temp file
    echo "Error: awk processing failed or produced empty output. Original file untouched."
    rm -f "$tmp_file"
    exit 1
fi

exit 0
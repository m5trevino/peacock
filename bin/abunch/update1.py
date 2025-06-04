#!/usr/bin/env python3

import os
import re
import pandas as pd
import psutil
from pathlib import Path

def extract_signatures_to_combined(decompiled_dir, output_combined_file):
    """
    Extract class and method signatures from decompiled Java files and save them in a single CSV file.
    If a class has no methods, it will add "no method extracted".
    """
    print(f"[*] Analyzing decompiled files in {decompiled_dir}")
    
    combined_data = []
    no_method_count = 0
    total_classes = 0
    total_methods = 0

    # Process each decompiled APK directory
    for apk_dir in Path(decompiled_dir).iterdir():
        if not apk_dir.is_dir():
            continue
            
        print(f"\n[*] Processing {apk_dir.name}")
        
        # Find all Java files recursively
        java_files = list(apk_dir.rglob("*.java"))
        
        for java_file in java_files:
            try:
                with open(java_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    # Extract class name
                    class_match = re.search(r'class (\w+)', content)
                    if not class_match:
                        continue
                        
                    class_name = class_match.group(1)
                    total_classes += 1
                    
                    # Extract method signatures
                    methods = re.finditer(r'(?:public|private|protected|\s)?[\w\<\>\[\]]+\s+(\w+)\s*\([^\)]*\)\s*(?:throws\s+[\w\s,]+)?\s*(?:;|{)', content)
                    method_list = [m.group(0) for m in methods]
                    
                    # Add to combined data
                    if method_list:
                        combined_data.append({
                            'class': class_name,
                            'methods': '; '.join(method_list)  # Join methods with semicolon
                        })
                        total_methods += len(method_list)
                    else:
                        combined_data.append({
                            'class': class_name,
                            'methods': 'no method extracted'  # Add placeholder for no methods
                        })
                        no_method_count += 1

                # Print updates every 100 classes processed
                if total_classes % 100 == 0:
                    mem = psutil.virtual_memory()
                    print(f"Classes processed: {total_classes}, Methods extracted: {total_methods}, Classes with no methods: {no_method_count}")
                    print(f"Memory usage: {mem.percent}%")

            except Exception as e:
                print(f"[-] Error processing {java_file}: {str(e)}")
                continue

    # Create DataFrame for combined data
    combined_data_df = pd.DataFrame(combined_data)
    
    # Save combined data to CSV
    combined_data_df.to_csv(output_combined_file, index=False)
    print(f"[+] Combined data saved to {output_combined_file}")
    print(f"Total classes processed: {total_classes}")
    print(f"Total methods extracted: {total_methods}")
    print(f"Total classes with no methods: {no_method_count}")

def preprocess_combined_csv(input_file):
    """
    Preprocess the combined CSV file to clean and validate the data.
    Saves a cleaned CSV and a report summarizing the findings based on the input filename.
    """
    print(f"[*] Loading file: {input_file}")
    try:
        # Load the combined CSV
        df = pd.read_csv(input_file)

        # Check for missing or invalid data
        print("[*] Checking for missing or invalid data...")
        total_rows = len(df)
        invalid_rows = df[(df['class'].isnull()) | (df['methods'].isnull())]
        valid_rows = df.dropna()

        # Normalize class names and methods
        print("[*] Normalizing data...")
        valid_rows['class'] = valid_rows['class'].str.strip()
        valid_rows['methods'] = valid_rows['methods'].str.strip()

        # Flag and count "no method extracted"
        no_methods_count = valid_rows[valid_rows['methods'] == 'no method extracted'].shape[0]

        # Identify any methods that don't match a typical signature
        print("[*] Validating method signatures...")
        method_pattern = re.compile(r'[\w<>]+\s+\w+\([^)]*\)')
        valid_rows['valid_method'] = valid_rows['methods'].apply(
            lambda x: 'valid' if method_pattern.search(x) or x == 'no method extracted' else 'invalid'
        )
        invalid_methods = valid_rows[valid_rows['valid_method'] == 'invalid']

        # Save cleaned data
        base_name = os.path.splitext(os.path.basename(input_file))[0]
        output_file = f"{base_name}_cleaned.csv"
        cleaned_data = valid_rows[valid_rows['valid_method'] == 'valid'].drop(columns=['valid_method'])
        cleaned_data.to_csv(output_file, index=False)

        # Generate a report
        report_file = f"{base_name}_report.txt"
        print(f"[*] Generating report: {report_file}")
        with open(report_file, 'w') as report:
            report.write(f"Total rows: {total_rows}\n")
            report.write(f"Valid rows: {len(cleaned_data)}\n")
            report.write(f"Rows with missing data: {len(invalid_rows)}\n")
            report.write(f"Rows with 'no method extracted': {no_methods_count}\n")
            report.write(f"Rows with invalid methods: {len(invalid_methods)}\n")

        print(f"[+] Preprocessing completed successfully!")
        print(f"    Cleaned data saved to: {os.path.abspath(output_file)}")
        print(f"    Report saved to: {os.path.abspath(report_file)}")

    except Exception as e:
        print(f"[-] Error during preprocessing: {str(e)}")

if __name__ == "__main__":
    # Prompt for decompiled directory
    decompiled_dir = input("Enter the path to the directory containing the decompiled APK files: ").strip()

    # Validate input directory
    if not os.path.isdir(decompiled_dir):
        print(f"[-] Error: {decompiled_dir} is not a valid directory.")
        exit(1)

    # Use the directory name to create the output CSV filename
    dir_name = os.path.basename(os.path.normpath(decompiled_dir))
    output_combined_file = f"{dir_name}_combined.csv"

    # Run the extraction process
    extract_signatures_to_combined(decompiled_dir, output_combined_file)

    # Run the preprocessing process
    preprocess_combined_csv(output_combined_file)

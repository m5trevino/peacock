#!/usr/bin/env python3

import os
import re
import pandas as pd
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

            except Exception as e:
                print(f"[-] Error processing {java_file}: {str(e)}")
                continue

    # Create DataFrame for combined data
    combined_df = pd.DataFrame(combined_data)
    
    # Save combined data to CSV
    combined_df.to_csv(output_combined_file, index=False)
    print(f"[+] Combined data saved to {output_combined_file}")
    print(f"Total classes processed: {total_classes}")
    print(f"Total methods extracted: {total_methods}")
    print(f"Total classes with no methods: {no_method_count}")

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

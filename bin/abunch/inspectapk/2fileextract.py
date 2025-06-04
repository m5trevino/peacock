#!/usr/bin/env python3

import os
import sys
import re
import pandas as pd
import psutil  # For monitoring system resource usage
from pathlib import Path

def extract_signatures(decompiled_dir, output_classes_file, output_methods_file):
    """
    Extract class and method signatures from decompiled Java files and save them in separate CSV files.
    If a class has no methods, a "no method extracted" entry is added.
    """
    print(f"[*] Analyzing decompiled files in {decompiled_dir}")
    
    # Store data for DataFrame
    classes_data = []
    methods_data = []
    no_method_count = 0
    total_classes = 0
    total_methods = 0
    index = 0
    
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
                    classes_data.append({'index': index, 'class': class_name})
                    total_classes += 1
                    
                    # Extract method signatures
                    methods = re.finditer(r'(?:public|private|protected|\s)?[\w\<\>\[\]]+\s+(\w+)\s*\([^\)]*\)\s*(?:throws\s+[\w\s,]+)?\s*(?:;|{)', content)
                    method_list = [m.group(0) for m in methods]
                    
                    # If methods found, add to the methods data
                    if method_list:
                        methods_data.append({
                            'index': index,
                            'methods': '; '.join(method_list)  # Join methods with semicolon
                        })
                        total_methods += len(method_list)
                    else:
                        methods_data.append({
                            'index': index,
                            'methods': 'no method extracted'  # Add a placeholder for no methods
                        })
                        no_method_count += 1
                    
                    index += 1

                # Print updates every 100 classes processed
                if total_classes % 100 == 0:
                    mem = psutil.virtual_memory()
                    print(f"Classes processed: {total_classes}, Methods extracted: {total_methods}, Classes with no methods: {no_method_count}")
                    print(f"Memory usage: {mem.percent}%")

            except Exception as e:
                print(f"[-] Error processing {java_file}: {str(e)}")
                continue

    # Create DataFrames for classes and methods
    classes_df = pd.DataFrame(classes_data)[['class']]
    methods_df = pd.DataFrame(methods_data)[['methods']]
    
    # Save class names to CSV
    classes_df.to_csv(output_classes_file, index=False, header=['class'])
    print(f"[+] Extracted {len(classes_df)} classes to {output_classes_file}")
        
    # Save method signatures to CSV
    methods_df.to_csv(output_methods_file, index=False, header=['methods'])
    print(f"[+] Extracted {len(methods_df)} method signatures to {output_methods_file}")
    print(f"Total number of methods extracted: {total_methods}")
    print(f"Total number of classes with no methods: {no_method_count}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python 2_extract_signatures.py <decompiled_dir> <output_classes_file> <output_methods_file>")
        print("Example: python 2_extract_signatures.py ./decompiled ./classes.csv ./methods.csv")
        sys.exit(1)
    
    decompiled_dir = sys.argv[1]
    output_classes_file = sys.argv[2]
    output_methods_file = sys.argv[3]
    extract_signatures(decompiled_dir, output_classes_file, output_methods_file)

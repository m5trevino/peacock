#!/usr/bin/env python3

import os
import sys
import re
import pandas as pd
import psutil  # For monitoring system resource usage
from pathlib import Path

def get_unique_filename(base_path, filename):
    """
    Generates a unique filename by appending a number if a file already exists.
    """
    counter = 0
    file_path = os.path.join(base_path, filename)
    while os.path.exists(file_path):
        counter += 1
        name, ext = os.path.splitext(filename)
        filename = f"{name}-{counter:02d}{ext}"
        file_path = os.path.join(base_path, filename)
    return file_path

def extract_signatures(decompiled_dir, output_base_dir):
    """
    Extract class and method signatures from decompiled Java files for each subdirectory (APK).
    Each subdirectory will have two CSVs: one for classes and one for methods.
    """
    print(f"[*] Analyzing decompiled files in {decompiled_dir}")
    
    # Process each decompiled APK directory (each subdirectory)
    for apk_dir in Path(decompiled_dir).iterdir():
        if not apk_dir.is_dir():
            continue
        
        app_name = apk_dir.name  # Use subdir name as the base for CSV filenames
        print(f"\n[*] Processing {apk_dir.name}")
        
        # Store data for DataFrame
        classes_data = []
        methods_data = []
        no_method_count = 0
        total_classes = 0
        total_methods = 0
        index = 0
        
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
        
        # Generate filenames for class and method CSVs
        class_filename = f"{app_name}-class.csv"
        method_filename = f"{app_name}-method.csv"
        
        # Get unique filenames in case files already exist
        class_file_path = get_unique_filename(output_base_dir, class_filename)
        method_file_path = get_unique_filename(output_base_dir, method_filename)
        
        # Create DataFrames for classes and methods
        classes_df = pd.DataFrame(classes_data)[['class']]
        methods_df = pd.DataFrame(methods_data)[['methods']]
        
        # Save class names to CSV
        classes_df.to_csv(class_file_path, index=False, header=['class'])
        print(f"[+] Extracted {len(classes_df)} classes to {class_file_path}")
        
        # Save method signatures to CSV
        methods_df.to_csv(method_file_path, index=False, header=['methods'])
        print(f"[+] Extracted {len(methods_df)} method signatures to {method_file_path}")
        print(f"Total number of methods extracted: {total_methods}")
        print(f"Total number of classes with no methods: {no_method_count}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python 2_extract_signatures.py <decompiled_dir> <output_base_dir>")
        print("Example: python 2_extract_signatures.py ./decompiled /media/flintx/7eb08ac4-d6a0-d01d-500f-4f15b41813c2/trainfrida/.extracted")
        sys.exit(1)
    
    decompiled_dir = sys.argv[1]
    output_base_dir = sys.argv[2]
    extract_signatures(decompiled_dir, output_base_dir)

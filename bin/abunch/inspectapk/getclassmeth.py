#!/usr/bin/env python3

import os
import sys
import re
import pandas as pd
import psutil  # For monitoring system resource usage
from pathlib import Path

def extract_signatures(decompiled_dir, output_csv):
    """
    Extract class and method signatures from decompiled Java files into a single CSV file.
    Each row contains a class and its associated methods. If no methods exist, a placeholder is added.
    """
    print(f"[*] Analyzing decompiled files in {decompiled_dir}")

    extracted_data = []
    total_classes = 0
    total_methods = 0
    no_method_count = 0

    # Process each decompiled APK directory (each subdirectory)
    for apk_dir in Path(decompiled_dir).iterdir():
        if not apk_dir.is_dir():
            continue

        app_name = apk_dir.name  # Use subdir name as reference
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
                    methods = re.finditer(
                        r'(?:public|private|protected|\s)?[\w\<\>\[\]]+\s+(\w+)\s*\([^\)]*\)\s*(?:throws\s+[\w\s,]+)?\s*(?:;|{)',
                        content
                    )
                    method_list = [m.group(0) for m in methods]

                    if method_list:
                        extracted_data.append({'class': class_name, 'methods': '; '.join(method_list)})
                        total_methods += len(method_list)
                    else:
                        extracted_data.append({'class': class_name, 'methods': 'no method extracted'})
                        no_method_count += 1

                # Print system resource updates every 100 classes processed
                if total_classes % 100 == 0:
                    mem = psutil.virtual_memory()
                    print(f"Classes processed: {total_classes}, Methods extracted: {total_methods}, Classes with no methods: {no_method_count}")
                    print(f"Memory usage: {mem.percent}%")

            except Exception as e:
                print(f"[-] Error processing {java_file}: {str(e)}")
                continue

    # Save to CSV
    output_df = pd.DataFrame(extracted_data)
    output_df.to_csv(output_csv, index=False, header=['class', 'methods'])

    print(f"\n[+] Extracted {total_classes} classes to {output_csv}")
    print(f"Total number of methods extracted: {total_methods}")
    print(f"Total number of classes with no methods: {no_method_count}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python extract_signatures.py <decompiled_dir> <output_csv>")
        print("Example: python extract_signatures.py ./decompiled ./extracted_classes_methods.csv")
        sys.exit(1)

    decompiled_dir = sys.argv[1]
    output_csv = sys.argv[2]
    extract_signatures(decompiled_dir, output_csv)

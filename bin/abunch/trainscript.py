#!/usr/bin/env python3

import os
import re
import pandas as pd
import json

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
    for apk_dir in os.scandir(decompiled_dir):
        if not apk_dir.is_dir():
            continue

        print(f"\n[*] Processing {apk_dir.name}")

        # Find all Java files recursively
        for root, _, files in os.walk(apk_dir.path):
            for file in files:
                if file.endswith(".java"):
                    java_file = os.path.join(root, file)
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
    combined_data_df = pd.DataFrame(combined_data)

    # Save combined data to CSV
    combined_data_df.to_csv(output_combined_file, index=False)
    print(f"[+] Combined data saved to {output_combined_file}")
    print(f"Total classes processed: {total_classes}")
    print(f"Total methods extracted: {total_methods}")
    print(f"Total classes with no methods: {no_method_count}")

def generate_training_and_frida(preprocessed_csv, training_jsonl, frida_script):
    """
    Generate training dataset in JSONL format and a Frida script to bypass app security features.
    """
    print(f"[*] Loading preprocessed data from: {preprocessed_csv}")
    try:
        df = pd.read_csv(preprocessed_csv)
        training_data = []
        frida_snippets = []

        # Keywords for identifying security features
        feature_mapping = {
            'SSL Pinning': ['checkServerTrusted', 'verify', 'CertificatePinner'],
            'Root Detection': ['isRooted', 'isDeviceRooted', 'checkSuBinary', '/proc/'],
            'Anti-Debugging': ['isDebuggerConnected', '/proc/self/status'],
            'Tamper Detection': ['ro.hardware', 'Build.FINGERPRINT'],
            'Cryptography': ['Cipher', 'doFinal', 'generateKey'],
        }

        for _, row in df.iterrows():
            class_name = row['class']
            methods = row['methods']

            for feature, keywords in feature_mapping.items():
                if any(keyword in methods for keyword in keywords):
                    # Add to training data
                    input_text = f"Write a Frida hook to bypass {feature} in the class {class_name}"
                    output_hook = f"""Java.perform(function() {{
    var TargetClass = Java.use('{class_name}');
    TargetClass.{methods.split('(')[0]}.implementation = function() {{
        console.log('[+] Bypassing {feature} in {class_name}');
        return true;
    }};
}});"""
                    training_data.append({"input": input_text, "output": output_hook})

                    # Add to Frida script
                    frida_snippets.append(output_hook)

        # Save training data as JSONL
        with open(training_jsonl, 'w') as jsonl_file:
            for entry in training_data:
                jsonl_file.write(json.dumps(entry) + '\n')
        print(f"[+] Training dataset saved to {training_jsonl}")

        # Save Frida script
        with open(frida_script, 'w') as script_file:
            script_file.write("\n".join(frida_snippets))
        print(f"[+] Frida script saved to {frida_script}")

    except Exception as e:
        print(f"[-] Error during dataset and script generation: {str(e)}")

if __name__ == "__main__":
    # Prompt for input type
    choice = input("Do you want to process a decompiled directory (1) or use an existing CSV (2)? Enter 1 or 2: ").strip()

    if choice == '1':
        # Process decompiled directory
        decompiled_dir = input("Enter the path to the directory containing the decompiled APK files: ").strip()

        if not os.path.isdir(decompiled_dir):
            print(f"[-] Error: {decompiled_dir} is not a valid directory.")
            exit(1)

        # Use the directory name to create filenames
        dir_name = os.path.basename(os.path.normpath(decompiled_dir))
        combined_csv = f"{dir_name}_combined.csv"
        training_jsonl = f"{dir_name}_training.jsonl"
        frida_script = f"{dir_name}_frida.js"

        # Run extraction and preprocessing
        extract_signatures_to_combined(decompiled_dir, combined_csv)

        # Generate training dataset and Frida script
        generate_training_and_frida(combined_csv, training_jsonl, frida_script)

    elif choice == '2':
        # Use existing CSV
        preprocessed_csv = input("Enter the path to the preprocessed CSV file: ").strip()

        if not os.path.isfile(preprocessed_csv):
            print(f"[-] Error: {preprocessed_csv} is not a valid file.")
            exit(1)

        # Use the CSV filename to create output filenames
        base_name = os.path.splitext(os.path.basename(preprocessed_csv))[0]
        training_jsonl = f"{base_name}_training.jsonl"
        frida_script = f"{base_name}_frida.js"

        # Generate training dataset and Frida script
        generate_training_and_frida(preprocessed_csv, training_jsonl, frida_script)

    else:
        print("[-] Invalid choice. Please enter 1 or 2.")
        exit(1)

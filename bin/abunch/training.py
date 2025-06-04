#!/usr/bin/env python3

import sys
import json
import pandas as pd
import re

def clean_method_string(method_str):
    """Clean and extract method signature from method string"""
    # Remove leading/trailing whitespace and quotes
    method_str = method_str.strip().strip('"')
    # Remove empty lines
    lines = [line.strip() for line in method_str.split('\n') if line.strip()]
    # Extract method signatures using regex
    signatures = []
    for line in lines:
        if 'return' in line:
            # Extract method name and parameters
            match = re.search(r'return\s+(\w+)\((.*?)\)', line)
            if match:
                method_name = match.group(1)
                params = match.group(2)
                signatures.append(f"{method_name}({params})")
    return signatures

def prepare_training_data(signatures_file, hooks_file, output_file):
    """Format data for fine-tuning Starcoder"""
    print(f"[*] Preparing training data from {signatures_file} and {hooks_file}")
    
    try:
        # Read signatures file with more robust parsing
        signatures_df = pd.read_csv(
            signatures_file,
            sep='\t',  # Use tab as separator
            quoting=3,  # QUOTE_NONE
            quotechar='"',  # Still specify quote char for safety
            escapechar='\\',  # Use backslash as escape char
            on_bad_lines='warn'  # Warn about problematic lines instead of failing
        )
        
        # Ensure required columns exist
        if 'classes' not in signatures_df.columns or 'methods' not in signatures_df.columns:
            print("[-] Error: CSV file must have 'classes' and 'methods' columns")
            print("[*] Found columns:", signatures_df.columns.tolist())
            sys.exit(1)
        
        # Debug info
        print(f"[*] Found {len(signatures_df)} classes")
        
        training_data = []
        
        # Process each class and its methods
        for idx, row in signatures_df.iterrows():
            try:
                class_name = str(row['classes']).strip()
                method_str = str(row['methods']).strip()
                
                if not class_name or class_name == 'nan':
                    print(f"[-] Skipping row {idx}: Invalid class name")
                    continue
                
                # Get clean method signatures
                methods = clean_method_string(method_str)
                
                print(f"[*] Processing class {class_name} with {len(methods)} methods")
                
                for method in methods:
                    # Generate Frida hook template
                    method_name = method.split('(')[0]
                    params = method.split('(')[1].rstrip(')')
                    param_list = [f"arg{i}" for i, _ in enumerate(params.split(',')) if params]
                    
                    hook = f'''Java.perform(function() {{
    var {class_name} = Java.use("{class_name}");
    {class_name}.{method_name}.implementation = function({', '.join(param_list)}) {{
        console.log("[+] Called {class_name}.{method_name}");
        var ret = this.{method_name}({', '.join(param_list)});
        console.log("[+] Return value:", ret);
        return ret;
    }};
}});'''
                    
                    entry = {
                        "input": f"Generate Frida hook for class {class_name} method: {method}",
                        "output": hook
                    }
                    training_data.append(entry)
            
            except Exception as e:
                print(f"[-] Error processing row {idx}: {str(e)}")
                continue
        
        # Save as JSONL
        if training_data:
            with open(output_file, 'w') as f:
                for entry in training_data:
                    f.write(json.dumps(entry) + '\n')
            print(f"[+] Created {len(training_data)} training examples in {output_file}")
        else:
            print("[-] No training data was generated")
        
    except Exception as e:
        print(f"[-] Error preparing training data: {str(e)}")
        print("[*] Debug info:")
        print(f"    - Does {signatures_file} exist and contain data?")
        print("    - Is the file in the correct tab-separated format?")
        print("    - Does it have 'classes' and 'methods' columns?")
        
        # Try to read the first few lines of the file for debugging
        try:
            with open(signatures_file, 'r') as f:
                print("\n[*] First few lines of the file:")
                for i, line in enumerate(f):
                    if i < 5:  # Show first 5 lines
                        print(f"    {line.strip()}")
                    else:
                        break
        except Exception as read_error:
            print(f"[-] Could not read file for debugging: {str(read_error)}")
        
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python training.py <signatures_file> <hooks_file> <output_file>")
        print("Example: python training.py signatures.csv hooks.csv training.jsonl")
        sys.exit(1)
    
    signatures_file = sys.argv[1]
    hooks_file = sys.argv[2]
    output_file = sys.argv[3]
    prepare_training_data(signatures_file, hooks_file, output_file)
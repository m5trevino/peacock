import os
import sys
import re
from pathlib import Path
import pandas as pd
import json
import gc
import psutil  # For monitoring system resource usage

def extract_method_info(java_file):
    """Extract class name and method information from a Java file"""
    try:
        # Log memory usage
        mem = psutil.virtual_memory()
        print(f"Memory usage: {mem.percent}%")
        
        with open(java_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # Extract package name
            package_match = re.search(r'package\s+([\w.]+);', content)
            package_name = package_match.group(1) if package_match else ""
            
            # Extract class name
            class_match = re.search(r'class\s+(\w+)', content)
            if not class_match:
                return None
            
            class_name = class_match.group(1)
            full_class_name = f"{package_name}.{class_name}" if package_name else class_name
            
            # Extract methods using improved regex
            method_pattern = re.compile(
                r'(?:public|private|protected|static|\s+)'  # Access modifiers
                r'\s+'
                r'(?!class|new)(?:[\w\<\>\[\]]+)'  # Return type
                r'\s+'
                r'(\w+)'  # Method name
                r'\s*'
                r'\(((?:[^)]|\([^)]*\))*)\)'  # Parameters with nested parentheses
                r'\s*'
                r'(?:throws\s+[\w\s,]+)?'  # Optional throws clause
                r'\s*'
                r'(?:;|{)'  # End with semicolon or opening brace
            )
            
            methods = []
            for match in method_pattern.finditer(content):
                method_name = match.group(1)
                params = match.group(2).strip()
                
                # Skip constructors and static initializers
                if method_name != class_name and method_name != "static":
                    method_sig = f"{method_name}({params})"
                    methods.append(method_sig)
            
            if methods:
                return {
                    'class': full_class_name,
                    'methods': '\n'.join(methods)
                }
            
    except Exception as e:
        print(f"[-] Error processing {java_file}: {str(e)}")
    
    return None

def save_progress(progress_file, last_processed):
    """Save progress to a file"""
    with open(progress_file, 'w') as f:
        json.dump({'last_processed': last_processed}, f)

def load_progress(progress_file):
    """Load progress from a file"""
    try:
        with open(progress_file, 'r') as f:
            data = json.load(f)
            return data.get('last_processed', 0)
    except:
        return 0

def process_directory(input_dir, output_file, batch_size=1000, max_retries=3):
    """Process all Java files in directory and create CSV"""
    progress_file = output_file + '.progress'
    print(f"[*] Processing Java files in {input_dir}")
    
    # Get list of all Java files
    java_files = list(Path(input_dir).rglob("*.java"))
    total_files = len(java_files)
    print(f"[*] Found {total_files} Java files")
    
    # Load progress if exists
    start_from = load_progress(progress_file)
    if start_from > 0:
        print(f"[*] Resuming from file {start_from}")
    
    data = []
    current_batch = []
    
    for i, java_file in enumerate(java_files[start_from:], start=start_from):
        retries = 0
        while retries < max_retries:
            try:
                if i % 100 == 0:
                    print(f"[*] Progress: {i}/{total_files} files processed")
                
                result = extract_method_info(java_file)
                if result:
                    current_batch.append(result)
                
                # Process batch
                if len(current_batch) >= batch_size:
                    # Log memory usage
                    mem = psutil.virtual_memory()
                    print(f"Memory usage: {mem.percent}%")
                    
                    # Create DataFrame for current batch
                    df_batch = pd.DataFrame(current_batch, columns=['class', 'methods'])
                    
                    # Append to file
                    mode = 'a' if i > batch_size else 'w'
                    header = i <= batch_size
                    df_batch.to_csv(
                        output_file,
                        sep='\t',
                        index=False,
                        quoting=3,
                        escapechar='\\',
                        encoding='utf-8',
                        mode=mode,
                        header=header
                    )
                    
                    # Clear batch and force garbage collection
                    current_batch = []
                    gc.collect()
                    
                    # Save progress
                    save_progress(progress_file, i)
                
                break  # If successful, break out of the retry loop
                
            except Exception as e:
                print(f"[-] Error processing {java_file} (attempt {retries + 1}/{max_retries}): {str(e)}")
                retries += 1
                if retries >= max_retries:
                    print(f"[-] Skipping {java_file} after {max_retries} failed attempts.")
                    save_progress(progress_file, i)
                    break  # Skip to next file after retries exhausted
    
    # Process remaining files
    if current_batch:
        df_batch = pd.DataFrame(current_batch, columns=['class', 'methods'])
        df_batch.to_csv(
            output_file,
            sep='\t',
            index=False,
            quoting=3,
            escapechar='\\',
            encoding='utf-8',
            mode='a',
            header=False
        )
    
    # Clear progress file when done
    if os.path.exists(progress_file):
        os.remove(progress_file)
    
    print(f"\n[+] Successfully processed all {total_files} files")
    print(f"[+] Output saved to: {output_file}")

def main():
    if len(sys.argv) != 3:
        print("Usage: python extract_methods.py <input_dir> <output_file>")
        print("Example: python extract_methods.py ./decompiled ./methods.csv")
        sys.exit(1)
    
    input_dir = sys.argv[1]
    output_file = sys.argv[2]
    
    if not os.path.isdir(input_dir):
        print(f"[-] Error: {input_dir} is not a directory")
        sys.exit(1)
    
    process_directory(input_dir, output_file)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3

import os
import sys
import subprocess
import json
import re
from pathlib import Path

class APKAnalyzer:
    def __init__(self, output_dir="output"):
        self.output_dir = output_dir
        self.decompiled_dir = os.path.join(output_dir, "decompiled")
        self.signatures_file = os.path.join(output_dir, "method_signatures.txt")
        self.frida_hooks_file = os.path.join(output_dir, "frida_hooks.js")
        self.training_data_file = os.path.join(output_dir, "training_data.jsonl")

    def setup_directories(self):
        """Create necessary directories if they don't exist"""
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.decompiled_dir, exist_ok=True)

    def decompile_apk(self, apk_path):
        """Decompile APK using jadx"""
        print(f"[*] Decompiling {apk_path}...")
        try:
            subprocess.run(["jadx", "-d", self.decompiled_dir, apk_path], check=True)
            print("[+] Decompilation successful")
        except subprocess.CalledProcessError:
            print("[-] Error: jadx not found or decompilation failed")
            print("    Please install jadx: https://github.com/skylot/jadx")
            sys.exit(1)

    def extract_signatures(self):
        """Extract method signatures from decompiled Java files"""
        print("[*] Extracting method signatures...")
        signatures = []
        
        for java_file in Path(self.decompiled_dir).rglob("*.java"):
            with open(java_file, 'r', encoding='utf-8') as f:
                content = f.read()
                # Match method signatures
                matches = re.finditer(r'(?:public|private|protected|static|\s) +[\w\<\>\[\]]+\s+(\w+) *\([^\)]*\)', content)
                class_name = re.search(r'class (\w+)', content)
                
                if class_name:
                    class_name = class_name.group(1)
                    for match in matches:
                        method = match.group(0)
                        signatures.append(f"{class_name}.{method}")

        with open(self.signatures_file, 'w') as f:
            f.write('\n'.join(signatures))
        print(f"[+] Extracted {len(signatures)} signatures")

    def generate_frida_hooks(self):
        """Generate Frida hooks from extracted signatures"""
        print("[*] Generating Frida hooks...")
        hooks = []
        
        with open(self.signatures_file, 'r') as f:
            signatures = f.readlines()

        hook_template = '''Java.perform(function() {
    var %s = Java.use("%s");
    %s.%s.implementation = function(%s) {
        console.log("[+] Called %s.%s");
        var ret = this.%s(%s);
        console.log("[+] Return value:", ret);
        return ret;
    };
});'''

        for sig in signatures:
            if '.' in sig:
                class_name, method_sig = sig.strip().rsplit('.', 1)
                method_name = re.search(r'(\w+)\s*\(', method_sig)
                if method_name:
                    method_name = method_name.group(1)
                    params = re.search(r'\((.*?)\)', method_sig)
                    param_list = params.group(1).split(',') if params else []
                    param_names = [f'p{i}' for i in range(len(param_list))]
                    
                    hook = hook_template % (
                        class_name.replace('.', '_'),
                        class_name,
                        method_name,
                        method_name,
                        ', '.join(param_names),
                        class_name,
                        method_name,
                        method_name,
                        ', '.join(param_names)
                    )
                    hooks.append(hook)

        with open(self.frida_hooks_file, 'w') as f:
            f.write('\n\n'.join(hooks))
        print(f"[+] Generated {len(hooks)} Frida hooks")

    def prepare_training_data(self):
        """Format data for model training"""
        print("[*] Preparing training data...")
        training_data = []
        
        # Read signatures and hooks
        with open(self.signatures_file, 'r') as f:
            signatures = f.readlines()
        with open(self.frida_hooks_file, 'r') as f:
            hooks = f.read()

        # Create training pairs
        for sig in signatures:
            entry = {
                "input": f"Generate Frida hook for method: {sig.strip()}",
                "output": hooks  # You might want to find the corresponding hook instead of using all
            }
            training_data.append(entry)

        # Save as JSONL
        with open(self.training_data_file, 'w') as f:
            for entry in training_data:
                f.write(json.dumps(entry) + '\n')
        print(f"[+] Created {len(training_data)} training examples")

def main():
    if len(sys.argv) != 2:
        print("Usage: python apk_toolkit.py <path_to_apk>")
        sys.exit(1)

    apk_path = sys.argv[1]
    analyzer = APKAnalyzer()
    
    analyzer.setup_directories()
    analyzer.decompile_apk(apk_path)
    analyzer.extract_signatures()
    analyzer.generate_frida_hooks()
    analyzer.prepare_training_data()
    
    print("\n[+] Analysis complete! Files generated:")
    print(f"    - Method signatures: {analyzer.signatures_file}")
    print(f"    - Frida hooks: {analyzer.frida_hooks_file}")
    print(f"    - Training data: {analyzer.training_data_file}")

if __name__ == "__main__":
    main()
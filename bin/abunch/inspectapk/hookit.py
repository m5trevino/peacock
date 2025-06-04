#!/usr/bin/env python3

import os
import sys
import pandas as pd
import re

def generate_hooks(signatures_file, output_file):
    """
    Generate Frida hooks from extracted signatures
    """
    print(f"[*] Reading signatures from {signatures_file}")
    
    try:
        # Read signatures file
        df = pd.read_csv(signatures_file, sep='\t')
        
        hook_template = '''Java.perform(function() {
    var %s = Java.use("%s");
    %s.%s.implementation = function(%s) {
        console.log("[+] Called %s.%s");
        var ret = this.%s(%s);
        console.log("[+] Return value:", ret);
        return ret;
    };
});'''
        
        hooks = []
        
        # Process each class and its methods
        for _, row in df.iterrows():
            class_name = str(row['classes']) if pd.notna(row['classes']) else "UnknownClass"
            methods = row['methods'].split('\n')
            
            for method in methods:
                # Extract method name and parameters
                method_match = re.search(r'(\w+)\s*\((.*?)\)', method)
                if method_match:
                    method_name = method_match.group(1)
                    params = method_match.group(2).split(',')
                    param_names = [f'p{i}' for i in range(len(params)) if params[0]]
                    
                    hook = hook_template % (
                        class_name.replace('.', '_'),
                        class_name,
                        class_name,
                        method_name,
                        ', '.join(param_names),
                        class_name,
                        method_name,
                        method_name,
                        ', '.join(param_names)
                    )
                    hooks.append(hook)
        
        # Save hooks to file
        with open(output_file, 'w') as f:
            f.write('\n\n'.join(hooks))
        
        print(f"[+] Generated {len(hooks)} Frida hooks in {output_file}")
        
    except Exception as e:
        print(f"[-] Error generating hooks: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python 3_generate_frida_hooks.py <signatures_file> <output_file>")
        print("Example: python 3_generate_frida_hooks.py ./signatures.txt ./frida_hooks.js")
        sys.exit(1)
    
    signatures_file = sys.argv[1]
    output_file = sys.argv[2]
    generate_hooks(signatures_file, output_file)

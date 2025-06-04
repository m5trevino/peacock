#!/usr/bin/env python3

import os
import sys
import subprocess
from pathlib import Path

def decompile_apks(input_dir, output_base_dir):
    """
    Decompile all APKs in the input directory using jadx
    """
    input_path = Path(input_dir)
    output_path = Path(output_base_dir)
    
    # Create output directory if it doesn't exist
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Find all APK files
    apk_files = list(input_path.glob("*.apk"))
    
    if not apk_files:
        print("[-] No APK files found in the input directory")
        return
    
    print(f"[*] Found {len(apk_files)} APK files")
    
    for apk_file in apk_files:
        # Create output directory for this APK
        apk_output_dir = output_path / apk_file.stem
        print(f"\n[*] Decompiling {apk_file.name} to {apk_output_dir}")
        
        try:
            subprocess.run(["jadx", "-d", str(apk_output_dir), str(apk_file)], check=True)
            print(f"[+] Successfully decompiled {apk_file.name}")
        except subprocess.CalledProcessError:
            print(f"[-] Error decompiling {apk_file.name}")
            print("    Make sure jadx is installed: https://github.com/skylot/jadx")
            continue

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python 1_decompile_apks.py <input_dir> <output_dir>")
        print("Example: python 1_decompile_apks.py ./apks ./decompiled")
        sys.exit(1)
    
    input_dir = sys.argv[1]
    output_dir = sys.argv[2]
    decompile_apks(input_dir, output_dir)
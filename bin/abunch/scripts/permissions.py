#!/usr/bin/env python3

import os
import sys
import stat
import time
from pathlib import Path

def print_permission_key():
    """Print a key explaining permission flags"""
    print("\n=== Permission Key ===")
    print("r (4) = Read permission")
    print("w (2) = Write permission")
    print("x (1) = Execute permission")
    print("\nCombinations:")
    print("7 = rwx (4+2+1)")
    print("6 = rw- (4+2)")
    print("5 = r-x (4+1)")
    print("4 = r-- (4)")
    print("3 = -wx (2+1)")
    print("2 = -w- (2)")
    print("1 = --x (1)")
    print("0 = --- (0)")

def get_path():
    """Get path from user if not provided"""
    while True:
        path = input("Enter path to file or directory (or '.' for current directory): ").strip()
        if path:
            abs_path = os.path.abspath(path)
            if os.path.exists(abs_path):
                return abs_path
            else:
                print(f"Error: Path does not exist: {abs_path}")
        else:
            print("Please enter a valid path")

def get_permission_string(mode):
    """Convert mode to string representation"""
    perms = ['---', '---', '---']
    for i in range(3):
        if mode & (4 << (i * 3)):
            perms[2 - i] = perms[2 - i][:0] + 'r' + perms[2 - i][1:]
        if mode & (2 << (i * 3)):
            perms[2 - i] = perms[2 - i][:1] + 'w' + perms[2 - i][2:]
        if mode & (1 << (i * 3)):
            perms[2 - i] = perms[2 - i][:2] + 'x' + perms[2 - i][3:]
    return ''.join(perms)

def clear_line():
    """Clear the current line in terminal"""
    sys.stdout.write('\r' + ' ' * 80 + '\r')
    sys.stdout.flush()

def apply_permissions(path):
    """Apply permissions sequence to a file or directory"""
    try:
        abs_path = os.path.abspath(path)
        
        if os.path.exists(abs_path):
            print("\nChoose display mode:")
            print("1: Show all changes at once (flood mode)")
            print("2: Show changes one by one (clean mode)")
            
            while True:
                display_mode = input("Enter your choice (1 or 2): ").strip()
                if display_mode in ['1', '2']:
                    break
                print("Please enter 1 or 2")

            print(f"\nApplying permissions to: {abs_path}")
            
            # Basic permission sequence
            print("Changing ownership...")
            os.system(f"sudo chown -R {os.getuid()}:{os.getgid()} '{abs_path}'")
            print("Removing write permissions...")
            os.system(f"sudo chmod a-w '{abs_path}'")
            print("Setting 777 permissions...")
            os.system(f"sudo chmod -R 777 '{abs_path}'")
            print("Setting rwx permissions...")
            os.system(f"sudo chmod +rwx -R '{abs_path}'")
            
            # Process and display permissions for all items
            if os.path.isdir(abs_path):
                for root, dirs, files in os.walk(abs_path):
                    for d in dirs:
                        full_path = os.path.join(root, d)
                        mode = os.stat(full_path).st_mode
                        perm_string = get_permission_string(stat.S_IMODE(mode))
                        
                        if display_mode == "1":
                            print(f"Directory: {full_path} -> {perm_string} (777)")
                        else:
                            clear_line()
                            sys.stdout.write(f"Processing: {full_path} -> {perm_string} (777)")
                            sys.stdout.flush()
                            time.sleep(0.1)
                    
                    for f in files:
                        full_path = os.path.join(root, f)
                        mode = os.stat(full_path).st_mode
                        perm_string = get_permission_string(stat.S_IMODE(mode))
                        
                        if display_mode == "1":
                            print(f"File: {full_path} -> {perm_string} (777)")
                        else:
                            clear_line()
                            sys.stdout.write(f"Processing: {full_path} -> {perm_string} (777)")
                            sys.stdout.flush()
                            time.sleep(0.1)
            else:
                mode = os.stat(abs_path).st_mode
                perm_string = get_permission_string(stat.S_IMODE(mode))
                print(f"File: {abs_path} -> {perm_string} (777)")

            if display_mode == "2":
                clear_line()
                print("Processing complete!")

            print_permission_key()
            
            # Ask about additional permissions
            while True:
                print("\nWould you like to add more specific permissions?")
                print("1: Yes")
                print("2: No")
                
                choice = input("Enter your choice (1 or 2): ").strip()
                
                if choice in ['1', '2']:
                    break
                print("Please enter 1 or 2")
            
            if choice == "1":
                print("\nAvailable permissions:")
                print("a: all (user, group, others)")
                print("u: user")
                print("g: group")
                print("o: others")
                print("r: read")
                print("w: write")
                print("x: execute")
                print("\nExample combinations:")
                print("awx: all write execute")
                print("ur: user read")
                print("gw: group write")
                print("ox: others execute")
                
                perm = input("\nEnter permissions: ").strip().lower()
                
                # Convert text permissions to octal
                mode = 0
                if 'a' in perm:
                    if 'r' in perm: mode |= 0o444
                    if 'w' in perm: mode |= 0o222
                    if 'x' in perm: mode |= 0o111
                else:
                    if 'u' in perm:
                        if 'r' in perm: mode |= 0o400
                        if 'w' in perm: mode |= 0o200
                        if 'x' in perm: mode |= 0o100
                    if 'g' in perm:
                        if 'r' in perm: mode |= 0o040
                        if 'w' in perm: mode |= 0o020
                        if 'x' in perm: mode |= 0o010
                    if 'o' in perm:
                        if 'r' in perm: mode |= 0o004
                        if 'w' in perm: mode |= 0o002
                        if 'x' in perm: mode |= 0o001
                
                if mode > 0:
                    os.chmod(abs_path, mode)
                    print(f"\nApplied additional permissions to: {abs_path}")
                    mode = os.stat(abs_path).st_mode
                    perm_string = get_permission_string(stat.S_IMODE(mode))
                    print(f"Final permissions: {perm_string}")

    except Exception as e:
        print(f"Error: {str(e)}")

def main():
    # If no path provided, ask for it
    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
        path = get_path()
    
    apply_permissions(path)

if __name__ == "__main__":
    main()
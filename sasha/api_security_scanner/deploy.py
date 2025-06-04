#!/usr/bin/env python3
"""
Deployment script for API Security Scanner
Handles different environment setups
"""

import os
import sys
import subprocess
import platform

def install_system_deps():
    """Install system dependencies"""
    system = platform.system().lower()
    
    if system == "linux":
        if os.path.exists("/etc/debian_version"):
            # Debian/Ubuntu
            subprocess.run(["sudo", "apt-get", "update"], check=False)
            subprocess.run(["sudo", "apt-get", "install", "-y", "python3-pip", "python3-venv"], check=False)
        elif os.path.exists("/etc/redhat-release"):
            # RHEL/CentOS
            subprocess.run(["sudo", "yum", "install", "-y", "python3-pip"], check=False)
    
    elif system == "darwin":
        # macOS
        if not subprocess.run(["which", "brew"], capture_output=True).returncode == 0:
            print("Please install Homebrew first: https://brew.sh")
            return False
        subprocess.run(["brew", "install", "python3"], check=False)
    
    return True

def setup_venv():
    """Set up virtual environment"""
    if not os.path.exists("venv"):
        subprocess.run([sys.executable, "-m", "venv", "venv"], check=True)
    
    # Activate and install
    if platform.system().lower() == "windows":
        pip_path = os.path.join("venv", "Scripts", "pip")
    else:
        pip_path = os.path.join("venv", "bin", "pip")
    
    subprocess.run([pip_path, "install", "--upgrade", "pip"], check=True)
    subprocess.run([pip_path, "install", "-r", "requirements.txt"], check=True)

def create_launcher():
    """Create launcher script"""
    if platform.system().lower() == "windows":
        launcher = "api-scan.bat"
        content = f"""@echo off
{os.path.join("venv", "Scripts", "python")} api_security_tool.py %*
"""
    else:
        launcher = "api-scan"
        content = f"""#!/bin/bash
{os.path.join(".", "venv", "bin", "python")} api_security_tool.py "$@"
"""
    
    with open(launcher, 'w') as f:
        f.write(content)
    
    if not platform.system().lower() == "windows":
        os.chmod(launcher, 0o755)
    
    print(f"✅ Launcher created: {launcher}")

if __name__ == "__main__":
    print("🚀 Deploying API Security Scanner...")
    
    if "--system-deps" in sys.argv:
        install_system_deps()
    
    setup_venv()
    create_launcher()
    
    print("\n✅ Deployment complete!")
    print("\nUsage:")
    if platform.system().lower() == "windows":
        print("  api-scan.bat your_file.har")
    else:
        print("  ./api-scan your_file.har")

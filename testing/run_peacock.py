#!/usr/bin/env python3
"""
Peacock Main Runner - Handles all path issues
"""
import sys
from pathlib import Path

# Add both directories to Python path
root_dir = Path(__file__).parent
sys.path.insert(0, str(root_dir / "peacock" / "apps"))
sys.path.insert(0, str(root_dir / "spark"))

def run_xedit():
    from mockup_xedit_generator import generate_enhanced_html_interface
    # Sample code for testing
    sample_code = '''struct Calculator {
    num1: f64,
    num2: f64,
}

fn main() {
    println!("Hello world");
}'''
    generate_enhanced_html_interface(sample_code, "Test Project", 1)

def run_dashboard():
    from peacock_model_dashboard import generate_model_dashboard
    generate_model_dashboard()

def run_server():
    import os
    os.chdir("spark")
    from enhanced_mcp_server import main
    main()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "xedit":
            run_xedit()
        elif sys.argv[1] == "dashboard":
            run_dashboard()
        elif sys.argv[1] == "server":
            run_server()
        else:
            print("Usage: python run_peacock.py [xedit|dashboard|server]")
    else:
        print("🦚 PEACOCK OPTIONS:")
        print("python run_peacock.py xedit      - Run XEdit interface")
        print("python run_peacock.py dashboard  - Run Model Dashboard")
        print("python run_peacock.py server     - Run MCP Server")

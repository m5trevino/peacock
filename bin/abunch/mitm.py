import subprocess
import os
import time

# Colors for output
CYAN = "\033[1;36m"
GREEN = "\033[1;32m"
PURPLE = "\033[1;35m"
YELLOW = "\033[1;33m"
RED = "\033[1;31m"
RESET = "\033[0m"

# Mitmproxy certificate directory
CERT_DIR = "/home/flintx/flow/certs/"

# Helper function to run a command
def run_command(command):
    print(f"{CYAN}Executing: {command}{RESET}")
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"{RED}Error executing command: {e}{RESET}")

# Dashboard to display mitmproxy status
def display_dashboard():
    os.system('clear')
    print(f"{PURPLE}--- MITMPROXY DASHBOARD ---{RESET}")
    mitm_status = subprocess.run(['pgrep', '-x', 'mitmproxy'], capture_output=True, text=True)
    if mitm_status.returncode == 0:
        print(f"{GREEN}Mitmproxy is running{RESET}")
    else:
        print(f"{RED}Mitmproxy is NOT running{RESET}")

    cert_files = [f for f in os.listdir(CERT_DIR) if f.endswith('.pem')]
    print(f"{YELLOW}Certificates in {CERT_DIR}:{RESET}")
    if cert_files:
        for cert in cert_files:
            print(f"- {cert}")
    else:
        print(f"{RED}No certificates found.{RESET}")
    print()

# Command to run mitmdump with hardump option
def run_mitmdump():
    save_dir = input(f"{CYAN}Enter the directory to save the HAR file: {RESET}")
    if not os.path.isdir(save_dir):
        print(f"{RED}Invalid directory. Please try again.{RESET}")
        return
    command = f"mitmdump --set hardump={os.path.join(save_dir, 'dump.har')}"
    run_command(command)

# Menu to display common mitmproxy commands
def mitmproxy_menu():
    while True:
        display_dashboard()
        print(f"{YELLOW}--- MITMPROXY MENU ---{RESET}")
        print("1. Start Mitmproxy")
        print("2. Start Mitmdump with HAR output")
        print("3. Start Mitmweb")
        print("4. View Certificates")
        print("5. Exit")

        choice = input(f"{CYAN}Select an option: {RESET}")
        if choice == '1':
            run_command("mitmproxy")
        elif choice == '2':
            run_mitmdump()
        elif choice == '3':
            run_command("mitmweb")
        elif choice == '4':
            cert_files = [f for f in os.listdir(CERT_DIR) if f.endswith('.pem')]
            if cert_files:
                print(f"{CYAN}Certificates found:{RESET}")
                for cert in cert_files:
                    print(f"- {cert}")
            else:
                print(f"{RED}No certificates found.{RESET}")
            input(f"{CYAN}Press Enter to continue...{RESET}")
        elif choice == '5':
            print(f"{GREEN}Exiting Mitmproxy menu...{RESET}")
            break
        else:
            print(f"{RED}Invalid choice. Try again.{RESET}")
        time.sleep(2)

if __name__ == "__main__":
    mitmproxy_menu()

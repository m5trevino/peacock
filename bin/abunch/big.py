import os
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import pandas as pd
from pathlib import Path
import webbrowser
import subprocess
import psutil

# Directory management
BASE_DIR = Path("/home/flintx/flow/java2html")

# Initialize main window
window = tk.Tk()
window.title("APK Analyzer & Security Scanner")
window.geometry("820x460")
window.configure(bg="#1A1A2E")

# GUI variables
apk_path_var = tk.StringVar()
app_name_var = tk.StringVar()
status_var = tk.StringVar(value="Idle")
decompile_speed = tk.IntVar(value=100)
class_count_var = tk.IntVar(value=0)
method_count_var = tk.IntVar(value=0)
no_method_count_var = tk.IntVar(value=0)
current_script_file = None

def select_apk():
    """Select an APK file and ask for a folder name."""
    apk_file = filedialog.askopenfilename(filetypes=[("APK Files", "*.apk")])
    if apk_file:
        apk_path_var.set(apk_file)
        folder_name = simpledialog.askstring("App Folder Name", "Enter a folder name for the app:")
        if folder_name:
            folder_name = folder_name.strip().lower().replace(" ", "_")
            app_name_var.set(folder_name)
            log_text.insert(tk.END, f"[+] Loaded APK: {apk_file}\n", "success")
        else:
            messagebox.showerror("Error", "Folder name is required!")

def get_app_dir():
    """Generate and return the app directory based on the provided app name."""
    app_name = app_name_var.get().strip().lower().replace(" ", "_")
    if not app_name:
        app_name = "default_app"
    app_dir = BASE_DIR / app_name
    app_dir.mkdir(parents=True, exist_ok=True)
    return app_dir

def update_resource_monitor():
    """Update CPU and memory usage in the status labels."""
    while True:
        cpu_usage = psutil.cpu_percent(interval=0.5)
        mem_usage = psutil.virtual_memory().percent
        cpu_label.config(text=f"CPU: {cpu_usage}%")
        mem_label.config(text=f"MEM: {mem_usage}%")
        time.sleep(0.5)

def decompile_apk():
    """Decompile the APK and display progress."""
    apk_file = apk_path_var.get().strip()
    if not apk_file:
        messagebox.showerror("Error", "Please select an APK file.")
        return

    app_dir = get_app_dir()
    output_sources_dir = app_dir / "sources"

    def run_decompile():
        try:
            log_text.insert(tk.END, f"[*] Decompiling {apk_file}...\n", "log")
            cmd = ["jadx", "-d", str(output_sources_dir), apk_file]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            while True:
                output = process.stdout.readline()
                if output:
                    log_text.insert(tk.END, output, "log")
                    log_text.see(tk.END)
                if process.poll() is not None:
                    break
                time.sleep((100 - decompile_speed.get()) / 100)

            log_text.insert(tk.END, "[+] Decompilation completed.\n", "success")
        except Exception as e:
            log_text.insert(tk.END, f"[-] Error during decompilation: {e}\n", "error")

    threading.Thread(target=run_decompile).start()

def check_missing_files():
    """Check for apps that have been decompiled but are missing CSV or JS files."""
    missing_apps = []
    for app_dir in BASE_DIR.iterdir():
        if app_dir.is_dir():
            csv_file = app_dir / f"{app_dir.name}.csv"
            js_file = app_dir / f"{app_dir.name}.js"
            if not csv_file.exists() or not js_file.exists():
                missing_apps.append(app_dir.name)
    return missing_apps

def generate_csv_html_frida():
    """Generate CSV, HTML, and Frida script from decompiled data."""
    apk_file = apk_path_var.get().strip()
    if not apk_file:
        missing_apps = check_missing_files()
        if missing_apps:
            app_choice = simpledialog.askstring("Select App", f"Choose from the following apps:\n{', '.join(missing_apps)}")
            if app_choice:
                app_name_var.set(app_choice.strip().lower().replace(" ", "_"))
            else:
                messagebox.showerror("Error", "Please select an app or load an APK.")
                return
        else:
            messagebox.showerror("Error", "No decompiled apps found.")
            return

    app_dir = get_app_dir()
    csv_file = app_dir / f"{app_dir.name}.csv"
    html_file = app_dir / f"{app_dir.name}.html"
    global current_script_file
    current_script_file = app_dir / f"{app_dir.name}.js"

    try:
        # Mock data (replace with real data extraction)
        classes = [f"com.example.Class{i}" for i in range(100)]
        methods = [f"method{i}()" for i in range(100)]

        class_count_var.set(len(classes))
        method_count_var.set(sum(1 for m in methods if m))
        no_method_count_var.set(sum(1 for m in methods if not m.strip()))

        # Generate CSV
        df = pd.DataFrame({"class": classes, "methods": methods})
        df.to_csv(csv_file, index=False)
        log_text.insert(tk.END, f"[+] CSV generated at: {csv_file}\n", "success")

        # Generate HTML
        html_content = df.to_html()
        with open(html_file, "w") as f:
            f.write(html_content)
        log_text.insert(tk.END, f"[+] HTML generated at: {html_file}\n", "success")

        # Generate Frida script
        frida_script = f"""
        Java.perform(function() {{
            console.log("[*] Starting Frida script for {app_dir.stem}...");
            var ExampleClass = Java.use("com.example.Class0");
            ExampleClass.method0.implementation = function() {{
                console.log("[+] Hooked method0");
                return this.method0();
            }};
        }});
        """
        with open(current_script_file, "w") as f:
            f.write(frida_script)
        
        # Load script into editor
        script_editor.delete("1.0", tk.END)
        script_editor.insert("1.0", frida_script)

        log_text.insert(tk.END, f"[+] Frida script generated at: {current_script_file}\n", "success")
    except Exception as e:
        log_text.insert(tk.END, f"[-] Error generating files: {e}\n", "error")

def save_script():
    """Save the contents of the script editor."""
    if not current_script_file:
        messagebox.showerror("Error", "No script file to save.")
        return

    with open(current_script_file, "w") as f:
        f.write(script_editor.get("1.0", tk.END).strip())

    log_text.insert(tk.END, f"[+] Script saved to {current_script_file}\n", "success")
    messagebox.showinfo("Success", "Script saved successfully.")

# GUI Layout

# Labels, sliders, and buttons
tk.Label(window, text="FRIDA SCRIPT EDITOR", font=("Arial", 10, "bold"), fg="#00FF41", bg="#1A1A2E").place(x=10, y=8)
tk.Scale(window, from_=5, to=100, orient="horizontal", variable=decompile_speed, bg="#1A1A2E", fg="#00FF41", length=160).place(x=501, y=20)
cpu_label = tk.Label(window, text="CPU: 0%", font=("Arial", 10), fg="#00FF41", bg="#1A1A2E")
cpu_label.place(x=667, y=18)
mem_label = tk.Label(window, text="MEM: 0%", font=("Arial", 10), fg="#00FF41", bg="#1A1A2E")
mem_label.place(x=667, y=42)

tk.Button(window, text="Load APK", command=select_apk, bg="#3D348B", fg="#00FF41").place(x=395, y=55)
tk.Button(window, text="Decompile APK", command=decompile_apk, bg="#3D348B", fg="#00FF41").place(x=395, y=130)
tk.Button(window, text="Build CSV & JS", command=generate_csv_html_frida, bg="#3D348B", fg="#00FF41").place(x=395, y=225)
tk.Button(window, text="Save Script", command=save_script, bg="#3D348B", fg="#00FF41").place(x=220, y=8)

script_editor = tk.Text(window, height=20, width=46, bg="#000000", fg="#00FF41", bd=2, relief="ridge")
script_editor.place(x=10, y=40)
log_text = tk.Text(window, height=15, width=36, bg="#000000", fg="#00FF41", bd=2, relief="ridge")
log_text.place(x=501, y=66)

log_text.tag_config("log", foreground="#00FF41")
log_text.tag_config("success", foreground="#00FF41", font=("Arial", 10, "bold"))
log_text.tag_config("error", foreground="#FF3131", font=("Arial", 10, "bold"))

# Start monitoring system resources
threading.Thread(target=update_resource_monitor, daemon=True).start()

window.mainloop()

import os
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox
import pandas as pd
from pathlib import Path
import webbrowser
import subprocess
import psutil

# Directory management
BASE_DIR = Path("/home/flintx/flow/java2html")

# Initialize main window
window = tk.Tk()
window.title("APK Analyzer & Script Builder")
window.geometry("806x400")
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
    """Select an APK file."""
    apk_file = filedialog.askopenfilename(filetypes=[("APK Files", "*.apk")])
    if apk_file:
        apk_path_var.set(apk_file)

def get_app_dir():
    """Generate and return the app directory based on the user's input."""
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

            # Stream process output
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

def generate_csv_html_frida():
    """Generate CSV, HTML, and Frida script from decompiled data."""
    apk_file = apk_path_var.get().strip()
    if not apk_file:
        messagebox.showerror("Error", "Please select an APK file.")
        return

    app_dir = get_app_dir()
    csv_file = app_dir / "app.csv"
    html_file = app_dir / "app.html"
    global current_script_file
    current_script_file = app_dir / "app.js"

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

def generate_databank_html(file_type):
    """Generate an HTML databank page listing all available files of the given type."""
    if file_type == "html":
        file_extension = "*.html"
        title = "HTML Databank"
    elif file_type == "js":
        file_extension = "*.js"
        title = "Frida Script Databank"

    all_files = list(BASE_DIR.rglob(file_extension))

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head><title>{title}</title></head>
    <body>
        <h1>{title}</h1>
        <ul>
    """
    for file in all_files:
        file_path = file.resolve()
        html_content += f'<li><a href="file://{file_path}" target="_blank">{file_path.name}</a></li>'

    html_content += """
        </ul>
    </body>
    </html>
    """

    databank_file = BASE_DIR / f"{file_type}_databank.html"
    with open(databank_file, "w") as f:
        f.write(html_content)

    webbrowser.open(f"file://{databank_file}")

def open_html_databank():
    """Open the HTML databank."""
    generate_databank_html("html")

def open_frida_script_databank():
    """Open the Frida script databank."""
    generate_databank_html("js")

# GUI Layout

# Labels and slider
tk.Label(window, text="FRIDA SCRIPT EDITOR", font=("Arial", 10, "bold"), fg="#00FF41", bg="#1A1A2E").place(x=10, y=8)
tk.Label(window, text="Decompile Speed", font=("Arial", 9), fg="#00FF41", bg="#1A1A2E").place(x=501, y=5)
tk.Scale(window, from_=5, to=100, orient="horizontal", variable=decompile_speed, bg="#1A1A2E", fg="#00FF41", length=160).place(x=501, y=20)

# Resource labels
cpu_label = tk.Label(window, text="CPU: 0%", font=("Arial", 10), fg="#00FF41", bg="#1A1A2E")
cpu_label.place(x=667, y=18)
mem_label = tk.Label(window, text="MEM: 0%", font=("Arial", 10), fg="#00FF41", bg="#1A1A2E")
mem_label.place(x=667 , y=42)

# Buttons
tk.Button(window, text="Load APK", font=("Arial", 8), command=select_apk, bg="#3D348B", fg="#00FF41").place(x=395, y=55)
tk.Button(window, text="Decompile APK", font=("Arial", 8), command=decompile_apk, bg="#3D348B", fg="#00FF41").place(x=395, y=130)
tk.Button(window, text="Build CSV & JS", font=("Arial", 8), command=generate_csv_html_frida, bg="#3D348B", fg="#00FF41").place(x=395, y=225)
tk.Button(window, text="Save Script", font=("Arial", 8), command=save_script, bg="#3D348B", fg="#00FF41").place(x=220, y=8)

# Databank buttons
tk.Button(window, text="HTML DATABANK", font=("Arial", 8), command=open_html_databank, bg="#3D348B", fg="#00FF41").place(x=650, y=336)
tk.Button(window, text="FRIDA SCRIPT DATABANK", font=("Arial", 8), command=open_frida_script_databank, bg="#3D348B", fg="#00FF41").place(x=650, y=366)

# Script editor and log window with green borders
script_editor = tk.Text(window, height=20, width=46, bg="#000000", fg="#00FF41", insertbackground="#00FF41", bd=2, relief="ridge", highlightbackground="#00FF41", highlightcolor="#00FF41")
script_editor.place(x=10, y=40)

log_text = tk.Text(window, height=15, width=36, bg="#000000", fg="#00FF41", insertbackground="#00FF41", bd=2, relief="ridge", highlightbackground="#00FF41", highlightcolor="#00FF41")
log_text.place(x=501, y=66)

# Log text tags
log_text.tag_config("log", foreground="#00FF41")
log_text.tag_config("success", foreground="#00FF41", font=("Arial", 10, "bold"))
log_text.tag_config("error", foreground="#FF3131", font=("Arial", 10, "bold"))

# Start resource monitoring
threading.Thread(target=update_resource_monitor, daemon=True).start()

# Run the main loop
window.mainloop()

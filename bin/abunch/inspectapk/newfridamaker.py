import pandas as pd
import os

def generate_frida_script():
    # Prompt for CSV file path
    csv_file = input("Enter the path to the class-method CSV file: ").strip()

    # Check if CSV file exists
    if not os.path.isfile(csv_file):
        print(f"[-] Error: CSV file '{csv_file}' not found!")
        return

    # Prompt for output Frida script path & filename
    output_frida_script = input("Enter the output Frida script path & filename (e.g., /path/to/frida.js): ").strip()

    # Load class and method data
    try:
        df = pd.read_csv(csv_file)
    except Exception as e:
        print(f"[-] Error reading CSV file: {e}")
        return

    # Ensure the required columns exist
    if 'class' not in df.columns or 'methods' not in df.columns:
        print("[-] Error: CSV file must have 'class' and 'methods' columns!")
        return

    # Script Header
    frida_script = """setTimeout(function() {
    Java.perform(function() {
        console.log('[*] Starting Frida script...');
"""

    # Track hooked classes to prevent duplicate hooks
    hooked_classes = set()

    for _, row in df.iterrows():
        class_name = str(row['class']).strip()
        methods = str(row['methods']).strip()

        # Validate class name
        if not class_name or class_name.lower() == 'nan':
            print(f"[-] Skipping invalid class entry: {class_name}")
            continue

        safe_class_var = class_name.replace(".", "_")

        # Hook the class if not already hooked
        if class_name not in hooked_classes:
            frida_script += f"""
        try {{
            var {safe_class_var} = Java.use('{class_name}');
            console.log('[+] Hooked class: {class_name}');
        }} catch (err) {{
            console.log('[-] Failed to hook {class_name}: ' + err);
        }}
"""
            hooked_classes.add(class_name)

        # Hook methods if available
        if methods.lower() != "no method extracted":
            method_list = methods.split("; ")

            for method in method_list:
                method_cleaned = method.split('(')[0].strip()  # Extract method name

                if method_cleaned:
                    frida_script += f"""
        try {{
            if ({safe_class_var}.{method_cleaned} !== undefined) {{
                {safe_class_var}.{method_cleaned}.implementation = function() {{
                    console.log('[+] Hooked {class_name}.{method_cleaned}');
                    return this.{method_cleaned}.apply(this, arguments);
                }};
            }} else {{
                console.log('[-] Method {method_cleaned} does not exist in {class_name}');
            }}
        }} catch (err) {{
            console.log('[-] Failed to hook {class_name}.{method_cleaned}: ' + err);
        }}
"""

    # Add Security Bypass Implementations
    frida_script += """
        console.log('[*] Hooking Complete! Implementing security bypasses...');

        // SSL Pinning Bypass
        try {
            var array_list = Java.use("java.util.ArrayList");
            var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            if (TrustManagerImpl) {
                TrustManagerImpl.checkTrustedRecursive.implementation = function() {
                    console.log('[+] Bypassing SSL Pinning');
                    return array_list.$new();
                };
            }
        } catch (e) {
            console.log('[-] SSL Pinning bypass failed: ' + e);
        }

        // Root Detection Bypass
        try {
            var File = Java.use('java.io.File');
            File.exists.implementation = function() {
                var fileName = this.getAbsolutePath();
                if (fileName.indexOf('su') > -1 || fileName.indexOf('magisk') > -1) {
                    console.log('[+] Root check bypassed for: ' + fileName);
                    return false;
                }
                return this.exists.call(this);
            };
        } catch (err) {
            console.log('[-] Root detection bypass failed: ' + err);
        }

        // WebView SSL Error Bypass
        try {
            var WebViewClient = Java.use('android.webkit.WebViewClient');
            WebViewClient.onReceivedSslError.implementation = function(webView, sslErrorHandler, sslError) {
                console.log('[+] WebView SSL error bypassed');
                sslErrorHandler.proceed();
                return;
            };
        } catch (err) {
            console.log('[-] WebView bypass failed: ' + err);
        }

        // Debugging Detection Bypass
        try {
            var Debug = Java.use('android.os.Debug');
            Debug.isDebuggerConnected.implementation = function() {
                console.log('[+] Debugging detection bypassed');
                return false;
            };
        } catch (err) {
            console.log('[-] Debugging detection bypass failed: ' + err);
        }

        console.log('[*] Frida script execution complete.');
    });
}, 0);
"""

    # Save the generated script to the output file
    try:
        with open(output_frida_script, "w") as f:
            f.write(frida_script)
        print(f"[+] Frida script saved to {output_frida_script}")
    except Exception as e:
        print(f"[-] Error saving Frida script: {e}")

# Run the script generation
if __name__ == "__main__":
    generate_frida_script()

import pandas as pd
import os

def generate_frida_script():
    # Prompt for CSV file
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

    # Ensure columns exist
    if 'class' not in df.columns or 'methods' not in df.columns:
        print("[-] Error: CSV file must have 'class' and 'methods' columns!")
        return

    # Define important security-related classes/methods
    security_classes = {
        "SSL": ["TrustManagerImpl", "CertificatePinner", "X509TrustManager", "SSLContext"],
        "RootDetection": ["java.io.File"],
        "WebView": ["android.webkit.WebViewClient"],
        "DebugDetection": ["android.os.Debug"],
        "NetworkSecurity": ["android.security.net.config.NetworkSecurityConfig"]
    }

    frida_script = """setTimeout(function() {
    Java.perform(function() {
        console.log('[*] Starting Security Bypass Script...');
"""

    for _, row in df.iterrows():
        class_name = str(row['class']).strip()
        methods = str(row['methods']).strip()

        # Identify which security category the class belongs to
        category = None
        for sec_type, class_list in security_classes.items():
            if any(c in class_name for c in class_list):
                category = sec_type
                break

        if not category:
            continue  # Skip irrelevant classes

        safe_class_var = class_name.replace(".", "_")

        frida_script += f"""
        try {{
            var {safe_class_var} = Java.use('{class_name}');
            console.log('[+] Hooked class: {class_name}');
        }} catch (err) {{
            console.log('[-] Failed to hook {class_name}: ' + err);
        }}
"""

        # Hook security-related methods
        if category == "SSL":
            frida_script += f"""
        try {{
            if ({safe_class_var}.checkTrustedRecursive !== undefined) {{
                {safe_class_var}.checkTrustedRecursive.implementation = function() {{
                    console.log('[+] Bypassing SSL Pinning for {class_name}');
                    return [];
                }};
            }}
        }} catch (err) {{
            console.log('[-] Failed to bypass SSL Pinning: ' + err);
        }}
"""
        elif category == "RootDetection":
            frida_script += f"""
        try {{
            {safe_class_var}.exists.implementation = function() {{
                var fileName = this.getAbsolutePath();
                if (fileName.indexOf('su') > -1 || fileName.indexOf('magisk') > -1 || fileName.indexOf('xposed') > -1) {{
                    console.log('[+] Root detection bypassed for: ' + fileName);
                    return false;
                }}
                return this.exists.call(this);
            }};
        }} catch (err) {{
            console.log('[-] Root detection bypass failed: ' + err);
        }}
"""
        elif category == "WebView":
            frida_script += f"""
        try {{
            {safe_class_var}.onReceivedSslError.implementation = function(webView, sslErrorHandler, sslError) {{
                console.log('[+] WebView SSL bypassed');
                sslErrorHandler.proceed();
            }};
        }} catch (err) {{
            console.log('[-] WebView SSL bypass failed: ' + err);
        }}
"""
        elif category == "DebugDetection":
            frida_script += f"""
        try {{
            {safe_class_var}.isDebuggerConnected.implementation = function() {{
                console.log('[+] Debugging detection bypassed');
                return false;
            }};
        }} catch (err) {{
            console.log('[-] Debugging detection bypass failed: ' + err);
        }}
"""
        elif category == "NetworkSecurity":
            frida_script += f"""
        try {{
            {safe_class_var}.isCleartextTrafficPermitted.implementation = function() {{
                console.log('[+] Allowing cleartext traffic');
                return true;
            }};
        }} catch (err) {{
            console.log('[-] Network security bypass failed: ' + err);
        }}
"""

    frida_script += """
        console.log('[*] Security bypasses complete.');
    });
}, 0);
"""

    # Save the script
    try:
        with open(output_frida_script, "w") as f:
            f.write(frida_script)
        print(f"[+] Frida script saved to {output_frida_script}")
    except Exception as e:
        print(f"[-] Error saving Frida script: {e}")

# Run the script generation
if __name__ == "__main__":
    generate_frida_script()

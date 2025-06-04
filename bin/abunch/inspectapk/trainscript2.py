#!/usr/bin/env python3

import os
import re
import pandas as pd
import json

def extract_signatures_to_combined(decompiled_dir, output_combined_file):
    """
    Extract class and method signatures from decompiled Java files and save them in a single CSV file.
    If a class has no methods, it will add "no method extracted".
    """
    print(f"[*] Analyzing decompiled files in {decompiled_dir}")
    
    combined_data = []
    no_method_count = 0
    total_classes = 0
    total_methods = 0

    # Process each decompiled APK directory
    for apk_dir in os.scandir(decompiled_dir):
        if not apk_dir.is_dir():
            continue

        print(f"\n[*] Processing {apk_dir.name}")

        # Find all Java files recursively
        for root, _, files in os.walk(apk_dir.path):
            for file in files:
                if file.endswith(".java"):
                    java_file = os.path.join(root, file)
                    try:
                        with open(java_file, 'r', encoding='utf-8') as f:
                            content = f.read()

                            # Extract class name
                            class_match = re.search(r'class (\w+)', content)
                            if not class_match:
                                continue

                            class_name = class_match.group(1)
                            total_classes += 1

                            # Extract method signatures
                            methods = re.finditer(
                                r'(?:public|private|protected|\s)?[\w\<\>\[\]]+\s+(\w+)\s*\([^\)]*\)\s*'
                                r'(?:throws\s+[\w\s,]+)?\s*(?:;|{)',
                                content
                            )
                            method_list = [m.group(0) for m in methods]

                            # Add to combined data
                            if method_list:
                                combined_data.append({
                                    'class': class_name,
                                    'methods': '; '.join(method_list)  # Join methods with semicolon
                                })
                                total_methods += len(method_list)
                            else:
                                combined_data.append({
                                    'class': class_name,
                                    'methods': 'no method extracted'  # Add placeholder for no methods
                                })
                                no_method_count += 1

                    except Exception as e:
                        print(f"[-] Error processing {java_file}: {str(e)}")
                        continue

    # Create DataFrame for combined data
    combined_data_df = pd.DataFrame(combined_data)

    # Save combined data to CSV
    combined_data_df.to_csv(output_combined_file, index=False)
    print(f"[+] Combined data saved to {output_combined_file}")
    print(f"Total classes processed: {total_classes}")
    print(f"Total methods extracted: {total_methods}")
    print(f"Total classes with no methods: {no_method_count}")


def generate_training_and_frida(preprocessed_csv, training_jsonl, frida_script):
    """
    Generate optional training dataset in JSONL format and a universal Frida script
    to bypass app security features.
    """
    print(f"[*] Loading preprocessed data from: {preprocessed_csv}")
    try:
        df = pd.read_csv(preprocessed_csv)
        
        # --------------------------------------------------------------------
        # 1) (Optional) Build some training data from CSV if you still want it:
        # --------------------------------------------------------------------
        training_data = []

        # Example of building training data from the CSV
        for _, row in df.iterrows():
            class_name = row['class']
            methods = row['methods']
            # Add generic input/output for training if you like
            # This is arbitrary — customize as desired
            training_data.append({
                "input": f"Explain how to bypass security checks in class {class_name} with methods {methods}",
                "output": "Use a universal hooking approach that overrides known security-check classes."
            })

        # Write training data as JSONL if desired
        with open(training_jsonl, 'w') as jsonl_file:
            for entry in training_data:
                jsonl_file.write(json.dumps(entry) + '\n')
        print(f"[+] Training dataset saved to {training_jsonl}")

        # --------------------------------------------------------------------
        # 2) Generate a universal Frida script (like the one that worked)
        #    We IGNORE the CSV's method info for hooking, and just output a
        #    time-tested universal snippet.
        # --------------------------------------------------------------------
        universal_frida_script = r"""setTimeout(function() {
    Java.perform(function() {
        console.log('[*] Starting SSL pinning bypass...');

        // Universal SSL Pinning Bypass
        try {
            var array_list = Java.use("java.util.ArrayList");
            var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            if (ApiClient) {
                ApiClient.checkTrustedRecursive.implementation = function(a1, a2, a3, a4, a5, a6) {
                    console.log('[+] Bypassing SSL Pinning');
                    var k = array_list.$new();
                    return k;
                };
            }
        } catch(e) {
            console.log('[-] TrustManagerImpl bypass failed: ' + e);
        }

        // OkHttp3 Pinning Bypass
        try {
            var CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, certificates) {
                console.log('[+] OkHttp3 check() called with ' + hostname);
                return;
            };
            CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(hostname, certificates) {
                console.log('[+] OkHttp3 check() called with ' + hostname);
                return;
            };
            console.log('[+] OkHttp3 pinning bypassed');
        } catch(err) {
            console.log('[-] OkHttp3 pinning bypass failed: ' + err);
        }

        // Trustkit Pinning Bypass
        try {
            var TrustKit = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
            TrustKit.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(hostname, session) {
                console.log('[+] Trustkit verify() called with ' + hostname);
                return true;
            };
            console.log('[+] Trustkit pinning bypassed');
        } catch(err) {
            console.log('[-] Trustkit pinning bypass failed: ' + err);
        }

        // Custom SSL Implementation
        try {
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var SSLContext = Java.use('javax.net.ssl.SSLContext');
            
            var TrustManager = Java.registerClass({
                name: 'com.temp.CustomTrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() { return []; }
                }
            });

            var TrustManagers = [TrustManager.$new()];
            var context = SSLContext.getInstance('TLS');
            context.init(null, TrustManagers, null);

            var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
            HttpsURLConnection.setDefaultSSLSocketFactory.implementation = function(factory) {
                console.log('[+] Setting default SSL socket factory');
                HttpsURLConnection.setDefaultSSLSocketFactory.call(this, context.getSocketFactory());
            };
            console.log('[+] Custom SSL implementation complete');
        } catch(err) {
            console.log('[-] Custom SSL implementation failed: ' + err);
        }

        // WebView SSL Bypass
        try {
            var WebViewClient = Java.use('android.webkit.WebViewClient');
            WebViewClient.onReceivedSslError.implementation = function(webView, sslErrorHandler, sslError) {
                console.log('[+] WebViewClient SSL error bypassed');
                sslErrorHandler.proceed();
                return;
            };
        } catch(err) {
            console.log('[-] WebViewClient SSL bypass failed: ' + err);
        }

        // Root Detection Bypass
        try {
            var File = Java.use('java.io.File');
            File.exists.implementation = function() {
                var fileName = this.getAbsolutePath();
                if (fileName.indexOf('su') > -1 || 
                    fileName.indexOf('magisk') > -1 || 
                    fileName.indexOf('supersu') > -1 || 
                    fileName.indexOf('xposed') > -1) {
                    console.log('[+] Root check bypassed for: ' + fileName);
                    return false;
                }
                return this.exists.call(this);
            };
        } catch(err) {
            console.log('[-] Root detection bypass failed: ' + err);
        }

        // Network Security Config Bypass
        try {
            var NetworkSecurityConfig = Java.use('android.security.net.config.NetworkSecurityConfig');
            NetworkSecurityConfig.isCleartextTrafficPermitted.implementation = function() {
                console.log('[+] Allowing cleartext traffic');
                return true;
            };
        } catch(err) {
            console.log('[-] Network security config bypass failed: ' + err);
        }

        console.log('[*] SSL pinning and security bypasses complete');
    });
}, 0);
"""

        # 3) Write the universal Frida script to file
        with open(frida_script, 'w') as script_file:
            script_file.write(universal_frida_script)
        print(f"[+] Universal Frida script saved to {frida_script}")

    except Exception as e:
        print(f"[-] Error during dataset and script generation: {str(e)}")


if __name__ == "__main__":
    # Prompt for input type
    choice = input("Do you want to process a decompiled directory (1) or use an existing CSV (2)? Enter 1 or 2: ").strip()

    if choice == '1':
        # Process decompiled directory
        decompiled_dir = input("Enter the path to the directory containing the decompiled APK files: ").strip()

        if not os.path.isdir(decompiled_dir):
            print(f"[-] Error: {decompiled_dir} is not a valid directory.")
            exit(1)

        # Use the directory name to create filenames
        dir_name = os.path.basename(os.path.normpath(decompiled_dir))
        combined_csv = f"{dir_name}_combined.csv"
        training_jsonl = f"{dir_name}_training.jsonl"
        frida_script = f"{dir_name}_frida.js"

        # Run extraction and preprocessing
        extract_signatures_to_combined(decompiled_dir, combined_csv)

        # Generate universal Frida script (and optional training data)
        generate_training_and_frida(combined_csv, training_jsonl, frida_script)

    elif choice == '2':
        # Use existing CSV
        preprocessed_csv = input("Enter the path to the preprocessed CSV file: ").strip()

        if not os.path.isfile(preprocessed_csv):
            print(f"[-] Error: {preprocessed_csv} is not a valid file.")
            exit(1)

        # Use the CSV filename to create output filenames
        base_name = os.path.splitext(os.path.basename(preprocessed_csv))[0]
        training_jsonl = f"{base_name}_training.jsonl"
        frida_script = f"{base_name}_frida.js"

        # Generate universal Frida script (and optional training data)
        generate_training_and_frida(preprocessed_csv, training_jsonl, frida_script)

    else:
        print("[-] Invalid choice. Please enter 1 or 2.")
        exit(1)

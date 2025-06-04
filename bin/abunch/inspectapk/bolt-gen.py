#!/usr/bin/env python3

import pandas as pd
import os
import re

def generate_frida_script():
    # Prompt for CSV file
    csv_file = input("Enter the path to the class-method CSV file: ").strip()

    if not os.path.isfile(csv_file):
        print(f"[-] Error: CSV file '{csv_file}' not found!")
        return

    output_frida_script = input("Enter the output Frida script path & filename (e.g., /path/to/frida.js): ").strip()

    try:
        df = pd.read_csv(csv_file)
        if 'class' not in df.columns or 'methods' not in df.columns:
            print("[-] Error: CSV file must have 'class' and 'methods' columns!")
            return
    except Exception as e:
        print(f"[-] Error reading CSV file: {e}")
        return

    # Generate comprehensive Frida script with proper formatting
    frida_script = """Java.perform(function() {
    console.log('[*] Starting comprehensive security bypass...');

    // Universal SSL/TLS Bypass
    try {
        var array_list = Java.use("java.util.ArrayList");
        var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        
        if (ApiClient) {
            ApiClient.checkTrustedRecursive.implementation = function(a1, a2, a3, a4, a5, a6) {
                console.log('[+] Bypassing SSL/TLS check');
                return array_list.$new();
            };
        }

        // Create universal trust manager
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        
        var TrustManager = Java.registerClass({
            name: 'com.custom.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });

        // Apply custom trust manager
        var TrustManagers = [TrustManager.$new()];
        var SSLContext_inst = SSLContext.getInstance('TLS');
        SSLContext_inst.init(null, TrustManagers, null);

        var SSLContext_static = Java.use('javax.net.ssl.SSLContext');
        SSLContext_static.setDefault.implementation = function(context) {
            console.log('[+] Setting default SSL context');
            SSLContext_static.setDefault.call(this, SSLContext_inst);
        };

        // Bypass hostname verifier
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var AllowAllVerifier = Java.registerClass({
            name: 'com.custom.AllowAllVerifier',
            implements: [HostnameVerifier],
            methods: {
                verify: function(hostname, session) {
                    console.log('[+] Bypassing hostname verification for: ' + hostname);
                    return true;
                }
            }
        });

        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
            console.log('[+] Setting default hostname verifier');
            HttpsURLConnection.setDefaultHostnameVerifier.call(this, AllowAllVerifier.$new());
        };
        
        HttpsURLConnection.setSSLSocketFactory.implementation = function(SSLSocketFactory) {
            console.log('[+] Setting custom SSL socket factory');
            HttpsURLConnection.setSSLSocketFactory.call(this, SSLContext_inst.getSocketFactory());
        };

    } catch (err) {
        console.log('[-] SSL/TLS bypass error: ' + err);
    }

    // Enhanced WebView SSL Error Bypass
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        var WebView = Java.use('android.webkit.WebView');
        
        // Handle all SSL errors
        WebViewClient.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function(webView, handler, error) {
            console.log('[+] WebView SSL error bypassed');
            handler.proceed();
        };

        // Handle all general errors
        WebViewClient.onReceivedError.overload('android.webkit.WebView', 'int', 'java.lang.String', 'java.lang.String').implementation = function(webView, errorCode, description, failingUrl) {
            console.log('[+] WebView error bypassed: ' + description);
        };

        // Enable WebView debugging
        WebView.setWebContentsDebuggingEnabled.implementation = function(enabled) {
            console.log('[+] Enabling WebView debugging');
            this.setWebContentsDebuggingEnabled.call(this, true);
        };

        // Set WebView client settings
        var WebSettings = Java.use('android.webkit.WebSettings');
        WebView.getSettings.implementation = function() {
            var settings = this.getSettings.call(this);
            settings.setJavaScriptEnabled(true);
            settings.setDomStorageEnabled(true);
            settings.setAllowFileAccess(true);
            settings.setAllowContentAccess(true);
            settings.setAllowFileAccessFromFileURLs(true);
            settings.setAllowUniversalAccessFromFileURLs(true);
            settings.setMixedContentMode(0);  // MIXED_CONTENT_ALWAYS_ALLOW
            console.log('[+] WebView settings optimized');
            return settings;
        };

    } catch (err) {
        console.log('[-] WebView bypass error: ' + err);
    }

    // Root Detection Bypass
    try {
        var File = Java.use('java.io.File');
        
        File.exists.implementation = function() {
            var fileName = this.getAbsolutePath();
            var banned = ['/su', '/magisk', '/supersu', '/Superuser.apk', '/xposed', '/substrate'];
            
            if (banned.some(function(path) { 
                return fileName.toLowerCase().indexOf(path.toLowerCase()) > -1;
            })) {
                console.log('[+] Root check bypassed: ' + fileName);
                return false;
            }
            return this.exists.call(this);
        };

        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
            if (cmd.indexOf('which su') !== -1 || cmd.indexOf('getprop') !== -1) {
                console.log('[+] Runtime.exec root check bypassed');
                return null;
            }
            return this.exec.call(this, cmd);
        };
    } catch (err) {
        console.log('[-] Root detection bypass error: ' + err);
    }

    // Network Security Bypass
    try {
        var NetworkSecurityConfig = Java.use('android.security.net.config.NetworkSecurityConfig');
        NetworkSecurityConfig.isCleartextTrafficPermitted.implementation = function() {
            console.log('[+] Allowing cleartext traffic');
            return true;
        };
    } catch (err) {
        console.log('[-] Network security bypass error: ' + err);
    }

    console.log('[*] All security bypasses completed');
});"""

    try:
        with open(output_frida_script, "w") as f:
            f.write(frida_script)
        print(f"[+] Enhanced Frida script saved to {output_frida_script}")
    except Exception as e:
        print(f"[-] Error saving Frida script: {e}")

if __name__ == "__main__":
    generate_frida_script()
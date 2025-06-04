#!/usr/bin/env python3

import os
import re
import json
import pandas as pd
from typing import List, Dict

class AndroidSecurityAnalyzer:
    def __init__(self):
        self.security_patterns = {
            'ssl_pinning': r'CertificatePinner|X509TrustManager|SSLContext',
            'root_detection': r'\.exists\(\)|\.isFile\(\)|/su|/magisk|/supersu',
            'webview_security': r'WebViewClient|onReceivedSslError',
            'network_security': r'NetworkSecurityConfig|isCleartextTrafficPermitted'
        }

    def analyze_java_file(self, file_path: str) -> Dict:
        """Analyze a single Java file for security patterns."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            findings = {
                'file': os.path.basename(file_path),
                'class': self._extract_class_name(content),
                'methods': self._extract_methods(content),
                'security_findings': self._find_security_patterns(content)
            }
            return findings
        except Exception as e:
            print(f"Error analyzing {file_path}: {str(e)}")
            return None

    def _extract_class_name(self, content: str) -> str:
        match = re.search(r'class\s+(\w+)', content)
        return match.group(1) if match else "Unknown"

    def _extract_methods(self, content: str) -> List[str]:
        methods = re.finditer(
            r'(?:public|private|protected|\s)[\w\<\>\[\]]+\s+(\w+)\s*\([^\)]*\)',
            content
        )
        return [m.group(0) for m in methods]

    def _find_security_patterns(self, content: str) -> Dict:
        findings = {}
        for category, pattern in self.security_patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                findings[category] = True
        return findings

    def generate_frida_script(self, findings: List[Dict]) -> str:
        """Generate a targeted Frida script based on analysis findings."""
        script_parts = []
        
        # Add basic setup
        script_parts.append("""setTimeout(function() {
    Java.perform(function() {
        console.log('[*] Starting security bypass...');""")

        # Add relevant bypasses based on findings
        security_features = set()
        for finding in findings:
            if finding.get('security_findings'):
                security_features.update(finding['security_findings'].keys())

        if 'ssl_pinning' in security_features:
            script_parts.append(self._get_ssl_pinning_bypass())
        if 'root_detection' in security_features:
            script_parts.append(self._get_root_detection_bypass())
        if 'webview_security' in security_features:
            script_parts.append(self._get_webview_bypass())
        if 'network_security' in security_features:
            script_parts.append(self._get_network_security_bypass())

        # Add closing
        script_parts.append("""
        console.log('[*] Security bypasses complete');
    });
}, 0);""")

        return "\n".join(script_parts)

    def _get_ssl_pinning_bypass(self) -> str:
        return """
        // SSL Pinning Bypass
        try {
            var array_list = Java.use("java.util.ArrayList");
            var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            if (ApiClient) {
                ApiClient.checkTrustedRecursive.implementation = function(a1, a2, a3, a4, a5, a6) {
                    console.log('[+] Bypassing SSL Pinning');
                    var k = array_list.$new();
                    return k;
                }
            }
        } catch(e) {
            console.log('[-] SSL Pinning bypass failed: ' + e);
        }"""

    def _get_root_detection_bypass(self) -> str:
        return """
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
        } catch(err) {
            console.log('[-] Root detection bypass failed: ' + err);
        }"""

    def _get_webview_bypass(self) -> str:
        return """
        // WebView SSL Bypass
        try {
            var WebViewClient = Java.use('android.webkit.WebViewClient');
            WebViewClient.onReceivedSslError.implementation = function(webView, sslErrorHandler, sslError) {
                console.log('[+] WebView SSL error bypassed');
                sslErrorHandler.proceed();
                return;
            };
        } catch(err) {
            console.log('[-] WebView bypass failed: ' + err);
        }"""

    def _get_network_security_bypass(self) -> str:
        return """
        // Network Security Bypass
        try {
            var NetworkSecurityConfig = Java.use('android.security.net.config.NetworkSecurityConfig');
            NetworkSecurityConfig.isCleartextTrafficPermitted.implementation = function() {
                console.log('[+] Allowing cleartext traffic');
                return true;
            };
        } catch(err) {
            console.log('[-] Network security bypass failed: ' + err);
        }"""

def main():
    analyzer = AndroidSecurityAnalyzer()
    
    print("Android Security Analysis Tool")
    print("1. Analyze decompiled APK")
    print("2. Generate Frida script from existing analysis")
    choice = input("Select option (1-2): ").strip()

    if choice == '1':
        decompiled_dir = input("Enter path to decompiled APK directory: ").strip()
        if not os.path.isdir(decompiled_dir):
            print("Invalid directory path!")
            return

        findings = []
        for root, _, files in os.walk(decompiled_dir):
            for file in files:
                if file.endswith('.java'):
                    result = analyzer.analyze_java_file(os.path.join(root, file))
                    if result:
                        findings.append(result)

        # Save analysis results
        output_base = os.path.basename(decompiled_dir)
        with open(f"{output_base}_analysis.json", 'w') as f:
            json.dump(findings, f, indent=2)

        # Generate Frida script
        frida_script = analyzer.generate_frida_script(findings)
        with open(f"{output_base}_frida.js", 'w') as f:
            f.write(frida_script)

        print(f"Analysis saved to {output_base}_analysis.json")
        print(f"Frida script saved to {output_base}_frida.js")

    elif choice == '2':
        analysis_file = input("Enter path to analysis JSON file: ").strip()
        if not os.path.isfile(analysis_file):
            print("Invalid file path!")
            return

        with open(analysis_file, 'r') as f:
            findings = json.load(f)

        output_base = os.path.splitext(analysis_file)[0]
        frida_script = analyzer.generate_frida_script(findings)
        with open(f"{output_base}_frida.js", 'w') as f:
            f.write(frida_script)

        print(f"Frida script saved to {output_base}_frida.js")

if __name__ == "__main__":
    main()
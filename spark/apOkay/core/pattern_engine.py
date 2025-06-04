"""
Pattern Engine - Extract and analyze security patterns
Builds intelligence database from APK analysis
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path

class PatternEngine:
    def __init__(self):
        self.patterns_db = {}
        
    def extract_patterns(self, apk_data: Dict[str, Any], vendor_info: Dict[str, Any]) -> Dict[str, Any]:
        """Extract security patterns from APK data"""
        
        patterns = {
            'security_features': [],
            'protection_mechanisms': [],
            'attack_surface': [],
            'bypass_opportunities': []
        }
        
        # Analyze permissions for security indicators
        permissions = apk_data.get('manifest', {}).get('permissions', [])
        
        # High-risk permissions that indicate security features
        security_permissions = [
            'android.permission.SYSTEM_ALERT_WINDOW',
            'android.permission.WRITE_SECURE_SETTINGS',
            'android.permission.BIND_DEVICE_ADMIN',
            'android.permission.BIND_ACCESSIBILITY_SERVICE'
        ]
        
        for perm in permissions:
            if any(sec_perm in perm for sec_perm in security_permissions):
                patterns['security_features'].append(f"Security permission: {perm}")
        
        # Analyze native libraries for protection mechanisms
        native_libs = apk_data.get('native_libs', [])
        for lib in native_libs:
            if any(keyword in lib.lower() for keyword in ['guard', 'protect', 'security', 'anti']):
                patterns['protection_mechanisms'].append(f"Security library: {lib}")
        
        # Identify potential attack surface
        if len(apk_data.get('dex_files', [])) > 1:
            patterns['attack_surface'].append("Multiple DEX files - potential code injection points")
        
        if apk_data.get('manifest', {}).get('application', {}).get('debuggable'):
            patterns['bypass_opportunities'].append("App is debuggable")
        
        # Add vendor-specific patterns
        if vendor_info.get('vendor') != 'unknown':
            patterns['vendor_patterns'] = self._get_vendor_patterns(vendor_info)
        
        return patterns
    
    def _get_vendor_patterns(self, vendor_info: Dict[str, Any]) -> Dict[str, Any]:
        """Get vendor-specific attack patterns"""
        
        vendor = vendor_info.get('vendor')
        vendor_patterns = {
            'arxan': {
                'common_bypasses': ['Frida hook libguard.so', 'SSL pinning bypass'],
                'weak_points': ['Native library hooking', 'Runtime manipulation']
            },
            'guardsquare': {
                'common_bypasses': ['ProGuard deobfuscation', 'String decryption'],
                'weak_points': ['Reflection analysis', 'Control flow analysis']
            },
            'irdeto': {
                'common_bypasses': ['Hardware attestation bypass', 'TEE manipulation'],
                'weak_points': ['Emulator detection', 'Root detection']
            },
            'promon': {
                'common_bypasses': ['SHIELD runtime hooks', 'Memory patching'],
                'weak_points': ['Runtime detection', 'Code integrity']
            }
        }
        
        return vendor_patterns.get(vendor, {})
    
    def generate_intelligence_report(self, results: List[Dict], output_dir: str):
        """Generate comprehensive intelligence report"""
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Summary statistics
        total_apks = len(results)
        vendor_counts = {}
        pattern_summary = {}
        
        for result in results:
            vendor = result['vendor_info'].get('vendor', 'unknown')
            vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1
            
            # Aggregate patterns
            patterns = result.get('patterns', {})
            for pattern_type, pattern_list in patterns.items():
                if pattern_type not in pattern_summary:
                    pattern_summary[pattern_type] = {}
                for pattern in pattern_list:
                    pattern_summary[pattern_type][pattern] = pattern_summary[pattern_type].get(pattern, 0) + 1
        
        # Generate summary report
        summary = {
            'scan_timestamp': datetime.now().isoformat(),
            'total_apks_analyzed': total_apks,
            'vendor_distribution': vendor_counts,
            'pattern_analysis': pattern_summary,
            'top_vendors': sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        }
        
        # Write summary JSON
        with open(f"{output_dir}/intelligence_summary.json", 'w') as f:
            json.dump(summary, f, indent=2)
        
        # Write detailed results
        with open(f"{output_dir}/detailed_results.json", 'w') as f:
            json.dump(results, f, indent=2)
        
        # Generate Frida script templates
        self._generate_frida_templates(results, output_dir)
    
    def _generate_frida_templates(self, results: List[Dict], output_dir: str):
        """Generate Frida bypass script templates"""
        
        frida_dir = f"{output_dir}/frida_scripts"
        os.makedirs(frida_dir, exist_ok=True)
        
        # Group by vendor for script generation
        vendor_groups = {}
        for result in results:
            vendor = result['vendor_info'].get('vendor')
            if vendor and vendor != 'unknown':
                if vendor not in vendor_groups:
                    vendor_groups[vendor] = []
                vendor_groups[vendor].append(result)
        
        # Generate vendor-specific scripts
        for vendor, vendor_results in vendor_groups.items():
            script_content = self._create_vendor_script(vendor, vendor_results)
            
            with open(f"{frida_dir}/{vendor}_bypass.js", 'w') as f:
                f.write(script_content)
    
    def _create_vendor_script(self, vendor: str, results: List[Dict]) -> str:
        """Create Frida script for specific vendor"""
        
        script_templates = {
            'arxan': '''
// Arxan/DexGuard Bypass Script
console.log("[+] Arxan/DexGuard bypass starting...");

// Hook common Arxan libraries
var libguard = Process.findModuleByName("libguard.so");
if (libguard) {
    console.log("[+] Found libguard.so at: " + libguard.base);
    // Add specific hooks here
}

// SSL Pinning bypass
Java.perform(function() {
    // Common Arxan SSL pinning bypass
    console.log("[+] Hooking SSL verification...");
});
            ''',
            'guardsquare': '''
// GuardSquare/ProGuard Bypass Script  
console.log("[+] GuardSquare bypass starting...");

Java.perform(function() {
    // String decryption hooks
    console.log("[+] Hooking string decryption...");
    
    // Anti-debugging bypass
    console.log("[+] Bypassing debug detection...");
});
            ''',
            'promon': '''
// Promon SHIELD Bypass Script
console.log("[+] Promon SHIELD bypass starting...");

// Hook SHIELD runtime protection
var libshield = Process.findModuleByName("libshield.so");
if (libshield) {
    console.log("[+] Found libshield.so at: " + libshield.base);
}

Java.perform(function() {
    console.log("[+] Bypassing SHIELD runtime checks...");
});
            '''
        }
        
        return script_templates.get(vendor, f'// {vendor} bypass script template\nconsole.log("[+] {vendor} bypass starting...");')

"""
Vendor Detector - Security vendor identification engine
Identifies which security company protected the APK
"""

import re
from typing import Dict, Any, List

class VendorDetector:
    def __init__(self):
        self.vendor_signatures = self._load_vendor_signatures()
    
    def _load_vendor_signatures(self) -> Dict[str, Dict]:
        """Load security vendor fingerprint database"""
        return {
            'arxan': {
                'native_libs': [
                    r'libguard\.so',
                    r'libdgprotect\.so',
                    r'libensemble\.so'
                ],
                'classes': [
                    r'com\.arxan\.',
                    r'com\.guardsquare\.'
                ],
                'strings': [
                    'DexGuard',
                    'Arxan',
                    'ApplicationIntegrityException'
                ]
            },
            'guardsquare': {
                'native_libs': [
                    r'libguard\.so',
                    r'libdexguard\.so'
                ],
                'classes': [
                    r'com\.guardsquare\.',
                    r'proguard\.'
                ],
                'strings': [
                    'DexGuard',
                    'ProGuard',
                    'GuardSquare'
                ]
            },
            'irdeto': {
                'native_libs': [
                    r'libcryptoguard\.so',
                    r'libirdeto\.so'
                ],
                'classes': [
                    r'com\.irdeto\.',
                    r'cryptoguard\.'
                ],
                'strings': [
                    'Irdeto',
                    'CryptoGuard',
                    'Hardware Security'
                ]
            },
            'promon': {
                'native_libs': [
                    r'libshield\.so',
                    r'libpromon\.so'
                ],
                'classes': [
                    r'com\.promon\.',
                    r'shield\.'
                ],
                'strings': [
                    'SHIELD',
                    'Promon',
                    'Runtime Protection'
                ]
            },
            'liapp': {
                'native_libs': [
                    r'libliapp\.so',
                    r'libprotect\.so'
                ],
                'classes': [
                    r'com\.licel\.',
                    r'liapp\.'
                ],
                'strings': [
                    'LiApp',
                    'Licel',
                    'AppGuard'
                ]
            }
        }
    
    def identify_vendor(self, apk_data: Dict[str, Any]) -> Dict[str, Any]:
        """Identify security vendor from APK data"""
        
        vendor_scores = {}
        detection_details = {}
        
        for vendor_name, signatures in self.vendor_signatures.items():
            score = 0
            details = {'matches': [], 'confidence': 0}
            
            # Check native libraries
            for lib_pattern in signatures.get('native_libs', []):
                for lib in apk_data.get('native_libs', []):
                    if re.search(lib_pattern, lib, re.IGNORECASE):
                        score += 3  # High weight for native libs
                        details['matches'].append(f"Native lib: {lib}")
            
            # Check class names (would need decompilation)
            # For now, we'll implement this later
            
            # Check strings (would need string extraction)
            # For now, we'll implement this later
            
            # Check for obfuscation patterns specific to vendor
            obf_indicators = apk_data.get('obfuscation_indicators', [])
            if vendor_name == 'guardsquare' and 'multiple_dex_files' in obf_indicators:
                score += 2
                details['matches'].append("ProGuard/DexGuard obfuscation pattern")
            
            if score > 0:
                details['confidence'] = min(score * 10, 100)  # Convert to percentage
                vendor_scores[vendor_name] = score
                detection_details[vendor_name] = details
        
        # Determine most likely vendor
        if vendor_scores:
            top_vendor = max(vendor_scores.keys(), key=lambda k: vendor_scores[k])
            return {
                'vendor': top_vendor,
                'confidence': detection_details[top_vendor]['confidence'],
                'details': detection_details[top_vendor]['matches'],
                'all_scores': vendor_scores
            }
        else:
            return {
                'vendor': 'unknown',
                'confidence': 0,
                'details': [],
                'all_scores': {}
            }

    def _detect_cloud_security(self, apk_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect cloud-based security patterns"""
        
        cloud_indicators = {
            'firebase': [],
            'auth_providers': [],
            'payment_providers': [],
            'cloud_services': []
        }
        
        file_list = apk_data.get('file_list', [])
        
        # Firebase detection
        firebase_files = [f for f in file_list if 'firebase' in f.lower()]
        if firebase_files:
            cloud_indicators['firebase'] = firebase_files[:5]  # Limit output
        
        # Auth provider detection
        manifest = apk_data.get('manifest', {})
        if 'auth0' in str(manifest).lower():
            cloud_indicators['auth_providers'].append('Auth0')
        
        # Google services detection
        google_files = [f for f in file_list if any(x in f.lower() for x in ['google', 'gms'])]
        if google_files:
            cloud_indicators['cloud_services'].extend(['Google Play Services', 'Google Pay'])
        
        return cloud_indicators

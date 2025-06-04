"""
Enhanced APK Scanner - Handles APK and XAPK files
"""

import os
import zipfile
import subprocess
import tempfile
import json
from pathlib import Path
from typing import List, Dict, Any
import xml.etree.ElementTree as ET

class APKScanner:
    def __init__(self, threads=4, verbose=False):
        self.threads = threads
        self.verbose = verbose
        
    def find_apks(self, directory: str) -> List[Path]:
        """Find all APK and XAPK files in directory recursively"""
        apk_path = Path(directory)
        apk_files = list(apk_path.rglob("*.apk"))
        xapk_files = list(apk_path.rglob("*.xapk"))
        
        if self.verbose and xapk_files:
            print(f"Found {len(xapk_files)} XAPK files")
        
        return apk_files + xapk_files
    
    def scan_apk(self, apk_path: Path) -> Dict[str, Any]:
        """Scan APK or XAPK and extract intelligence data"""
        
        if apk_path.suffix.lower() == '.xapk':
            return self._scan_xapk(apk_path)
        else:
            return self._scan_standard_apk(apk_path)
    
    def _scan_xapk(self, xapk_path: Path) -> Dict[str, Any]:
        """Scan XAPK file (extract main APK and analyze)"""
        
        xapk_data = {
            'path': str(xapk_path),
            'name': xapk_path.name,
            'size': xapk_path.stat().st_size,
            'type': 'xapk',
            'main_apk': None,
            'obb_files': [],
            'manifest': {},
            'native_libs': [],
            'dex_files': [],
            'assets': [],
            'certificates': [],
            'strings': [],
            'permissions': []
        }
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Extract XAPK contents
                with zipfile.ZipFile(xapk_path, 'r') as xapk_zip:
                    xapk_zip.extractall(temp_dir)
                
                # Parse manifest.json from XAPK
                manifest_json_path = Path(temp_dir) / 'manifest.json'
                if manifest_json_path.exists():
                    with open(manifest_json_path, 'r') as f:
                        xapk_manifest = json.load(f)
                        xapk_data['xapk_manifest'] = xapk_manifest
                        if self.verbose:
                            print(f"XAPK Package: {xapk_manifest.get('package_name', 'unknown')}")
                
                # Find main APK file
                temp_path = Path(temp_dir)
                apk_files = list(temp_path.glob("*.apk"))
                
                if apk_files:
                    main_apk = apk_files[0]  # Usually the main APK
                    xapk_data['main_apk'] = str(main_apk)
                    
                    # Analyze the main APK
                    apk_analysis = self._scan_standard_apk(main_apk)
                    
                    # Merge APK analysis into XAPK data
                    xapk_data.update({
                        'manifest': apk_analysis.get('manifest', {}),
                        'native_libs': apk_analysis.get('native_libs', []),
                        'dex_files': apk_analysis.get('dex_files', []),
                        'assets': apk_analysis.get('assets', []),
                        'obfuscation_indicators': apk_analysis.get('obfuscation_indicators', [])
                    })
                
                # Find OBB files
                obb_files = list(temp_path.glob("*.obb"))
                xapk_data['obb_files'] = [str(f) for f in obb_files]
                
                if self.verbose and obb_files:
                    print(f"Found {len(obb_files)} OBB files")
                
        except Exception as e:
            if self.verbose:
                print(f"Error scanning XAPK {xapk_path}: {e}")
        
        return xapk_data
    
    def _scan_standard_apk(self, apk_path: Path) -> Dict[str, Any]:
        """Scan standard APK file"""
        
        apk_data = {
            'path': str(apk_path),
            'name': apk_path.name,
            'size': apk_path.stat().st_size,
            'type': 'apk',
            'manifest': {},
            'native_libs': [],
            'dex_files': [],
            'assets': [],
            'certificates': [],
            'strings': [],
            'permissions': []
        }
        
        try:
            # Extract manifest using aapt
            manifest_data = self._extract_manifest(apk_path)
            apk_data['manifest'] = manifest_data
            
            # Analyze ZIP structure
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                file_list = apk_zip.namelist()
                
                # Get native libraries
                apk_data['native_libs'] = [f for f in file_list if f.startswith('lib/')]
                
                # Get DEX files
                apk_data['dex_files'] = [f for f in file_list if f.endswith('.dex')]
                
                # Get assets
                apk_data['assets'] = [f for f in file_list if f.startswith('assets/')]
                
                # Check for obfuscation indicators
                apk_data['obfuscation_indicators'] = self._check_obfuscation(apk_zip)
                
                # Store complete file list for vendor detection
                apk_data['file_list'] = file_list
                
        except Exception as e:
            if self.verbose:
                print(f"Error scanning {apk_path}: {e}")
        
        return apk_data
    
    def _extract_manifest(self, apk_path: Path) -> Dict[str, Any]:
        """Extract and parse AndroidManifest.xml"""
        try:
            # Use aapt to dump manifest
            result = subprocess.run([
                'aapt', 'dump', 'xmltree', str(apk_path), 'AndroidManifest.xml'
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return self._parse_manifest_output(result.stdout)
            else:
                # Fallback to jadx
                return self._extract_manifest_jadx(apk_path)
                
        except Exception:
            return {}
    
    def _extract_manifest_jadx(self, apk_path: Path) -> Dict[str, Any]:
        """Extract manifest using JADX as fallback"""
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Decompile with jadx
                subprocess.run([
                    'jadx', '-d', temp_dir, '--no-src', str(apk_path)
                ], capture_output=True, timeout=60)
                
                manifest_path = Path(temp_dir) / 'AndroidManifest.xml'
                if manifest_path.exists():
                    return self._parse_manifest_xml(manifest_path)
                    
        except Exception:
            pass
        
        return {}
    
    def _parse_manifest_output(self, aapt_output: str) -> Dict[str, Any]:
        """Parse aapt manifest output"""
        manifest_data = {
            'package': '',
            'permissions': [],
            'activities': [],
            'services': [],
            'receivers': [],
            'providers': [],
            'application': {}
        }
        
        # Parse aapt output (simplified for now)
        lines = aapt_output.split('\n')
        for line in lines:
            if 'package=' in line:
                # Extract package name
                start = line.find('package="') + 9
                end = line.find('"', start)
                if start > 8 and end > start:
                    manifest_data['package'] = line[start:end]
            elif 'uses-permission:' in line:
                # Extract permissions
                if 'name=' in line:
                    start = line.find('name="') + 6
                    end = line.find('"', start)
                    if start > 5 and end > start:
                        manifest_data['permissions'].append(line[start:end])
        
        return manifest_data
    
    def _parse_manifest_xml(self, manifest_path: Path) -> Dict[str, Any]:
        """Parse manifest XML file"""
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            manifest_data = {
                'package': root.get('package', ''),
                'permissions': [],
                'activities': [],
                'services': [],
                'receivers': [],
                'providers': [],
                'application': {}
            }
            
            # Extract permissions
            for perm in root.findall('.//uses-permission'):
                name = perm.get('{http://schemas.android.com/apk/res/android}name')
                if name:
                    manifest_data['permissions'].append(name)
            
            return manifest_data
            
        except Exception:
            return {}
    
    def _check_obfuscation(self, apk_zip: zipfile.ZipFile) -> List[str]:
        """Check for obfuscation indicators"""
        indicators = []
        
        # Check for common obfuscation patterns
        for filename in apk_zip.namelist():
            # ProGuard/R8 indicators
            if filename.startswith('classes') and filename.endswith('.dex'):
                if filename != 'classes.dex':
                    indicators.append('multiple_dex_files')
            
            # Native library obfuscation
            if filename.startswith('lib/') and filename.endswith('.so'):
                lib_name = os.path.basename(filename)
                if len(lib_name) < 10 or not lib_name.startswith('lib'):
                    indicators.append('obfuscated_native_libs')
        
        return list(set(indicators))

#!/usr/bin/env python3
"""
apOkay - APK Security Intelligence Platform
The real shit for breaking mobile security without breaking apps
"""

import click
import os
import sys
from pathlib import Path
from rich.console import Console
from rich.progress import track

# Import our modules (we'll build these next)
from core.apk_scanner import APKScanner
from core.vendor_detector import VendorDetector
from core.pattern_engine import PatternEngine

console = Console()

@click.command()
@click.option('--apk-dir', '-d', required=True, help='Directory containing APKs to scan')
@click.option('--output', '-o', default='./output', help='Output directory for results')
@click.option('--threads', '-t', default=4, help='Number of processing threads')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def main(apk_dir, output, threads, verbose):
    """
    apOkay - Mass APK Security Analysis
    
    Point it at a directory full of APKs and watch it build
    your security vendor intelligence database
    """
    
    if not os.path.exists(apk_dir):
        console.print(f"[red]APK directory not found: {apk_dir}[/red]")
        sys.exit(1)
    
    console.print("[bold green]apOkay - Let's break some security without breaking apps![/bold green]")
    console.print(f"[cyan]Scanning APK directory: {apk_dir}[/cyan]")
    console.print(f"[cyan]Output directory: {output}[/cyan]")
    
    # Initialize our engines
    scanner = APKScanner(threads=threads, verbose=verbose)
    detector = VendorDetector()
    engine = PatternEngine()
    
    # Find all APKs in directory
    apk_files = scanner.find_apks(apk_dir)
    console.print(f"[yellow]Found {len(apk_files)} APK files[/yellow]")
    
    if not apk_files:
        console.print("[red]No APK files found in directory[/red]")
        sys.exit(1)
    
    # Process each APK
    results = []
    for apk_path in track(apk_files, description="Processing APKs..."):
        try:
            # Scan APK structure
            apk_data = scanner.scan_apk(apk_path)
            
            # Detect security vendor
            vendor_info = detector.identify_vendor(apk_data)
            
            # Extract patterns
            patterns = engine.extract_patterns(apk_data, vendor_info)
            
            result = {
                'apk_path': str(apk_path),
                'apk_data': apk_data,
                'vendor_info': vendor_info,
                'patterns': patterns
            }
            results.append(result)
            
            if verbose:
                console.print(f"[green]Processed: {apk_path.name}[/green]")
                if vendor_info.get('vendor'):
                    console.print(f"  Security Vendor: {vendor_info['vendor']}")
                
        except Exception as e:
            console.print(f"[red]Error processing {apk_path}: {e}[/red]")
            continue
    
    # Generate output
    engine.generate_intelligence_report(results, output)
    console.print(f"[bold green]Intelligence report generated in: {output}[/bold green]")

if __name__ == '__main__':
    main()

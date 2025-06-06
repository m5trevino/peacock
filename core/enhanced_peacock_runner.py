#!/usr/bin/env python3
"""
Enhanced Peacock Code Processor - Works with ANY Python code
Usage: python enhanced_peacock_runner.py [file_path_or_options]
"""

import sys
import argparse
from pathlib import Path
import json
from peacock_mcp_processor import PeacockCodeAnalyzer, PeacockHTMLGenerator


def process_file(file_path: str) -> dict:
    """Process a single Python file"""
    
    file_path = Path(file_path)
    
    if not file_path.exists():
        print(f"❌ ERROR: File not found: {file_path}")
        return None
    
    if not file_path.suffix == '.py':
        print(f"⚠️  WARNING: {file_path} is not a Python file, processing anyway...")
    
    print(f"🔍 Analyzing: {file_path}")
    
    # Read the code
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            code_content = f.read()
    except Exception as e:
        print(f"❌ ERROR reading file: {e}")
        return None
    
    # Analyze the code
    analyzer = PeacockCodeAnalyzer()
    analysis_result = analyzer.analyze_code(code_content, file_path.name)
    
    # Generate HTML
    html_generator = PeacockHTMLGenerator()
    html_output = html_generator.generate_html(analysis_result)
    
    # Save outputs
    output_name = file_path.stem
    html_path = f"peacock_analysis_{output_name}.html"
    json_path = f"peacock_analysis_{output_name}.json"
    
    # Save HTML
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_output)
    
    # Save JSON data for MCP
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(analysis_result, f, indent=2, default=str)
    
    print(f"✅ Generated: {html_path}")
    print(f"💾 MCP Data: {json_path}")
    
    return analysis_result


def process_directory(directory: str) -> list:
    """Process all Python files in a directory"""
    
    directory = Path(directory)
    if not directory.exists():
        print(f"❌ ERROR: Directory not found: {directory}")
        return []
    
    python_files = list(directory.glob("*.py"))
    if not python_files:
        print(f"⚠️  No Python files found in: {directory}")
        return []
    
    print(f"📂 Found {len(python_files)} Python files in {directory}")
    
    results = []
    for py_file in python_files:
        result = process_file(str(py_file))
        if result:
            results.append(result)
    
    return results


def process_stdin():
    """Process code from stdin/clipboard"""
    
    print("📝 Paste your Python code (Ctrl+D when done):")
    try:
        code_content = sys.stdin.read()
    except KeyboardInterrupt:
        print("\n❌ Cancelled")
        return None
    
    if not code_content.strip():
        print("❌ ERROR: No code provided")
        return None
    
    print("🔍 Analyzing pasted code...")
    
    # Analyze the code
    analyzer = PeacockCodeAnalyzer()
    analysis_result = analyzer.analyze_code(code_content, "pasted_code.py")
    
    # Generate HTML
    html_generator = PeacockHTMLGenerator()
    html_output = html_generator.generate_html(analysis_result)
    
    # Save outputs
    html_path = "peacock_analysis_pasted_code.html"
    json_path = "peacock_analysis_pasted_code.json"
    
    # Save HTML
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_output)
    
    # Save JSON data for MCP
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(analysis_result, f, indent=2, default=str)
    
    print(f"✅ Generated: {html_path}")
    print(f"💾 MCP Data: {json_path}")
    
    return analysis_result


def create_mcp_integration_example():
    """Create example MCP integration code"""
    
    mcp_code = '''#!/usr/bin/env python3
"""
MCP Integration Example - How Peacock integrates with your MCP server
"""

from enhanced_peacock_runner import process_file, process_stdin
import json
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/analyze-code', methods=['POST'])
def mcp_analyze_code():
    """MCP endpoint to analyze code and return structured data"""
    
    data = request.get_json()
    
    if 'code' in data:
        # Direct code analysis
        analyzer = PeacockCodeAnalyzer()
        result = analyzer.analyze_code(data['code'], data.get('filename', 'code.py'))
        
    elif 'file_path' in data:
        # File analysis
        result = process_file(data['file_path'])
        
    else:
        return jsonify({'error': 'No code or file_path provided'}), 400
    
    if not result:
        return jsonify({'error': 'Analysis failed'}), 500
    
    # Return structured data for LLM2
    return jsonify({
        'status': 'success',
        'analysis': result,
        'xedit_paths': [elem['xedit_path'] for elem in result['elements']],
        'critical_elements': [
            elem for elem in result['elements'] 
            if elem['complexity'] == 'critical'
        ],
        'html_report_generated': True
    })

@app.route('/get-xedit-paths', methods=['POST'])
def get_xedit_paths():
    """Get XEdit-Paths for specific code sections"""
    
    data = request.get_json()
    file_path = data.get('file_path')
    line_numbers = data.get('line_numbers', [])
    
    if not file_path:
        return jsonify({'error': 'file_path required'}), 400
    
    # Analyze file
    result = process_file(file_path)
    if not result:
        return jsonify({'error': 'Analysis failed'}), 500
    
    # Filter XEdit-Paths for requested lines
    matching_paths = []
    for elem in result['elements']:
        if any(elem['start_line'] <= line <= elem['end_line'] for line in line_numbers):
            matching_paths.append({
                'xedit_path': elem['xedit_path'],
                'element_type': elem['element_type'],
                'complexity': elem['complexity'],
                'description': elem['description']
            })
    
    return jsonify({
        'status': 'success',
        'xedit_paths': matching_paths,
        'total_matches': len(matching_paths)
    })

if __name__ == '__main__':
    app.run(host='localhost', port=8080, debug=True)
'''
    
    with open('mcp_integration_example.py', 'w') as f:
        f.write(mcp_code)
    
    print("📡 Created MCP integration example: mcp_integration_example.py")


def main():
    """Main function with argument parsing"""
    
    parser = argparse.ArgumentParser(description='🦚 Peacock Code Analyzer')
    parser.add_argument('target', nargs='?', help='Python file or directory to analyze')
    parser.add_argument('--stdin', action='store_true', help='Read code from stdin')
    parser.add_argument('--directory', '-d', help='Analyze all Python files in directory')
    parser.add_argument('--create-mcp', action='store_true', help='Create MCP integration example')
    
    args = parser.parse_args()
    
    print("🦚 PEACOCK CODE ANALYZER")
    print("=" * 40)
    
    if args.create_mcp:
        create_mcp_integration_example()
        return
    
    if args.stdin:
        process_stdin()
    elif args.directory:
        process_directory(args.directory)
    elif args.target:
        target_path = Path(args.target)
        if target_path.is_file():
            process_file(args.target)
        elif target_path.is_dir():
            process_directory(args.target)
        else:
            print(f"❌ ERROR: {args.target} is not a valid file or directory")
    else:
        # Interactive mode
        print("🎯 USAGE OPTIONS:")
        print("1. Analyze file:      python enhanced_peacock_runner.py mycode.py")
        print("2. Analyze directory: python enhanced_peacock_runner.py --directory ./myproject")
        print("3. Paste code:        python enhanced_peacock_runner.py --stdin")
        print("4. Create MCP example: python enhanced_peacock_runner.py --create-mcp")
        print("")
        
        choice = input("Enter file path or option: ").strip()
        if choice:
            if Path(choice).exists():
                if Path(choice).is_file():
                    process_file(choice)
                else:
                    process_directory(choice)
            else:
                print(f"❌ File/directory not found: {choice}")


if __name__ == "__main__":
    main()

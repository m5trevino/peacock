#!/usr/bin/env python3
"""
project-builder.py - Project Builder and Deployment Handler
Creates deployable Python projects from parsed code files
"""

import json
import datetime
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional

from schemas import FinalCodeOutput, CodeFile


class ProjectBuilder:
    """Project Builder - Creates deployable Python projects"""
    
    def __init__(self):
        self.stage_name = "PROJECT-BUILDER"
        self.icon = "🏗️"
        self.specialty = "Project Deployment & Build Creation"
    
    def deploy_and_run(self, project_files: List[Dict[str, Any]], project_name: str) -> Dict[str, Any]:
        """Generate Python project folder with auto-setup script"""
        print(f"🏗️ PROJECT-BUILDER: Creating deployable project: {project_name}")
        
        try:
            # Create apps directory if it doesn't exist
            apps_dir = Path("/home/flintx/peacock/apps")
            apps_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate project folder path
            project_folder = f"{project_name.replace(' ', '-').lower()}"
            project_path = apps_dir / project_folder
            
            # Remove existing folder if it exists
            if project_path.exists():
                shutil.rmtree(project_path)
            
            # Create project directory
            project_path.mkdir(parents=True, exist_ok=True)
            
            # Detect project type
            app_type = self._detect_app_type(project_files)
            
            # Write all project files
            for file_data in project_files:
                file_path = project_path / file_data['filename']
                
                # Create subdirectories if needed
                file_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Write file content
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(file_data['code'])
                
                print(f"✅ Created: {file_data['filename']}")
            
            # Add setup.py if not already present
            setup_path = project_path / "setup.py"
            if not setup_path.exists():
                setup_content = self._generate_setup_script(project_name, app_type, project_files)
                with open(setup_path, 'w', encoding='utf-8') as f:
                    f.write(setup_content)
                # Make setup.py executable
                import os
                os.chmod(setup_path, 0o755)
                print("✅ Created: setup.py (auto-installer)")
            
            # Ensure requirements.txt exists with Python dependencies
            requirements_path = project_path / "requirements.txt"
            if not requirements_path.exists():
                requirements_content = self._generate_requirements_txt(project_files, app_type)
                with open(requirements_path, 'w', encoding='utf-8') as f:
                    f.write(requirements_content)
                print("✅ Created: requirements.txt (dependencies)")
            
            # Ensure README.md exists with project documentation
            readme_path = project_path / "README.md"
            if not readme_path.exists():
                readme_content = self._generate_readme_md(project_name, app_type, project_files)
                with open(readme_path, 'w', encoding='utf-8') as f:
                    f.write(readme_content)
                print("✅ Created: README.md (documentation)")
            
            files_created_count = len(project_files) + 3  # +3 for setup.py, requirements.txt, README.md
            
            print(f"✅ Created Python project: {project_path}")
            print(f"🚀 To run: cd {project_folder} && python setup.py")
            
            return {
                "success": True,
                "message": f"🦚 Python project created: {project_folder}",
                "project_path": str(project_path),
                "app_type": app_type,
                "files_created": files_created_count,
                "run_command": f"cd apps/{project_folder} && python setup.py"
            }
            
        except Exception as e:
            error_msg = f"Python project creation failed: {str(e)}"
            print(f"❌ PROJECT-BUILDER: {error_msg}")
            return {
                "success": False,
                "error": error_msg
            }
    
    def _generate_setup_script(self, project_name: str, app_type: str, project_files: List[Dict[str, Any]]) -> str:
        """Generate auto-setup script for Python projects"""
        
        # Find main Python file
        main_file = "app.py"
        for file_data in project_files:
            if file_data['filename'] in ['app.py', 'main.py', 'run.py']:
                main_file = file_data['filename']
                break
        
        return f'''#!/usr/bin/env python3
"""
🦚 Peacock {project_name} - Auto Setup & Run
Just run: python setup.py
"""
import subprocess
import sys
import os
from pathlib import Path

def main():
    print("🦚 {project_name}")
    print("=" * 40)
    
    # Check Python version
    if sys.version_info < (3, 7):
        print("❌ Python 3.7+ required")
        sys.exit(1)
    
    # Install dependencies
    if Path("requirements.txt").exists():
        print("📦 Installing dependencies...")
        try:
            subprocess.run([
                sys.executable, "-m", "pip", "install", 
                "-r", "requirements.txt", "--quiet"
            ], check=True)
            print("✅ Dependencies installed")
        except subprocess.CalledProcessError:
            print("⚠️  Some dependencies may have failed to install")
            print("💡 Try: pip install -r requirements.txt")
    
    # Run the app
    print("🚀 Starting application...")
    if "{app_type}" == "flask":
        print("🌐 Flask app will start at http://localhost:5000")
    
    try:
        subprocess.run([sys.executable, "{main_file}"])
    except KeyboardInterrupt:
        print("\\n👋 Application stopped")
    except Exception as e:
        print(f"❌ Error running app: {{e}}")
        print(f"💡 Try: python {main_file}")

if __name__ == "__main__":
    main()
'''

    def _generate_requirements_txt(self, project_files: List[Dict[str, Any]], app_type: str) -> str:
        """Generate requirements.txt with Python dependencies"""
        
        # Default Python dependencies
        requirements = set([
            "# Core Python dependencies for Peacock projects"
        ])
        
        # Analyze project files for common dependencies
        all_code = ""
        for file_data in project_files:
            if file_data.get('language') == 'python':
                all_code += file_data.get('code', '') + "\n"
        
        # Detect common Python libraries and add appropriate versions
        if 'flask' in all_code.lower() or 'from flask' in all_code.lower():
            requirements.add("Flask==3.0.0")
            requirements.add("Werkzeug==3.0.1")
        
        if 'django' in all_code.lower() or 'from django' in all_code.lower():
            requirements.add("Django==4.2.7")
            requirements.add("djangorestframework==3.14.0")
        
        if 'fastapi' in all_code.lower() or 'from fastapi' in all_code.lower():
            requirements.add("fastapi==0.104.1")
            requirements.add("uvicorn==0.24.0")
        
        if 'requests' in all_code.lower() or 'import requests' in all_code.lower():
            requirements.add("requests==2.31.0")
        
        if 'numpy' in all_code.lower() or 'import numpy' in all_code.lower():
            requirements.add("numpy==1.24.3")
        
        if 'pandas' in all_code.lower() or 'import pandas' in all_code.lower():
            requirements.add("pandas==2.0.3")
        
        if 'matplotlib' in all_code.lower() or 'import matplotlib' in all_code.lower():
            requirements.add("matplotlib==3.7.2")
        
        if 'sqlalchemy' in all_code.lower() or 'from sqlalchemy' in all_code.lower():
            requirements.add("SQLAlchemy==2.0.23")
        
        if 'pytest' in all_code.lower() or 'import pytest' in all_code.lower():
            requirements.add("pytest==7.4.3")
        
        if 'click' in all_code.lower() or 'import click' in all_code.lower():
            requirements.add("click==8.1.7")
        
        if 'python-dotenv' in all_code.lower() or 'from dotenv' in all_code.lower():
            requirements.add("python-dotenv==1.0.0")
        
        # Add common development dependencies
        requirements.add("# Development dependencies")
        requirements.add("black==23.11.0")
        requirements.add("flake8==6.1.0")
        
        # Convert to sorted list (keeping comments at top)
        requirements_list = []
        comments = [req for req in requirements if req.startswith('#')]
        packages = sorted([req for req in requirements if not req.startswith('#')])
        
        # Build final requirements content
        content = "# 🦚 Peacock Generated Requirements\n"
        content += "# Automatically generated Python dependencies\n\n"
        
        for comment in comments:
            if comment not in content:
                content += comment + "\n"
        
        for package in packages:
            content += package + "\n"
        
        # Add a blank line at the end
        content += "\n# Add your custom dependencies below:\n"
        
        return content

    def _generate_readme_md(self, project_name: str, app_type: str, project_files: List[Dict[str, Any]]) -> str:
        """Generate comprehensive README.md documentation"""
        
        # Count different file types
        python_files = [f for f in project_files if f.get('language') == 'python']
        config_files = [f for f in project_files if f.get('filename', '').endswith(('.json', '.yml', '.yaml', '.env'))]
        
        # Detect main application file
        main_file = "main.py"
        entry_points = []
        for file_data in python_files:
            filename = file_data.get('filename', '')
            code = file_data.get('code', '')
            
            if filename in ['app.py', 'main.py', 'run.py', 'server.py']:
                main_file = filename
                entry_points.append(filename)
            elif 'if __name__ == "__main__"' in code:
                entry_points.append(filename)
        
        # Detect framework
        framework = "Python"
        if any('flask' in f.get('code', '').lower() for f in python_files):
            framework = "Flask"
        elif any('django' in f.get('code', '').lower() for f in python_files):
            framework = "Django"
        elif any('fastapi' in f.get('code', '').lower() for f in python_files):
            framework = "FastAPI"
        
        # Generate comprehensive README
        readme_content = f"""# 🦚 {project_name}

> Generated with Peacock AI Development System

A {framework} application built with pure Python - following the championship-tested 7-stage development process.

## ✨ Features

- ✅ Pure Python implementation (no web technologies)
- ✅ Production-ready code structure
- ✅ Comprehensive error handling
- ✅ Auto-setup and dependency management
- ✅ Built with Peacock AI (SPARK → FALCON → EAGLE → HAWK → SYNTHESIS → CODEGEN)

## 📁 Project Structure

```
{project_name.lower().replace(' ', '-')}/
├── {main_file}{'             # Main application entry point' if main_file in [f.get('filename') for f in python_files] else ''}
"""

        # Add file structure
        for file_data in project_files:
            filename = file_data.get('filename', '')
            if filename != main_file:
                readme_content += f"├── {filename}\n"
        
        readme_content += f"""├── requirements.txt    # Python dependencies
├── setup.py           # Auto-installer & runner
└── README.md          # This documentation

```

## 🚀 Quick Start

### Method 1: Auto-Setup (Recommended)
```bash
# Just run the auto-installer
python setup.py
```

### Method 2: Manual Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python {main_file}
```

## 📋 Requirements

- Python 3.8+
- Dependencies listed in `requirements.txt`

## 🔧 Development

### Running the Application
```bash
# Development mode
python {main_file}
"""

        # Add framework-specific instructions
        if framework == "Flask":
            readme_content += """
# The Flask app will start at http://localhost:5000
"""
        elif framework == "Django":
            readme_content += """
# Django development server
python manage.py runserver
"""
        elif framework == "FastAPI":
            readme_content += """
# FastAPI with uvicorn
uvicorn main:app --reload
"""

        readme_content += f"""```

### Code Quality
```bash
# Format code
black .

# Lint code  
flake8 .

# Run tests (if available)
pytest
```

## 📊 Project Stats

- **Framework**: {framework}
- **Python Files**: {len(python_files)}
- **Total Files**: {len(project_files)}
- **Entry Points**: {', '.join(entry_points) if entry_points else main_file}

## 🏗️ Architecture

This project follows the **Peacock 7-Stage Development System**:

1. **🕊️ SPARK** - Requirements analysis and strategic planning
2. **🏎️ FALCON** - System architecture and technical design  
3. **⚔️ EAGLE** - Complete code implementation
4. **🏠 HAWK** - Quality assurance and production readiness
5. **🦉 SYNTHESIS 1** - Project blueprint creation
6. **🦉 SYNTHESIS 2** - Build and test plan generation
7. **🦚 PEACOCK** - Final code generation and deployment

## 📝 Generated Files

"""

        # List all generated files with descriptions
        for file_data in project_files:
            filename = file_data.get('filename', '')
            language = file_data.get('language', 'text')
            
            if language == 'python':
                readme_content += f"- **{filename}** - Python module\n"
            elif filename.endswith('.json'):
                readme_content += f"- **{filename}** - Configuration file\n"
            elif filename.endswith('.txt'):
                readme_content += f"- **{filename}** - Text/data file\n"
            elif filename.endswith('.md'):
                readme_content += f"- **{filename}** - Documentation\n"
            else:
                readme_content += f"- **{filename}** - {language.title()} file\n"

        readme_content += f"""
## 🤝 Contributing

This project was generated by Peacock AI. To contribute:

1. Make your changes
2. Test thoroughly  
3. Follow Python best practices
4. Update documentation as needed

## 📄 License

Generated with [Peacock AI](https://github.com/peacock-ai) - Production-ready Python applications.

## 🦚 About Peacock AI

This project was created using the Peacock AI Development System, which uses a championship-tested 7-stage process to generate production-ready applications. Each stage is handled by specialized AI agents:

- **🕊️ SPARK**: Requirements analysis
- **🏎️ FALCON**: Architecture design  
- **⚔️ EAGLE**: Code implementation
- **🏠 HAWK**: Quality assurance
- **🦉 SYNTHESIS**: Blueprint & build plan creation
- **🦚 PEACOCK**: Final code generation

**Generated**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}  
**Framework**: {framework}  
**Language**: Python {'.'.join(map(str, [3, 8]))}+  

---

*🦚 Built with Peacock AI - Where AI meets production-ready development*
"""

        return readme_content
    
    def _detect_app_type(self, project_files: List[Dict[str, Any]]) -> str:
        """Detect the type of app being packaged"""
        filenames = [f.get("filename", "").lower() for f in project_files]
        
        # Check for Python script
        if any(f.endswith('.py') for f in filenames):
            return "python"
        
        # Check for web app (HTML/CSS/JS)
        has_html = any(f.endswith('.html') or f.endswith('.htm') for f in filenames)
        has_js = any(f.endswith('.js') for f in filenames)
        has_css = any(f.endswith('.css') for f in filenames)
        
        if has_html or has_js or has_css:
            return "web"
        
        # Default to generic
        return "generic"


def create_project_builder() -> ProjectBuilder:
    """Factory function to create ProjectBuilder instance"""
    return ProjectBuilder()


if __name__ == "__main__":
    # Test the project builder
    test_files = [
        {"filename": "app.py", "language": "python", "code": "def hello():\n    print('Hello World')\n\nif __name__ == '__main__':\n    hello()"},
        {"filename": "utils.py", "language": "python", "code": "def helper():\n    return 'Helper function'"}
    ]
    
    builder = create_project_builder()
    result = builder.deploy_and_run(test_files, "Test Project")
    
    print(f"✅ Test completed: {result.get('success')}")
    print(f"📁 Project path: {result.get('project_path')}")
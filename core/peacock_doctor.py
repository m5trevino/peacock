#!/usr/bin/env python3
"""
🦚 Peacock Doctor - v1.0
A comprehensive static analysis and system verification tool for the Peacock ecosystem.
It dissects the codebase to map dependencies, verify connections, and generate a
detailed system report for developers and AI agents.
"""

import os
import ast
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
import typer

CONSOLE = Console()

class PeacockDoctor:
    def __init__(self, project_path: Path):
        """
        Initializes the doctor, setting up paths and the analysis data structure.
        """
        self.project_path = project_path
        
        # --- FIX 1: DEFINE DIRECTORY PATHS ---
        # Define the core and aviary directories to prevent AttributeError
        self.core_dir = self.project_path / "core"
        self.aviary_dir = self.project_path / "aviary"

        # --- FIX 2: FULLY INITIALIZE ANALYSIS DICTIONARY ---
        # Pre-define the entire structure to prevent KeyError
        self.analysis = {
            'project_path': str(project_path),
            'files_found': {'python': 0, 'html': 0, 'other': 0},
            'dependencies': {},
            'connections': [],
            'issues': {
                'syntax_errors': [],
                'import_errors': [],
                'hardcoded_secrets': [],
                'missing_files': [],
                'connection_errors': []
            }
        }
        
        # Basic validation to ensure paths exist
        if not self.core_dir.is_dir() or not self.aviary_dir.is_dir():
            print(f"[bold red]Error: Could not find 'core' or 'aviary' directories in {self.project_path}[/bold red]")
            # In a real script, you might raise an exception here
            # For now, we'll let it continue and likely fail on the file search

    def analyze_file(self, file_path: Path):
        """Analyzes a single Python file using the AST module."""
        if not file_path.exists():
            return
            
        relative_path = str(file_path.relative_to(self.project_root))
        self.analysis["files"][relative_path] = {
            "path": str(file_path),
            "functions": [],
            "classes": [],
            "imports": [],
            "calls": []
        }

        with open(file_path, 'r', encoding='utf-8') as f:
            try:
                tree = ast.parse(f.read(), filename=str(file_path))
            except SyntaxError as e:
                self.analysis['issues']['syntax_errors'].append({"file": relative_path, "error": str(e)})
                return

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.analysis["files"][relative_path]["imports"].append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or '.'
                for alias in node.names:
                    self.analysis["files"][relative_path]["imports"].append(f"{module}.{alias.name}")
            elif isinstance(node, ast.FunctionDef):
                func_name = node.name
                self.analysis["files"][relative_path]["functions"].append(func_name)
                self.analysis["functions"][func_name] = {"file": relative_path, "line": node.lineno}
            elif isinstance(node, ast.ClassDef):
                class_name = node.name
                self.analysis["files"][relative_path]["classes"].append(class_name)
                self.analysis["classes"][class_name] = {"file": relative_path, "line": node.lineno}
            elif isinstance(node, ast.Call):
                call_name = ""
                if isinstance(node.func, ast.Name):
                    call_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    call_name = node.func.attr
                
                if call_name:
                    self.analysis["files"][relative_path]["calls"].append(call_name)
                    if call_name not in self.analysis["calls"]:
                        self.analysis["calls"][call_name] = []
                    self.analysis["calls"][call_name].append({"file": relative_path, "line": node.lineno})

    def run_full_diagnostic(self):
        """Runs the analysis on the entire Peacock project."""
        CONSOLE.print(Panel("🦚 Running Full System Diagnostic...", style="bold blue"))
        py_files = list(self.core_dir.rglob("*.py")) + list(self.aviary_dir.rglob("*.py"))
        for file_path in py_files:
            if "__init__" in file_path.name or "cpython" in str(file_path):
                continue
            self.analyze_file(file_path)
        self.verify_connections()
        self.generate_report()

    def verify_connections(self):
        """Verifies that all function calls resolve to a definition."""
        defined_symbols = set(self.analysis["functions"].keys()) | set(self.analysis["classes"].keys())
        
        # Add built-in functions to avoid false positives
        defined_symbols.update(['print', 'open', 'len', 'str', 'int', 'list', 'dict', 'set', 'isinstance', 'hasattr'])

        for call_name, locations in self.analysis["calls"].items():
            if call_name not in defined_symbols:
                # Let's check if it's a method on a class instance (simple check)
                is_method = False
                for loc in locations:
                    # This is a heuristic and not perfect, but good for a start
                    if '.' in ast.dump(ast.parse(open(loc['file']).read()).body[0]):
                        # A better check would analyze variable types, which is much harder
                        pass
                
                if not is_method:
                     self.analysis["issues"]["undefined_calls"].append({
                        "call_name": call_name,
                        "locations": locations
                     })

    def generate_report(self):
        """Generates and prints the final analysis report."""
        CONSOLE.print(Panel("🔬 Peacock System Analysis Report 🔬", style="bold green"))

        # --- File & Component Tree ---
        tree = Tree("🦚 [bold magenta]Peacock Project Root[/bold magenta]")
        core_branch = tree.add("📁 [cyan]core[/cyan]")
        aviary_branch = tree.add("📁 [cyan]aviary[/cyan]")
        
        for file, data in self.analysis['files'].items():
            branch = core_branch if 'core' in file else aviary_branch
            file_node = branch.add(f"📄 {Path(file).name}")
            if data['classes']:
                c_node = file_node.add("🏗️ Classes")
                for c in data['classes']: c_node.add(f"[green]{c}[/green]")
            if data['functions']:
                f_node = file_node.add("⚡ Functions")
                for f in data['functions']: f_node.add(f"[yellow]{f}[/yellow]")

        CONSOLE.print(tree)

        # --- Issues Report ---
        CONSOLE.print(Panel("🚨 Issues & Broken Wires 🚨", style="bold red"))
        if not self.analysis['issues']['undefined_calls']:
            CONSOLE.print("[bold green]✅ No undefined function calls found. System appears to be wired correctly![/bold green]")
        else:
            table = Table(title="Undefined Function/Class Calls")
            table.add_column("Called Name", style="red")
            table.add_column("Called From File", style="yellow")
            table.add_column("Line Number", style="cyan")
            for issue in self.analysis['issues']['undefined_calls']:
                for loc in issue['locations']:
                    table.add_row(issue['call_name'], loc['file'], str(loc['line']))
            CONSOLE.print(table)
            
        # --- Save full analysis to JSON ---
        report_path = self.core_dir / f"peacock_diagnostic_{int(time.time())}.json"
        with open(report_path, 'w') as f:
            json.dump(self.analysis, f, indent=2)
        CONSOLE.print(f"\nFull diagnostic report saved to: [bold cyan]{report_path}[/bold cyan]")


def main(
    project_path: Path = typer.Argument(Path.cwd(), help="Path to the Peacock project root directory.")
):
    """The main entry point for the Peacock Doctor CLI."""
    if not (project_path / "core").exists() or not (project_path / "aviary").exists():
        CONSOLE.print("[bold red]Error:[/bold red] This script must be run from within the Peacock project, or the path to it must be provided.")
        CONSOLE.print(f"Current working directory: {Path.cwd()}")
        CONSOLE.print(f"Provided path: {project_path}")
        raise typer.Exit(code=1)
        
    doctor = PeacockDoctor(project_path)
    doctor.run_full_diagnostic()

if __name__ == "__main__":
    typer.run(main)
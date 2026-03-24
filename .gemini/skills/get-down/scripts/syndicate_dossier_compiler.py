#!/usr/bin/env python3
"""
💀 SYNDICATE MISSION DOSSIER COMPILER v1.0 💀
Manifests the entire project logic stream into one unified truth.
"""

import os
import json
import subprocess
from pathlib import Path
from datetime import datetime

# Optional tree-sitter for logic mapping
try:
    from tree_sitter import Language, Parser
    import tree_sitter_python as tspython
    TS_AVAILABLE = True
except ImportError:
    TS_AVAILABLE = False

# ============================================================
# 🏛️ CONFIGURATION
# ============================================================
PROJECT_ROOT = Path("/home/flintx/antivibe")
OUTPUT_FILE = PROJECT_ROOT / "ANTIVIBE_MISSION_DOSSIER.txt"
SYNDICATE_DIR = PROJECT_ROOT / "syndicate_33"
MANIFESTO_FILE = PROJECT_ROOT / "SYNDICATE_43_MANIFESTO.md"
STATE_FILE = PROJECT_ROOT / "PROJECT_STATE_COLD_START.md"

# ============================================================
# 📊 THE NARRATIVE LAYER (SYNTHESIS)
# ============================================================
def get_mission_intelligence() -> str:
    intel = []
    intel.append("══════════════════════════════════════════════════════════════════════")
    intel.append("💀 SECTION 1: MISSION INTELLIGENCE (THE WHY) 💀")
    intel.append("══════════════════════════════════════════════════════════════════════\n")

    # Pull from Manifesto
    if MANIFESTO_FILE.exists():
        intel.append("--- [SYNDICATE MANIFESTO] ---")
        intel.append(MANIFESTO_FILE.read_text().strip())
        intel.append("\n")

    # Pull from State Doc
    if STATE_FILE.exists():
        intel.append("--- [CURRENT STATE & PIVOTS] ---")
        intel.append(STATE_FILE.read_text().strip())
        intel.append("\n")

    intel.append("--- [OPERATOR'S LOG: THE RECENT PIVOT] ---")
    intel.append("MISSION PIVOT DETECTED: 2026-03-24")
    intel.append("- Social Lube project successfully extracted and moved to /home/flintx/social-lube/")
    intel.append("- Antivibe re-focused as 100% Logic Compiler Factory (Syndicate 43 HQ).")
    intel.append("- Vaults (Diamonds) secured in private repo: github.com/m5trevino/diamonds.")
    intel.append("- Public branch 'antivibe' initialized in github.com/m5trevino/peacock.")
    intel.append("\n")

    return "\n".join(intel)

# ============================================================
# 🔍 THE LOGIC MAP (TREE-SITTER)
# ============================================================
def get_logic_map() -> str:
    if not TS_AVAILABLE:
        return "⚠️ Logic Map limited: tree-sitter-python not detected in environment.\n"

    logic_map = []
    logic_map.append("══════════════════════════════════════════════════════════════════════")
    logic_map.append("💀 SECTION 2: LOGIC MAP (THE WHAT) 💀")
    logic_map.append("══════════════════════════════════════════════════════════════════════\n")

    parser = Parser(Language(tspython.language()))

    for py_file in PROJECT_ROOT.rglob("*.py"):
        # Respect gitignore (simplified check)
        if ".venv" in str(py_file) or "__pycache__" in str(py_file):
            continue

        rel_path = py_file.relative_to(PROJECT_ROOT)
        logic_map.append(f"FILE: {rel_path}")

        try:
            source = py_file.read_bytes()
            tree = parser.parse(source)

            # Simple walk to find functions and classes
            cursor = tree.walk()

            def walk_nodes(node, depth=0):
                if node.type == 'function_definition':
                    # Extract function name
                    name_node = next((child for child in node.children if child.type == 'identifier'), None)
                    if name_node:
                        func_name = source[name_node.start_byte:name_node.end_byte].decode('utf-8')
                        logic_map.append(f"  {'  ' * depth}λ [FUNC] {func_name}")
                elif node.type == 'class_definition':
                    name_node = next((child for child in node.children if child.type == 'identifier'), None)
                    if name_node:
                        class_name = source[name_node.start_byte:name_node.end_byte].decode('utf-8')
                        logic_map.append(f"  {'  ' * depth}⌬ [CLASS] {class_name}")

                for child in node.children:
                    walk_nodes(child, depth + 1)

            walk_nodes(tree.root_node)
            logic_map.append("")

        except Exception as e:
            logic_map.append(f"  ⚠️ Error parsing: {e}")

    return "\n".join(logic_map)

# ============================================================
# 💉 THE SOURCE STREAM (THE MARROW)
# ============================================================
def get_source_stream() -> str:
    stream = []
    stream.append("══════════════════════════════════════════════════════════════════════")
    stream.append("💀 SECTION 3: SOURCE STREAM (THE MARROW) 💀")
    stream.append("══════════════════════════════════════════════════════════════════════\n")

    # Use git to get tracked files only
    try:
        files = subprocess.check_output(
            ["git", "ls-files"],
            cwd=PROJECT_ROOT
        ).decode().splitlines()
    except subprocess.CalledProcessError:
        # Fallback if not a git repo yet
        files = []
        for ext in ["py", "md", "txt", "sh"]:
            for f in PROJECT_ROOT.rglob(f"*.{ext}"):
                if ".venv" not in str(f) and "__pycache__" not in str(f):
                    files.append(str(f.relative_to(PROJECT_ROOT)))

    for f_path in sorted(files):
        full_path = PROJECT_ROOT / f_path
        if not full_path.exists() or full_path.is_dir():
            continue
        if full_path == OUTPUT_FILE:
            continue

        stream.append("══════════════════════════════════════════════════════════════════════")
        stream.append(f"FILE: {f_path}")
        stream.append("══════════════════════════════════════════════════════════════════════")

        try:
            content = full_path.read_text(errors='ignore').strip()
            stream.append(content)
        except Exception as e:
            stream.append(f"⚠️ Error reading file: {e}")

        stream.append("\n")

    return "\n".join(stream)

# ============================================================
# 🚀 MAIN MANIFESTATION
# ============================================================
def main():
    print("\n\033[1;96m💀 SYNDICATE DOSSIER COMPILER v1.0 💀\033[0m")
    print(f"\033[1;90mTarget: {OUTPUT_FILE}\033[0m\n")

    intel = get_mission_intelligence()
    l_map = get_logic_map()
    marrow = get_source_stream()

    full_dossier = f"""
╔══════════════════════════════════════════════════════════════════════╗
║         💀 SYNDICATE 43: MISSION DOSSIER (ANTIVIBE) 💀             ║
║         GENERATED: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}                     ║
╚══════════════════════════════════════════════════════════════════════╝

{intel}

{l_map}

{marrow}

══════════════════════════════════════════════════════════════════════
🎯 END OF DOSSIER - 100% RESOLUTION 🎯
══════════════════════════════════════════════════════════════════════
"""

    OUTPUT_FILE.write_text(full_dossier)
    print(f"\033[1;92m✓ Dossier Manifested: {OUTPUT_FILE.name}\033[0m")
    print(f"\033[1;90mSize: {len(full_dossier)} bytes\033[0m\n")

if __name__ == "__main__":
    main()

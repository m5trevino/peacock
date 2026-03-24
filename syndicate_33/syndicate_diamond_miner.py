#!/usr/bin/env python3
"""
💎 SYNDICATE DIAMOND MINER v5.0 💎
Optimized for Invariant Law Extraction
Output: Ready-to-process shards for Trevino Doctrine LLM pipeline
"""

import os
import json
import sys
import hashlib
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import subprocess

# Tree-sitter imports
try:
    from tree_sitter import Language, Parser, Node
    import tree_sitter_python as tspython
    import tree_sitter_javascript as tsjs
    import tree_sitter_typescript as tsts
    import tree_sitter_go as tsgo
    import tree_sitter_rust as tsrust
except ImportError:
    print("\033[1;31m💀 Missing Tree-sitter packages\033[0m")
    print("pip install tree-sitter tree-sitter-python tree-sitter-javascript tree-sitter-typescript tree-sitter-go tree-sitter-rust")
    sys.exit(1)

# ============================================================
# 💎 CONFIGURATION
# ============================================================
SCRIPT_REPOS_ROOT = Path("/home/flintx/antivibe/script-repos")
DIAMOND_OUTPUT_DIR = Path("/home/flintx/antivibe/syndicate_33/diamond_shards")

# Language mappings
EXT_TO_LANG = {
    '.py': 'python',
    '.js': 'javascript',
    '.jsx': 'javascript', 
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.go': 'go',
    '.rs': 'rust',
}

LANGUAGES: Dict[str, Language] = {
    "python": Language(tspython.language()),
    "javascript": Language(tsjs.language()),
    "typescript": Language(tsts.language_typescript()),
    "go": Language(tsgo.language()),
    "rust": Language(tsrust.language()),
}

# ============================================================
# 💎 INVARIANT NODE TYPES (High-Value Extraction Targets)
# ============================================================
DIAMOND_NODES = {
    # Functions - the core logic carriers
    'function_definition', 'function_declaration', 'function_item',
    'method_definition', 'method_declaration', 'impl_item',
    'arrow_function', 'generator_function',
    
    # Classes/Structs - architectural blueprints
    'class_definition', 'class_declaration', 'struct_item', 
    'struct_definition', 'interface_declaration', 'trait_item',
    
    # Control flow - decision logic
    'if_statement', 'match_expression', 'match_arm',
    'try_statement', 'catch_clause', 'finally_clause',
    'for_statement', 'while_statement', 'loop_expression',
    
    # Concurrency - the hard stuff
    'async_function', 'async_arrow_function', 'await_expression',
    'goroutine', 'channel_operation', 'select_statement',
    'spawn_expression',
    
    # State management
    'const_declaration', 'let_declaration', 'static_item',
    'variable_declaration', 'field_declaration',
    
    # Types - contracts and boundaries  
    'type_alias_declaration', 'enum_declaration', 'enum_item',
    'interface_declaration', 'impl_block',
}

# ============================================================
# 💎 JUNK FILTERS (Aggressive)
# ============================================================
JUNK_DIRS = {
    '.git', 'node_modules', 'vendor', 'dist', 'build', 'out',
    'coverage', 'tests', 'test', '__tests__', '__mocks__',
    '__pycache__', '.next', 'target', 'venv', '.venv',
    'env', 'logs', 'docs', 'examples', 'scripts',
    '.github', '.vscode', '.idea', 'public', 'assets',
    'static', 'migrations', 'seeds', 'fixtures', 'tmp', 'temp'
}

JUNK_PATTERNS = [
    '.min.', '.bundle.', '.spec.', '.test.', '.d.ts',
    'eslint', 'babel', 'jest', 'webpack', 'rollup', 'vite',
    'prettier', 'tsconfig', 'package.json', 'yarn.lock',
    'pnpm-lock', 'Dockerfile', 'Makefile', '.editorconfig',
    '.gitignore', 'README', 'LICENSE', 'CHANGELOG',
    'CONTRIBUTING', 'CODE_OF_CONDUCT'
]

# ============================================================
# 💎 DIAMOND SHARD (Output Format)
# ============================================================
@dataclass
class DiamondShard:
    """A single extract ready for Trevino Doctrine processing"""
    shard_id: str
    repo: str
    file_path: str
    family: str  # Language family
    element_type: str  # Function, Class, etc.
    content: str  # The actual code
    context: str  # Surrounding context (imports, class signature)
    line_start: int
    line_end: int
    complexity_score: int
    
    def to_prompt_format(self) -> str:
        """Format for Trevino Doctrine LLM prompt"""
        return f"""SOURCE: {self.file_path}
FAMILY: {self.family}
ELEMENT: {self.element_type}
LINES: {self.line_start}-{self.line_end}

```
{self.content}
```

CONTEXT:
{self.context}
"""

# ============================================================
# 💎 PARSER FUNCTIONS
# ============================================================
def get_parser(lang: str) -> Optional[Parser]:
    if lang not in LANGUAGES:
        return None
    return Parser(LANGUAGES[lang])

def is_junk_file(path: Path) -> bool:
    name_lower = path.name.lower()
    return any(pat in name_lower for pat in JUNK_PATTERNS)

def is_junk_dir(name: str) -> bool:
    nl = name.lower()
    return nl in JUNK_DIRS or nl.startswith(('.', '_'))

def calculate_complexity(node: Node) -> int:
    """Calculate cyclomatic complexity proxy"""
    score = 1
    cursor = node.walk()
    
    complexity_nodes = {
        'if_statement', 'if_expression',
        'for_statement', 'for_expression', 'while_statement', 'while_expression',
        'match_expression', 'match_arm', 'case',
        'try_statement', 'catch_clause',
        'and', 'or', '&&', '||',
        'ternary_expression', 'conditional_expression'
    }
    
    def recurse(n):
        nonlocal score
        if n.type in complexity_nodes:
            score += 1
        for child in n.children:
            recurse(child)
    
    recurse(node)
    return min(score, 20)  # Cap at 20

def extract_context(root_node: Node, target_node: Node, source: bytes) -> str:
    """Extract imports and class/module context"""
    context_parts = []
    
    # Get imports/includes
    for child in root_node.children:
        if child.type in ('import_statement', 'import_declaration', 'import_spec',
                         'use_declaration', 'use_statement', 'extern_crate'):
            imp_text = source[child.start_byte:child.end_byte].decode('utf-8', errors='ignore')
            if len(imp_text) < 200:  # Only short imports
                context_parts.append(imp_text.strip())
    
    # Get parent class/trait if exists
    parent = target_node.parent
    while parent:
        if parent.type in ('class_declaration', 'class_definition', 'impl_item', 
                          'trait_item', 'interface_declaration'):
            parent_sig = source[parent.start_byte:parent.start_byte + 200].decode('utf-8', errors='ignore')
            context_parts.append(f"\nPARENT: {parent_sig.split('{')[0].strip()}")
            break
        parent = parent.parent
    
    return '\n'.join(context_parts[:10])  # Limit context

def extract_diamonds(node: Node, source: bytes, file_path: str, repo: str, 
                     lang: str, shards: List[DiamondShard], min_lines: int = 3):
    """Recursively extract invariant-bearing code structures"""
    
    if node.type in DIAMOND_NODES:
        # Extract the full text
        text = source[node.start_byte:node.end_byte].decode('utf-8', errors='ignore')
        
        # Skip if too small
        lines = text.count('\n') + 1
        if lines < min_lines or len(text) < 100:
            return
        
        # Skip if mostly comments/strings
        code_ratio = sum(1 for c in text if c.isalnum() or c in '{}();=') / max(len(text), 1)
        if code_ratio < 0.3:
            return
        
        # Create shard
        shard_id = hashlib.sha256(f"{file_path}:{node.start_byte}".encode()).hexdigest()[:16]
        
        shard = DiamondShard(
            shard_id=shard_id,
            repo=repo,
            file_path=file_path,
            family=lang.upper(),
            element_type=node.type.replace('_', ' ').title(),
            content=text,
            context=extract_context(node.tree_root, node, source),
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            complexity_score=calculate_complexity(node)
        )
        
        shards.append(shard)
        return  # Don't recurse into diamonds
    
    # Recurse into children
    for child in node.children:
        extract_diamonds(child, source, file_path, repo, lang, shards, min_lines)

# ============================================================
# 💎 FILE PROCESSING
# ============================================================
def process_file(filepath: Path, repo: str) -> List[DiamondShard]:
    """Process a single file and return diamond shards"""
    
    if is_junk_file(filepath):
        return []
    
    ext = filepath.suffix.lower()
    if ext not in EXT_TO_LANG:
        return []
    
    lang = EXT_TO_LANG[ext]
    parser = get_parser(lang)
    if not parser:
        return []
    
    try:
        source = filepath.read_bytes()
        if len(source) < 200 or len(source) > 500000:  # Skip tiny/huge files
            return []
        
        tree = parser.parse(source)
        shards = []
        extract_diamonds(tree.root_node, source, str(filepath), repo, lang, shards)
        
        return shards
        
    except Exception as e:
        print(f"  \033[1;33m⚠️  Parse error {filepath}: {e}\033[0m")
        return []

# ============================================================
# 💎 OUTPUT FORMATTING
# ============================================================
def save_shards_for_llm(shards: List[DiamondShard], output_dir: Path, repo: str):
    """Save shards in format ready for Trevino Doctrine LLM processing"""
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Group by complexity for batching strategy
    simple = [s for s in shards if s.complexity_score <= 5]
    medium = [s for s in shards if 5 < s.complexity_score <= 10]
    complex_shards = [s for s in shards if s.complexity_score > 10]
    
    batches = {
        'simple': simple,
        'medium': medium,
        'complex': complex_shards
    }
    
    saved_count = 0
    
    for batch_name, batch_shards in batches.items():
        for i, shard in enumerate(batch_shards):
            # Create filename: repo_complexity_idx_hash.prompt
            filename = f"{repo}_{batch_name}_{i:04d}_{shard.shard_id}.prompt"
            filepath = output_dir / filename
            
            # Write in Trevino Doctrine ready format
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(shard.to_prompt_format())
            
            saved_count += 1
    
    return saved_count

def save_manifest(shards: List[DiamondShard], output_dir: Path, repo: str):
    """Save a manifest JSON for tracking"""
    manifest = {
        "repo": repo,
        "extracted_at": datetime.now().isoformat(),
        "total_shards": len(shards),
        "by_family": {},
        "by_element": {},
        "complexity_distribution": {
            "simple": len([s for s in shards if s.complexity_score <= 5]),
            "medium": len([s for s in shards if 5 < s.complexity_score <= 10]),
            "complex": len([s for s in shards if s.complexity_score > 10])
        },
        "shards": [
            {
                "shard_id": s.shard_id,
                "file_path": s.file_path,
                "family": s.family,
                "element_type": s.element_type,
                "complexity": s.complexity_score,
                "lines": s.line_end - s.line_start
            }
            for s in shards[:1000]  # Limit manifest size
        ]
    }
    
    # Count by family/element
    for s in shards:
        manifest["by_family"][s.family] = manifest["by_family"].get(s.family, 0) + 1
        manifest["by_element"][s.element_type] = manifest["by_element"].get(s.element_type, 0) + 1
    
    manifest_path = output_dir / f"_manifest_{repo}.json"
    with open(manifest_path, 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=2)
    
    return manifest_path

# ============================================================
# 💎 REPO PROCESSING
# ============================================================
def find_repos(root: Path) -> List[Path]:
    """Find git repos under root"""
    repos = []
    if (root / '.git').is_dir():
        return [root]
    for item in root.iterdir():
        if item.is_dir() and (item / '.git').is_dir():
            repos.append(item)
    return sorted(repos)

def process_repo(repo_path: Path, output_dir: Path) -> Tuple[int, int]:
    """Process a repo and return (files_processed, shards_created)"""
    
    repo_name = repo_path.name
    print(f"\n\033[1;96m💎 Mining {repo_name}...\033[0m")
    
    all_shards = []
    files_processed = 0
    
    for root, dirs, files in os.walk(repo_path, topdown=True):
        # Filter junk dirs
        dirs[:] = [d for d in dirs if not is_junk_dir(d)]
        
        for file in files:
            filepath = Path(root) / file
            shards = process_file(filepath, repo_name)
            if shards:
                all_shards.extend(shards)
                files_processed += 1
                
                if files_processed % 50 == 0:
                    print(f"  \033[1;90m{files_processed} files | {len(all_shards)} shards\033[0m", end='\r')
    
    # Save results
    if all_shards:
        saved = save_shards_for_llm(all_shards, output_dir, repo_name)
        manifest = save_manifest(all_shards, output_dir, repo_name)
        
        print(f"  \033[1;92m✓ {files_processed} files → {len(all_shards)} shards → {saved} prompts\033[0m")
        print(f"  \033[1;90m  Manifest: {manifest.name}\033[0m")
    else:
        print(f"  \033[1;33m⚠️ No diamonds found\033[0m")
    
    return files_processed, len(all_shards)

# ============================================================
# 💎 MAIN
# ============================================================
def main():
    print("\033[1;95m" + "="*70)
    print("💎 SYNDICATE DIAMOND MINER v5.0 💎")
    print("   Optimized for Invariant Law Extraction")
    print("="*70 + "\033[0m\n")
    
    # Get input path
    print("Enter path to repo or directory containing repos:")
    raw = input("> ").strip()
    
    if not raw:
        print("\033[1;31mNo path entered. Exiting.\033[0m")
        return
    
    root = Path(raw).expanduser().resolve()
    if not root.exists():
        print(f"\033[1;31mPath not found: {root}\033[0m")
        return
    
    # Find repos
    repos = find_repos(root)
    if not repos:
        print("\033[1;31mNo git repositories found.\033[0m")
        return
    
    print(f"\n\033[1;92mFound {len(repos)} repo(s):\033[0m")
    for r in repos:
        print(f"  • {r.name}")
    
    # Confirm
    if input("\nProceed? [Y/n]: ").strip().lower() not in ('y', 'yes', ''):
        print("Aborted.")
        return
    
    # Output dir
    output_dir = DIAMOND_OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"\n\033[1;94mOutput: {output_dir}\033[0m\n")
    
    # Process all repos
    total_files = 0
    total_shards = 0
    
    for repo in repos:
        files, shards = process_repo(repo, output_dir)
        total_files += files
        total_shards += shards
    
    # Summary
    print("\n" + "\033[1;96m" + "="*70)
    print("💎 EXTRACTION COMPLETE 💎")
    print("="*70 + "\033[0m")
    print(f"\nTotal Files Processed: {total_files}")
    print(f"Total Diamond Shards:  {total_shards}")
    print(f"Output Directory:      {output_dir}")
    
    # List prompt files created
    prompt_files = list(output_dir.glob("*.prompt"))
    print(f"Prompt Files Ready:    {len(prompt_files)}")
    
    print("\n\033[1;92mReady for Trevino Doctrine LLM pipeline.\033[0m")
    print(f"\033[1;90mRun: python3 syndicate_master_governor.py\033[0m\n")

if __name__ == "__main__":
    main()

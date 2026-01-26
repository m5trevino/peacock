import os
import json
from pathlib import Path
from typing import List, Dict, Any
from app.config import AMMO_DIR, START_DIR, PROMPTS_DIR, SESSIONS_DIR, REFINED_DIR

def get_files_with_meta(directory: str) -> List[Dict[str, Any]]:
    path = Path(directory)
    if not path.exists():
        return []
    
    files = []
    for f in path.iterdir():
        if f.is_file() and not f.name.startswith('.'):
            stats = f.stat()
            files.append({
                "name": f.name,
                "modified": stats.st_mtime,
                "created": stats.st_ctime
            })
    return sorted(files, key=lambda x: x['modified'], reverse=True)

def read_file_content(directory: str, filename: str) -> str:
    path = Path(directory) / filename
    if not path.exists():
        raise FileNotFoundError(f"File {filename} not found in {directory}")
    return path.read_text(encoding='utf-8')

def secure_prompt(phase: str, name: str, content: str):
    path = Path(PROMPTS_DIR) / phase
    path.mkdir(parents=True, exist_ok=True)
    file_path = path / f"{name}.md"
    file_path.write_text(content, encoding='utf-8')

def list_prompts(phase: str) -> List[Dict[str, str]]:
    path = Path(PROMPTS_DIR) / phase
    if not path.exists():
        return []
    
    prompts = []
    for f in path.glob("*.md"):
        prompts.append({
            "id": f.name,
            "name": f.stem,
            "phase": phase,
            "content": f.read_text(encoding='utf-8')
        })
    return prompts

def save_session(name: str, data: Dict[str, Any]):
    path = Path(SESSIONS_DIR)
    path.mkdir(parents=True, exist_ok=True)
    file_path = path / name
    file_path.write_text(json.dumps(data, indent=2), encoding='utf-8')

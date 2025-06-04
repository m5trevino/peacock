#!/usr/bin/env python3

# START ### IMPORTS ###
import re
import os
import sys
import json
import time
import subprocess
import psutil
import requests
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt # Keep Prompt as original script uses it
from rich.table import Table
from rich.style import Style
from huggingface_hub import HfApi, hf_hub_download, model_info, list_repo_files, snapshot_download
# Import specific exceptions for better error handling
from huggingface_hub.utils import GatedRepoError, RepositoryNotFoundError, HFValidationError
from requests.exceptions import HTTPError as RequestsHTTPError
from tqdm import tqdm
import logging # For FastAPI script logging
import shlex # For escaping GGUF command
from packaging import version as pkg_version # Needed for llama.cpp version check

# Conditional imports for specific functionalities
try: import llama_cpp; LLAMA_CPP_AVAILABLE=True
except ImportError: LLAMA_CPP_AVAILABLE=False

try: import torch; TORCH_AVAILABLE=True
except ImportError: TORCH_AVAILABLE=False

try: import transformers; TRANSFORMERS_AVAILABLE=True
except ImportError: TRANSFORMERS_AVAILABLE=False

try: import accelerate; ACCELERATE_AVAILABLE=True
except ImportError: ACCELERATE_AVAILABLE=False

try: from transformers import BitsAndBytesConfig; BITSANDBYTES_AVAILABLE=True
except ImportError: BITSANDBYTES_AVAILABLE=False

try: import fastapi; FASTAPI_AVAILABLE=True
except ImportError: FASTAPI_AVAILABLE=False

try: import uvicorn; UVICORN_AVAILABLE=True
except ImportError: UVICORN_AVAILABLE=False

try: from pydantic import BaseModel, Field; PYDANTIC_AVAILABLE=True
except ImportError: PYDANTIC_AVAILABLE=False
# FINISH ### IMPORTS ###

# START ### CONSOLE SETUP ###
console = Console()
CYBER_STYLES = {
    'neon_green': Style(color="green1", bold=True),
    'cyber_purple': Style(color="purple", bold=True),
    'cyber_orange': Style(color="orange1", bold=True),
    'matrix_text': Style(color="green4"),
    'error_red': Style(color="red1", bold=True),
    'warn_yellow': Style(color="yellow1", bold=True),
    'info_blue': Style(color="cyan", bold=True),
    'dim_text': Style(color="grey50", dim=True, italic=True),
}

def print_styled(text, style_name):
    if style_name in CYBER_STYLES:
        console.print(text, style=CYBER_STYLES[style_name])
    else:
        console.print(f"[yellow]Warning: Invalid style '{style_name}'. Using default.[/yellow]")
        console.print(text)
# FINISH ### CONSOLE SETUP ###

# START ### CONSTANTS ###
GGUF_BASE_MODEL_DIR = Path.home() / "models"
GGUF_CONFIG_DIR = Path.home() / "deploy.bolt" / "config"
GGUF_SCRIPT_DIR = Path.home() / "deploy.bolt" / "scripts"
MODEL_DB_PATH = Path.home() / ".local" / "share" / "llm_models.json"
FASTAPI_SCRIPT_DIR = Path("/home/flintx/deploy.bolt/scripts/")
QUANT_INFO = { 'Q2_K': {'quality': 'Lowest', 'size': 'Smallest', 'ram': '4-8GB'}, 'Q3_K_M': {'quality': 'Low', 'size': 'Very Small', 'ram': '6-10GB'}, 'Q4_0': {'quality': 'Medium-Low', 'size': 'Small', 'ram': '8-12GB'}, 'Q4_K_M': {'quality': 'Medium', 'size': 'Medium', 'ram': '8-12GB'}, 'Q5_0': {'quality': 'Medium-High', 'size': 'Medium-Large', 'ram': '10-14GB'}, 'Q5_K_M': {'quality': 'High', 'size': 'Large', 'ram': '10-14GB'}, 'Q6_K': {'quality': 'Very High', 'size': 'Very Large', 'ram': '12-16GB'}, 'Q8_0': {'quality': 'Highest', 'size': 'Largest', 'ram': '16GB+'} }
# FINISH ### CONSTANTS ###

# START ### SYSTEM SPECS ###
def check_system_specs():
    try:
        ram = psutil.virtual_memory().total / (1024**3); gpu_ram = 0; gpu_name = None
        try:
            if TORCH_AVAILABLE and torch.cuda.is_available():
                if torch.cuda.device_count() > 0:
                     gpu_ram = torch.cuda.get_device_properties(0).total_memory / (1024**3)
                     gpu_name = torch.cuda.get_device_name(0)
                else: console.print("[yellow]Warning: torch.cuda.is_available()=True, but device_count=0.[/yellow]")
        except Exception as gpu_check_err: console.print(f"[yellow]Warning: GPU check failed ({gpu_check_err}).[/yellow]")
        quant = "Q4_K_M"
        if ram < 8: quant = "Q2_K"
        elif ram < 12: quant = "Q3_K_M"
        elif ram < 16: quant = "Q4_K_M"
        elif ram < 24: quant = "Q5_K_M"
        elif ram >= 24: quant = "Q6_K"
        return { "total_ram": ram, "gpu_ram": gpu_ram, "gpu_name": gpu_name, "recommended_quant": quant }
    except Exception as e: console.print(f"[red]Error checking system specs: {str(e)}[/red]"); return None
# FINISH ### SYSTEM SPECS ###

# START ### URL VALIDATION ###
def validate_hf_url(url):
    if not url: return None
    patterns = [ r'https?://huggingface\.co/([^/]+/[^/]+)(?:/tree/main)?/?$', r'^([^/]+/[^/]+)$' ]
    for pattern in patterns:
        match = re.match(pattern, url.strip())
        if match: return match.group(1)
    return None
# FINISH ### URL VALIDATION ###

# START ### MODEL INFO & FILE HANDLING ###
def get_model_files(repo_id):
    try: api = HfApi(); files = api.list_repo_files(repo_id, token=os.environ.get("HUGGING_FACE_HUB_TOKEN"))
    except RepositoryNotFoundError: console.print(f"[red]Repository not found: {repo_id}[/red]"); return None, None
    except GatedRepoError: console.print(f"[yellow]Repo {repo_id} is gated. Listing may be incomplete.[/yellow]"); files = []
    except Exception as e: console.print(f"[red]Error listing repo files for {repo_id}: {str(e)}[/red]"); return None, None
    gguf_files = [f for f in files if f.lower().endswith('.gguf')]
    other_files = [f for f in files if not f.lower().endswith('.gguf')]
    return gguf_files, other_files

def get_file_size(repo_id, file_name):
    try: from huggingface_hub.utils import build_hf_headers; url = f"https://huggingface.co/{repo_id}/resolve/main/{file_name}"
    except HFValidationError: console.print(f"[red]Invalid repo/file format: {repo_id}/{file_name}[/red]"); return None
    try:
        headers = build_hf_headers(token=os.environ.get("HUGGING_FACE_HUB_TOKEN")); response = requests.head(url, headers=headers, allow_redirects=True, timeout=30)
        response.raise_for_status(); size = 0
        if "x-linked-size" in response.headers: size = int(response.headers["x-linked-size"])
        elif "content-length" in response.headers: size = int(response.headers["content-length"])
        else: return None
        return size / (1024**3)
    except RequestsHTTPError as e:
        if e.response.status_code == 401: console.print(f"[yellow]Warn: Auth error getting size for {file_name}.[/yellow]")
        elif e.response.status_code == 403: console.print(f"[yellow]Warn: Access denied getting size for {file_name}.[/yellow]")
        elif e.response.status_code == 404: console.print(f"[yellow]Warn: File not found getting size for {file_name}.[/yellow]")
        else: console.print(f"[yellow]Warn: HTTP {e.response.status_code} getting size for {file_name}.[/yellow]")
        return None
    except Exception as e: console.print(f"[yellow]Warn: Couldn't get size for {file_name}: {e}[/yellow]"); return None
# FINISH ### MODEL INFO & FILE HANDLING ###

# START ### MODEL ANALYZER ###
def analyze_model(repo_id):
    try: info = model_info(repo_id, token=os.environ.get("HUGGING_FACE_HUB_TOKEN")); table = Table(title=f"Model Info: {repo_id}")
    except RepositoryNotFoundError: console.print(f"[red]Repo not found: {repo_id}[/red]"); return None
    except GatedRepoError: console.print(f"[yellow]Repo {repo_id} is gated. Info may require access.[/yellow]"); return None
    except Exception as e: console.print(f"[red]Couldn't get model info: {str(e)}[/red]"); return None
    table.add_column("Property", style="cyan"); table.add_column("Value", style="yellow")
    if info.tags: table.add_row("Tags", ", ".join(info.tags))
    if info.pipeline_tag: table.add_row("Pipeline", info.pipeline_tag)
    if info.downloads: table.add_row("Downloads", str(info.downloads))
    if info.likes: table.add_row("Likes", str(info.likes))
    console.print(table); return info
# FINISH ### MODEL ANALYZER ###

# START ### MODEL DATABASE ###
def get_model_database():
    MODEL_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    if MODEL_DB_PATH.exists():
        try:
            with open(MODEL_DB_PATH) as f: data = json.load(f)
            if isinstance(data, dict) and "models" in data and isinstance(data['models'], dict): return data
            else: console.print(f"[yellow]DB file {MODEL_DB_PATH} invalid format. Resetting.[/yellow]"); return {"models": {}}
        except Exception as e: console.print(f"[red]Error reading DB {MODEL_DB_PATH}: {e}. Resetting.[/red]"); return {"models": {}}
    return {"models": {}}

def save_model_database(db):
    temp_db_path = MODEL_DB_PATH.with_suffix(MODEL_DB_PATH.suffix + '.tmp')
    try: MODEL_DB_PATH.parent.mkdir(parents=True, exist_ok=True);
    except Exception as dir_err: print_styled(f"Error creating DB dir: {dir_err}", "error_red"); return
    try:
        with open(temp_db_path, "w") as f: json.dump(db, f, indent=2); os.replace(temp_db_path, MODEL_DB_PATH)
    except Exception as e: print_styled(f"Error saving database: {str(e)}", "error_red")
    finally:
          if temp_db_path.exists():
              try: temp_db_path.unlink()
              except OSError: pass

def update_gguf_db_entry(repo_id, file_name, local_path, model_info_dict):
     db = get_model_database(); models_db = db.setdefault("models", {})
     repo_entry = models_db.setdefault(repo_id, {"files": {}, "info": {}, "type": "gguf"})
     repo_entry["type"] = "gguf"; repo_entry.setdefault("files", {})[file_name] = str(local_path)
     # Ensure info is a dict before trying to update
     if not isinstance(repo_entry.get("info"), dict): repo_entry["info"] = {}
     if model_info_dict: repo_entry["info"].update(model_info_dict) # Update with new info
     save_model_database(db)

def update_transformers_db_entry(repo_id, cache_dir):
    db = get_model_database(); models_db = db.setdefault("models", {})
    repo_entry = models_db.setdefault(repo_id, {"cache": {}, "info": {}, "type": "transformers"})
    repo_entry["type"] = "transformers"; repo_entry["cache"] = { "path": str(cache_dir), "cached_at": time.strftime("%Y-%m-%d %H:%M:%S") }
    save_model_database(db)

# THIS function checks the DB first, THEN filesystem if DB fails (as per original design)
def check_gguf_exists_in_db(repo_id, file_name):
    db = get_model_database()
    file_path_str = db.get("models", {}).get(repo_id, {}).get("files", {}).get(file_name)
    if file_path_str and Path(file_path_str).exists() and Path(file_path_str).is_file(): return file_path_str
    # Fallback check removed here - keep original behavior
    return None

# THIS function checks DB first, then default cache if DB fails
def check_transformers_cache_in_db(repo_id):
    db = get_model_database()
    cache_path_str = db.get("models", {}).get(repo_id, {}).get("cache", {}).get("path")
    if cache_path_str:
        cache_path = Path(cache_path_str)
        config_json_path = cache_path / "config.json"
        if cache_path.exists() and cache_path.is_dir() and config_json_path.exists(): return cache_path_str
    try:
        from huggingface_hub.constants import HUGGINGFACE_HUB_CACHE
        hf_cache_path = Path(HUGGINGFACE_HUB_CACHE); mangled_repo = "models--" + repo_id.replace("/", "--")
        potential_cache_root = hf_cache_path / mangled_repo
        if potential_cache_root.is_dir() and (potential_cache_root / "config.json").exists(): return str(potential_cache_root)
    except Exception: pass
    return None
# FINISH ### MODEL DATABASE ###

# START ### GGUF DOWNLOAD MANAGER ###
# *** MODIFIED setup_model_directory ***
def setup_model_directory(model_name, quant_type):
    """Set up GGUF model directory, avoiding extra 'base' subdir."""
    if quant_type != "base":
        # If specific quant type found, use it as sub-directory
        model_dir = GGUF_BASE_MODEL_DIR / model_name / quant_type
    else:
        # If no specific quant, put file directly under model name directory
        model_dir = GGUF_BASE_MODEL_DIR / model_name
    model_dir.mkdir(parents=True, exist_ok=True); return model_dir
# *** END MODIFICATION ***

def download_model(repo_id, file_name, model_info_dict):
    """Download GGUF model using original requests/tqdm + Gated Error Check."""
    try:
        quant_type = next((k for k in QUANT_INFO.keys() if k in file_name), "base")
        # Use the MODIFIED setup_model_directory
        model_dir = setup_model_directory(repo_id.split("/")[1], quant_type)
        local_path = model_dir / file_name
        console.print(f"\n[cyan]Target Download Location:[/cyan] {local_path}")

        from huggingface_hub.utils import build_hf_headers
        url = f"https://huggingface.co/{repo_id}/resolve/main/{file_name}"; headers = build_hf_headers(token=os.environ.get("HUGGING_FACE_HUB_TOKEN"))
        total_size = 0; size_gb = model_info_dict.get("size_gb") # Use provided size first
        # Only call get_file_size if size wasn't provided
        if size_gb is None: size_gb = get_file_size(repo_id, file_name)
        if size_gb is not None and size_gb > 0: total_size = int(size_gb * 1024**3)

        if total_size > 0: console.print(f"\n[cyan]Starting GGUF download: {file_name}[/cyan]"); console.print(f"[cyan]Expected Size:[/cyan] {total_size / (1024**3):.2f} GB")
        else: console.print(f"\n[yellow]Warning: Could not determine GGUF file size.[/yellow]")

        response = requests.get(url, headers=headers, stream=True, timeout=60)
        if response.status_code == 403 or response.status_code == 401:
            is_gated = "Cannot access gated repo" in response.text or "restricted and you are not in the authorized list" in response.text
            error_title = "Gated Model Access Required" if is_gated else "Authentication Error"
            error_msg = ( f"Access to '[yellow]{repo_id}[/]' restricted.\n" f"Accept terms on Hugging Face website first.\n\n"
                          f"1. Visit: [link=https://huggingface.co/{repo_id}]https://huggingface.co/{repo_id}[/link]\n" f"2. Log in & accept terms.\n" f"3. Re-run script." ) if is_gated else (
                          f"Failed to download '{file_name}'.\nCheck HF token in .env or CLI login." )
            console.print(Panel(f"[bold red]ACCESS DENIED ({response.status_code})[/]\n\n{error_msg}", title=error_title, border_style="red")); return None
        response.raise_for_status()
        local_path.parent.mkdir(parents=True, exist_ok=True)
        with open(local_path, "wb") as f, tqdm( desc=f"Downloading {file_name}", total=total_size if total_size > 0 else None,
            disable=total_size == 0, unit='B', unit_scale=True, unit_divisor=1024 ) as pbar:
            for data in response.iter_content(chunk_size=1024*1024):
                if data: write_size = f.write(data); pbar.update(write_size)

        if total_size > 0 and local_path.stat().st_size < total_size * 0.95:
             console.print(f"[red]Error: Downloaded size mismatch. Deleting partial file.[/red]")
             try: local_path.unlink()
             except OSError as delete_err: console.print(f"[yellow]Warning: Could not delete mismatched/partial file {local_path}: {delete_err}[/yellow]")
             return None

        update_gguf_db_entry(repo_id, file_name, local_path, model_info_dict)
        console.print(f"\n[green]✓ GGUF Download complete![/green]"); console.print(f"[dim]Saved to: {local_path}[/dim]"); return str(local_path)
    except RequestsHTTPError as e: console.print(f"[red]HTTP Error downloading GGUF: {e}[/red]"); return None
    except Exception as e: console.print(f"[red]Error downloading GGUF model: {e}[/red]"); console.print_exception(show_locals=False);
    finally:
        if 'local_path' in locals() and local_path.exists() and not Path(check_gguf_exists_in_db(repo_id, file_name) or "").exists():
             try:
                  if local_path.stat().st_size < 1024*1024: print_styled(f"Cleaning partial file: {local_path}", "warn_yellow"); local_path.unlink()
             except (OSError, FileNotFoundError): pass
    return None
# FINISH ### GGUF DOWNLOAD MANAGER ###

# START ### TRANSFORMERS DOWNLOAD/CACHE MANAGER ###
def ensure_transformers_model(repo_id):
    cache_path_db = check_transformers_cache_in_db(repo_id)
    if cache_path_db: console.print(f"[green]✓ Transformers model already cached: {cache_path_db}[/green]"); return repo_id
    console.print(f"\n[yellow]Transformers cache for '{repo_id}' not found or invalid.[/yellow]")
    if Prompt.ask(f"Download/Cache model repo '{repo_id}'?", choices=["y", "n"], default="y") == "n":
         console.print("[yellow]Download/Cache skipped.[/yellow]"); return None
    console.print(f"[cyan]Attempting to cache/download Transformers model: {repo_id}[/cyan]")
    try:
        token = os.environ.get("HUGGING_FACE_HUB_TOKEN")
        ignore_patterns = os.environ.get("TRANSFORMERS_IGNORE_PATTERNS", "*.safetensors.index.json,*.gguf,*.bin").split(',')
        ignore_patterns = [p.strip() for p in ignore_patterns if p.strip()]
        console.print(f"[dim]Ignoring patterns: {ignore_patterns}[/dim]")
        cache_dir = snapshot_download( repo_id=repo_id, local_files_only=False, resume_download=True,
            token=token, ignore_patterns=ignore_patterns if ignore_patterns else None )
        update_transformers_db_entry(repo_id, cache_dir)
        console.print(f"[green]✓ Transformers model '{repo_id}' cached: {cache_dir}[/green]"); return repo_id
    except (GatedRepoError, RequestsHTTPError) as e:
        is_gated = isinstance(e, GatedRepoError) or (isinstance(e, RequestsHTTPError) and e.response.status_code == 403)
        is_auth = isinstance(e, RequestsHTTPError) and e.response.status_code == 401
        if is_gated: console.print(Panel(f"[bold red]ACCESS DENIED (Gated)[/]\n\nAccess to '[yellow]{repo_id}[/]' requires accepting terms.\nVisit: [link=https://huggingface.co/{repo_id}]https://huggingface.co/{repo_id}[/link]\nLog in, accept terms, re-run script.", title="Gated Model Access Required", border_style="red"))
        elif is_auth: console.print(Panel(f"[bold red]AUTH ERROR (401)[/]\n\nFailed to cache '{repo_id}'. Check token.", title="Authentication Failed", border_style="red"))
        else: console.print(f"[red]ERROR during cache/download: {e}[/red]"); console.print_exception(show_locals=False)
        return None
    except RepositoryNotFoundError: console.print(f"[red]Repository not found: {repo_id}[/red]"); return None
    except Exception as e: console.print(f"[red]Unexpected error during cache: {e}[/red]"); console.print_exception(show_locals=False); return None
# FINISH ### TRANSFORMERS DOWNLOAD/CACHE MANAGER ###

# START ### FastAPI SERVER CONFIG GENERATOR ###
def generate_fastapi_config(repo_id, system_specs):
    if not repo_id: print_styled("Error: No repo_id for FastAPI config.", "error_red"); return None
    device = "cpu"; torch_dtype = "auto"
    if TORCH_AVAILABLE and torch.cuda.is_available() and torch.cuda.device_count() > 0:
        device = "cuda"; gpu_ram_gb = system_specs.get("gpu_ram", 0)
        try:
             if torch.cuda.is_bf16_supported(): torch_dtype = "bfloat16"; console.print("[dim]BF16 supported, default=bfloat16[/dim]")
             elif gpu_ram_gb >= 6: torch_dtype = "float16"; console.print("[dim]GPU detected, default=float16[/dim]")
             else: torch_dtype = "float32"; console.print("[yellow]Low GPU VRAM, default=float32[/yellow]")
        except Exception as e: console.print(f"[yellow]Error checking dtype support: {e}. Using auto.[/yellow]"); torch_dtype = "auto"
    else: console.print("[yellow]CUDA not available/PyTorch missing, using CPU.[/yellow]"); device = "cpu"; torch_dtype = "float32"
    env_torch_dtype = os.environ.get("TRANSFORMERS_TORCH_DTYPE");
    if env_torch_dtype and env_torch_dtype.lower() in ["float16", "bfloat16", "float32", "auto"]: torch_dtype = env_torch_dtype.lower(); console.print(f"[cyan]Using torch_dtype from env: {torch_dtype}[/cyan]")
    quantization = os.environ.get("TRANSFORMERS_QUANT", "none").lower(); quantization_config_args = None
    if quantization in ["4bit", "8bit"] and device == "cuda":
        if BITSANDBYTES_AVAILABLE:
            if quantization == "4bit":
                 bnb_compute_dtype_str = torch_dtype if torch_dtype in ["float16", "bfloat16"] else "float16"; bnb_compute_dtype_str = os.environ.get("BNB_4BIT_COMPUTE_DTYPE", bnb_compute_dtype_str)
                 bnb_compute_dtype = torch.bfloat16 if bnb_compute_dtype_str == "bfloat16" and TORCH_AVAILABLE and torch.cuda.is_bf16_supported() else torch.float16 if TORCH_AVAILABLE else None
                 if bnb_compute_dtype:
                      quantization_config_args = { "load_in_4bit": True, "bnb_4bit_quant_type": os.environ.get("BNB_4BIT_QUANT_TYPE", "nf4"), "bnb_4bit_use_double_quant": os.environ.get("BNB_4BIT_USE_DOUBLE_QUANT", "False").lower() == "true", "bnb_4bit_compute_dtype": bnb_compute_dtype }
                      console.print(f"[cyan]Using 4-bit quantization: { {k: (str(v).split('.')[-1] if isinstance(v, type) else v) for k, v in quantization_config_args.items()} }[/cyan]")
                 else: console.print("[yellow]Cannot determine compute dtype for 4bit. Disabling quant.[/yellow]"); quantization = "none"
            else: quantization_config_args = {"load_in_8bit": True}; console.print("[cyan]Using 8-bit quantization.[/cyan]")
        else: console.print(f"[yellow]bitsandbytes not installed. Cannot use {quantization} quant.[/yellow]"); quantization = "none"
    elif quantization != "none": console.print(f"[yellow]Quant '{quantization}' not supported or device is CPU.[/yellow]"); quantization = "none"
    use_flash_attn_env = os.environ.get("USE_FLASH_ATTENTION", "auto").lower(); attn_implementation = None
    if use_flash_attn_env == "true": attn_implementation="flash_attention_2"; console.print("[cyan]Forcing Flash Attention 2.[/cyan]")
    elif use_flash_attn_env == "auto" and device == "cuda" and torch_dtype in ["float16", "bfloat16"]:
        try: import flash_attn; attn_implementation="flash_attention_2"; console.print("[cyan]Attempting Flash Attention 2 (auto).[/cyan]")
        except ImportError: console.print("[yellow]Flash Attention 2 (auto) requested but `flash_attn` not installed.[/yellow]")
    elif use_flash_attn_env == "false": console.print("[cyan]Flash Attention disabled via env var.[/cyan]")
    config = { "repo_id": repo_id, "host": os.environ.get("TRANSFORMERS_HOST", "0.0.0.0"), "port": int(os.environ.get("TRANSFORMERS_PORT", 8081)),
        "device": device, "torch_dtype": torch_dtype, "quantization": quantization, "quantization_config_args": quantization_config_args,
        "device_map": os.environ.get("TRANSFORMERS_DEVICE_MAP", "auto"), "trust_remote_code": os.environ.get("TRUST_REMOTE_CODE", "false").lower() == "true",
        "attn_implementation": attn_implementation, "model_alias": os.environ.get("TRANSFORMERS_MODEL_ALIAS", repo_id.split('/')[-1]),
        "max_new_tokens": int(os.environ.get("MAX_NEW_TOKENS", 512)), "temperature": float(os.environ.get("TEMPERATURE", 0.7)),
        "do_sample": os.environ.get("DO_SAMPLE", "true").lower() == "true", "top_p": float(os.environ.get("TOP_P", 1.0)),
        "top_k": int(os.environ.get("TOP_K", 50)), "uvicorn_workers": int(os.environ.get("UVICORN_WORKERS", 1)) }
    console.print(Panel.fit("[green]Generated FastAPI Server Config:[/green]", border_style="green"));
    try: from pprint import pformat; console.print(pformat(config))
    except ImportError: console.print(json.dumps(config, indent=2, default=lambda o: str(o) if isinstance(o, type) else repr(o)))
    return config

def create_fastapi_script(config):
    if not config: print_styled("Error: No config for FastAPI script.", "error_red"); return None
    if not FASTAPI_AVAILABLE or not UVICORN_AVAILABLE or not PYDANTIC_AVAILABLE: console.print("[red]Error: FastAPI/Uvicorn/Pydantic missing.[/red]"); return None
    FASTAPI_SCRIPT_DIR.mkdir(parents=True, exist_ok=True); safe_alias = re.sub(r'[^a-zA-Z0-9_.-]', '_', config['model_alias'])
    script_path = FASTAPI_SCRIPT_DIR / f"run_{safe_alias}_fastapi_server.py"; quant_config_init_str = "None"; bnb_imports_str = ""
    if config["quantization_config_args"]:
         bnb_imports_str = "from transformers import BitsAndBytesConfig\\nimport torch"
         bnb_arg_strs = [f"{k}={'torch.'+str(v).split('.')[-1] if isinstance(v, type) and 'torch' in str(v) else repr(v)}" for k, v in config["quantization_config_args"].items()]
         quant_config_init_str = f"BitsAndBytesConfig({', '.join(bnb_arg_strs)})"
    attn_impl_str = f'"{config["attn_implementation"]}"' if config["attn_implementation"] else "None"
    flash_attn_import_str = "import flash_attn" if config["attn_implementation"] == "flash_attention_2" else ""
    script_content = f"""#!/usr/bin/env python3
import os, logging, torch, uvicorn, gc, time, sys
from transformers import AutoTokenizer, AutoModelForCausalLM, GenerationConfig
{bnb_imports_str}
{flash_attn_import_str}
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field; from typing import Optional
MODEL_REPO_ID="{config['repo_id']}"; DEVICE_MAP="{config['device_map']}"; TORCH_DTYPE_STR="{config['torch_dtype']}"; QUANTIZATION_MODE="{config['quantization']}"; TRUST_REMOTE_CODE={config['trust_remote_code']}; ATTN_IMPLEMENTATION={attn_impl_str}
HOST="{config['host']}"; PORT={config['port']}; UVICORN_WORKERS={config['uvicorn_workers']}; DEFAULT_MAX_NEW_TOKENS={config['max_new_tokens']}; DEFAULT_TEMPERATURE={config['temperature']}; DEFAULT_DO_SAMPLE={config['do_sample']}; DEFAULT_TOP_P={config['top_p']}; DEFAULT_TOP_K={config['top_k']}
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'); logger = logging.getLogger(__name__)
tokenizer=None; model=None; model_device="cpu"; model_loaded=False
class GenReq(BaseModel): prompt: str; max_new_tokens: Optional[int]=Field(default=DEFAULT_MAX_NEW_TOKENS, gt=0); temperature: Optional[float]=Field(default=DEFAULT_TEMPERATURE, ge=0.0); do_sample: Optional[bool]=Field(default=DEFAULT_DO_SAMPLE); top_p: Optional[float]=Field(default=DEFAULT_TOP_P, ge=0.0, le=1.0); top_k: Optional[int]=Field(default=DEFAULT_TOP_K, ge=0)
class GenResp(BaseModel): generated_text: str; model_id: str=MODEL_REPO_ID; device: str; inference_time_ms: float
class HealthResp(BaseModel): status: str; model_id: str=MODEL_REPO_ID; device: str; model_loaded: bool
def get_torch_dtype(s): return {{'float16':torch.float16,'bfloat16':torch.bfloat16,'float32':torch.float32}}.get(s)
app = FastAPI(title=f"LLM Server ({config['model_alias']})", version="1.0.0")
@app.on_event("startup")
async def startup_event():
    global tokenizer, model, model_device, model_loaded; logger.info(f"--- Server Startup: Loading Model {{MODEL_REPO_ID}} ---")
    if model_loaded: logger.warning("Model already loaded."); return
    try:
        quant_config = {quant_config_init_str} if QUANTIZATION_MODE!="none" else None
        if QUANTIZATION_MODE!='none' and quant_config is None:
            if not BITSANDBYTES_AVAILABLE: raise ImportError("bitsandbytes needed but not installed.")
            else: raise ValueError("Quant config failed.")
        elif quant_config and not isinstance(quant_config, BitsAndBytesConfig): raise ValueError("Invalid quant_config.")
        torch_dtype = get_torch_dtype(TORCH_DTYPE_STR)
        logger.info("Loading tokenizer..."); tokenizer = AutoTokenizer.from_pretrained(MODEL_REPO_ID, trust_remote_code=TRUST_REMOTE_CODE)
        if tokenizer.pad_token is None:
            if tokenizer.eos_token: tokenizer.pad_token=tokenizer.eos_token; logger.warning("Set pad_token=eos_token")
            else: tokenizer.add_special_tokens({{'pad_token': '<|pad|>'}}); logger.warning("Added pad_token")
        logger.info("Loading model..."); model = AutoModelForCausalLM.from_pretrained( MODEL_REPO_ID, device_map=DEVICE_MAP, torch_dtype=torch_dtype or None,
            quantization_config=quant_config, trust_remote_code=TRUST_REMOTE_CODE, attn_implementation=ATTN_IMPLEMENTATION or None, low_cpu_mem_usage=DEVICE_MAP=="auto")
        if tokenizer.pad_token=='<|pad|>' and model.config.vocab_size<len(tokenizer): logger.info("Resizing embeddings"); model.resize_token_embeddings(len(tokenizer))
        model.eval()
        try: model_device = str(next(model.parameters()).device)
        except Exception: model_device="unknown"; logger.warning("Could not determine model device.")
        model_loaded = True; logger.info(f"--- Model loaded on: {{model_device}} ---"); gc.collect()
        if torch.cuda.is_available(): torch.cuda.empty_cache()
    except Exception as e: logger.critical(f"Failed to load model during startup: {{e}}", exc_info=True); model_loaded=False
@app.post("/generate", response_model=GenResp)
async def generate_text(req: GenReq):
    global tokenizer, model, model_device, model_loaded
    if not model_loaded: raise HTTPException(status_code=503, detail="Model not ready")
    start_time = time.perf_counter(); logger.info(f"Req: '{{req.prompt[:80]}}...'"); logger.debug(f"Params: {{req.dict(exclude={{'prompt'}})}}")
    try:
        inputs = tokenizer(req.prompt, return_tensors="pt", return_attention_mask=True)
        try: current_dev = str(next(model.parameters()).device); inputs = inputs.to(current_dev)
        except Exception as e: logger.warning(f"Input move failed ({{e}}). Assuming auto placement.")
        gen_conf = GenerationConfig( max_new_tokens=req.max_new_tokens, temperature=req.temperature if req.do_sample else 1.0, do_sample=req.do_sample,
            top_p=req.top_p if req.do_sample else None, top_k=req.top_k if req.do_sample else None, pad_token_id=tokenizer.pad_token_id, eos_token_id=tokenizer.eos_token_id )
        with torch.inference_mode(): outputs = model.generate(**inputs, generation_config=gen_conf)
        gen_tokens = outputs[0][inputs.input_ids.shape[1]:]; gen_text = tokenizer.decode(gen_tokens, skip_special_tokens=True).strip()
        end_time = time.perf_counter(); infer_time_ms = (end_time - start_time) * 1000
        logger.info(f"Success. Len: {{len(gen_text)}}. Time: {{infer_time_ms:.2f}} ms")
        return GenResp(generated_text=gen_text, device=model_device, inference_time_ms=infer_time_ms)
    except Exception as e: logger.error(f"Gen error: {{e}}", exc_info=True); raise HTTPException(status_code=500, detail="Internal server error")
@app.get("/health", response_model=HealthResp)
async def health_check(): global model_device, model_loaded; status="ok" if model_loaded else "error"; code=200 if model_loaded else 503; return JSONResponse(content=HealthResp(status=status, device=model_device, model_loaded=model_loaded).dict(), status_code=code)
if __name__ == "__main__": logger.info(f"Starting FastAPI server {{MODEL_REPO_ID}} on {{HOST}}:{{PORT}} ({{UVICORN_WORKERS}} workers)..."); uvicorn.run(app="__main__:app", host=HOST, port=PORT, workers=UVICORN_WORKERS, log_level="info", reload=False)
"""
    try:
        with open(script_path, "w") as f: f.write(script_content); script_path.chmod(0o755)
        console.print(f"\n[green]✓ Transformers FastAPI server script created:[/green] {script_path}"); return str(script_path)
    except Exception as e: console.print(f"[red]Error creating FastAPI script: {e}[/red]"); return None
# FINISH ### FastAPI SERVER CONFIG/SCRIPT ###

# START ### SERVICE LAUNCHER ###
def launch_bolt():
    try: deploy_bolt_dir = Path.home() / "deploy.bolt"; process = subprocess.Popen(['terminator', '--working-directory', str(deploy_bolt_dir), '-x', f'python3 {deploy_bolt_dir / "run_bolt.py"}'])
    except FileNotFoundError: console.print("[red]Error: 'terminator' command not found.[/red]"); return False
    except Exception as e: console.print(f"[red]Error launching run_bolt.py: {str(e)}[/red]"); return False
    console.print(f"[cyan]Launched run_bolt.py in new Terminator window (PID: {process.pid}).[/cyan]"); return True
# FINISH ### SERVICE LAUNCHER ###

# START ### MAIN FUNCTION ###
def main():
    console.print(Panel.fit("[cyan]MODEL SETUP & SERVER GENERATOR[/cyan]", border_style="cyan"))
    url = Prompt.ask("\nEnter Hugging Face URL or Repo ID\n[dim](e.g., google/gemma-2b or TheBloke/Mistral-7B-Instruct-v0.2-GGUF)[/dim]")
    repo_id = validate_hf_url(url)
    if not repo_id: console.print("[red]Invalid URL/Repo ID.[/red]"); sys.exit(1)
    console.print(f"\n[cyan]Processing Repo:[/cyan] {repo_id}")
    analyze_model(repo_id)
    sys_specs = check_system_specs()
    if sys_specs:
        console.print(f"\n[cyan]System Specs:[/cyan]"); console.print(f"  RAM: [yellow]{sys_specs['total_ram']:.1f}GB[/yellow]")
        if sys_specs.get("gpu_name"): console.print(f"  GPU: [yellow]{sys_specs['gpu_name']} ({sys_specs['gpu_ram']:.1f}GB)[/yellow]")
        else: console.print("  GPU: [yellow]Not Detected/Check Failed[/yellow]")
        if sys_specs.get("recommended_quant"): console.print(f"  Recommended Quant (GGUF): [green]{sys_specs['recommended_quant']}[/green]\n")
    else: console.print("[red]Could not determine system specs.[/red]"); sys_specs={}
    console.print("[cyan]Detecting model type...[/cyan]")
    gguf_files, other_files = get_model_files(repo_id)
    if gguf_files is None and other_files is None: console.print("[red]Failed to list files for repo.[/red]"); sys.exit(1)
    model_type = None
    if gguf_files: console.print("[green]Detected GGUF model type.[/green]"); model_type = "gguf"
    elif other_files and any(f.lower()=='config.json' for f in other_files) and any(f.lower().endswith(('.safetensors','.bin')) for f in other_files):
        console.print("[green]Detected Transformers model type.[/green]"); model_type = "transformers"
    else: console.print("[red]Could not reliably determine model type.[/red]"); sys.exit(1)
    if model_type == "gguf": handle_gguf_workflow(repo_id, sys_specs, gguf_files)
    elif model_type == "transformers": handle_transformers_workflow(repo_id, sys_specs)
    console.print("\n[cyan]Setup script finished.[/cyan]")
# END ### MAIN FUNCTION ###

# START ### GGUF WORKFLOW FUNCTION (Corrected Detection Logic) ###
def handle_gguf_workflow(repo_id, sys_specs, gguf_files):
    console.print("\n[cyan]Available GGUF model files:[/cyan]")
    valid_choices = []; displayed_files = []
    for i, file in enumerate(gguf_files, 1):
        size = get_file_size(repo_id, file); size_str = f"({size:.2f}GB)" if size is not None else "(size unknown)"
        quant_type = next((k for k in QUANT_INFO.keys() if k in file), None)
        valid_choices.append(str(i)); displayed_files.append(file)
        if quant_type: info = QUANT_INFO[quant_type]; console.print(f"{i}. [yellow]{file}[/yellow] {size_str}\n   [dim]Quality: {info['quality']} | RAM: {info['ram']}[/dim]")
        else: console.print(f"{i}. [yellow]{file}[/yellow] {size_str}")
    selected_file = None
    if not displayed_files: console.print("[red]No GGUF files found to select.[/red]"); return
    if len(displayed_files) > 1:
        choice = Prompt.ask("\n[cyan]Which GGUF file you want?[/cyan]", choices=valid_choices)
        selected_file = displayed_files[int(choice) - 1]
    else: selected_file = displayed_files[0]; console.print(f"\n[yellow]Auto-selected:[/yellow] {selected_file}")
    console.print(f"\n[green]Selected GGUF:[/green] {selected_file}")

    # *** CORRECTED DETECTION LOGIC ***
    # 1. Calculate expected local path *first*
    quant_type_local = next((k for k in QUANT_INFO.keys() if k in selected_file), "base")
    model_name_local = repo_id.split("/")[1]
    expected_local_dir = setup_model_directory(model_name_local, quant_type_local) # Use corrected setup_model_directory
    expected_local_path = expected_local_dir / selected_file

    # 2. Check filesystem directly
    existing_path = None
    if expected_local_path.exists() and expected_local_path.is_file():
        existing_path = str(expected_local_path)
        console.print(f"[green]Model already exists locally:[/green] {existing_path}")
        # Also check/update DB just in case
        db_path = check_gguf_exists_in_db(repo_id, selected_file)
        if not db_path or Path(db_path).resolve() != expected_local_path.resolve():
             console.print("[dim]Updating database entry for existing file...[/dim]")
             temp_size_gb = get_file_size(repo_id, selected_file) # Get size for DB update
             temp_model_info = {"repo_id": repo_id, "file": selected_file, "type": "gguf", "size_gb": temp_size_gb}
             update_gguf_db_entry(repo_id, selected_file, expected_local_path, temp_model_info)
    else:
        # If not found on filesystem, check DB as a fallback (original behavior was DB only)
        existing_path = check_gguf_exists_in_db(repo_id, selected_file)
        if existing_path:
            console.print(f"[yellow]Warning: Model found in DB but not at expected path:[/yellow] {existing_path}")
            console.print(f"[yellow]Expected path was:[/yellow] {expected_local_path}")
            # Ask user what to do? For now, treat as not found locally.
            existing_path = None # Force download prompt

    # 3. Proceed with download prompt logic based on existence check
    downloaded_path = None
    model_info_payload = { "repo_id": repo_id, "file": selected_file, "type": "gguf", "size_gb": get_file_size(repo_id, selected_file) }

    if existing_path:
        if Prompt.ask("Re-download anyway?", choices=["y","n"], default="n") == "y":
             console.print("[yellow]Proceeding with re-download...[/yellow]")
             downloaded_path = download_model(repo_id, selected_file, model_info_payload)
        else: downloaded_path = existing_path # User chose not to re-download
    else: # File doesn't exist locally
        if Prompt.ask("\n[cyan]Download this GGUF model?[/cyan]", choices=["y", "n"], default="y") == "y":
            downloaded_path = download_model(repo_id, selected_file, model_info_payload)
        else: console.print("[red]Download skipped.[/red]"); return
    # *** END CORRECTED DETECTION LOGIC ***

    if not downloaded_path: console.print("[red]Model acquisition failed.[/red]"); return

# FINISH ### GGUF WORKFLOW FUNCTION ###

# START ### TRANSFORMERS WORKFLOW FUNCTION ###
def handle_transformers_workflow(repo_id, sys_specs):
    console.print("\n[cyan]Preparing setup for Transformers model...[/cyan]")
    model_repo_id_confirmed = ensure_transformers_model(repo_id)
    if not model_repo_id_confirmed: console.print("[red]Transformers model caching/download failed or skipped.[/red]"); return
    console.print(f"\n[green]✓ Transformers model '{repo_id}' cache ready.[/green]")
    if Prompt.ask("[cyan]Generate FastAPI server script for this model?", choices=["y", "n"], default="y") == "y":
        console.print("[cyan]>> Generating FastAPI server config...[/cyan]")
        config = generate_fastapi_config(repo_id, sys_specs)
        if config:
            script_path = create_fastapi_script(config)
            if script_path:
                if Prompt.ask("\n[cyan]Start the FastAPI server now?", choices=["y", "n"], default="n") == "y":
                    console.print(f"[cyan]Executing FastAPI server: python3 {script_path}[/cyan]")
                    try: process = subprocess.Popen(['python3', str(script_path)]); console.print(f"[green]FastAPI server process started (PID: {process.pid}). Check logs.[/green]")
                    except Exception as e: console.print(f"[red]Failed to start FastAPI server: {e}[/red]")
        else: console.print("[red]Failed to generate FastAPI server config.[/red]")
# FINISH ### TRANSFORMERS WORKFLOW FUNCTION ###

# START ### SCRIPT RUNNER ###
if __name__ == "__main__":
    try: main(); sys.exit(0)
    except KeyboardInterrupt: print_styled("\nSetup interrupted by user.", "warn_yellow"); sys.exit(130)
    except SystemExit as e: sys.exit(e.code)
    except Exception as e: import traceback; print_styled(f"\nUnhandled Critical Error: {str(e)}", "error_red"); console.print(f"{traceback.format_exc()}"); sys.exit(1)
# FINISH ### SCRIPT RUNNER ##

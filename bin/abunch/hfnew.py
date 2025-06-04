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
            # --- Check for NVIDIA GPU first ---
            if TORCH_AVAILABLE and torch.cuda.is_available() and torch.cuda.device_count() > 0:
                 gpu_ram = torch.cuda.get_device_properties(0).total_memory / (1024**3)
                 gpu_name = torch.cuda.get_device_name(0)
            # --- Add check for Metal (Mac) if applicable ---
            elif TORCH_AVAILABLE and hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
                 # Getting exact Metal GPU RAM is trickier, often reports unified memory
                 # Let's report unified memory size and indicate it's Metal
                 gpu_ram = psutil.virtual_memory().total / (1024**3) # Approximate with system RAM for unified
                 gpu_name = "Apple Metal GPU (Unified Memory)"
            else:
                 console.print("[yellow]Warning: No compatible GPU detected by PyTorch (CUDA/MPS).[/yellow]")

        except Exception as gpu_check_err: console.print(f"[yellow]Warning: GPU check failed ({gpu_check_err}).[/yellow]")

        # --- Simplified Quant Recommendation (primarily RAM based for GGUF) ---
        quant = "Q4_K_M" # Default baseline
        if ram < 8: quant = "Q2_K"
        elif ram < 12: quant = "Q3_K_M"
        elif ram < 16: quant = "Q4_K_M"
        elif ram < 24: quant = "Q5_K_M"
        elif ram >= 24: quant = "Q6_K"

        # Add GPU info if detected for user awareness, even if recommendation is RAM-based
        spec_dict = { "total_ram": ram, "gpu_ram": gpu_ram, "gpu_name": gpu_name, "recommended_quant": quant }
        if gpu_name:
             spec_dict["detected_gpu_ram_gb"] = gpu_ram # Keep separate GPU RAM for clarity

        return spec_dict

    except Exception as e: console.print(f"[red]Error checking system specs: {str(e)}[/red]"); return None
# FINISH ### SYSTEM SPECS ###


# START ### URL VALIDATION ###
def validate_hf_url(url):
    if not url: return None
    # Handles URLs like https://huggingface.co/Org/Model, Org/Model, Org/Model/tree/main
    patterns = [
        r'https?://huggingface\.co/([^/]+/[^/]+)(?:/(?:tree|blob)/[^/]+)?/?$', # More robust URL matching
        r'^([^/]+/[^/]+)$' # Handles just repo_id format
    ]
    for pattern in patterns:
        match = re.match(pattern, url.strip())
        if match: return match.group(1)
    return None
# FINISH ### URL VALIDATION ###

# START ### MODEL INFO & FILE HANDLING ###
def get_model_files(repo_id):
    try:
        api = HfApi()
        # Attempt to get file list, handle potential auth errors gracefully
        files = api.list_repo_files(repo_id, token=os.environ.get("HUGGING_FACE_HUB_TOKEN"))
    except RepositoryNotFoundError:
        console.print(f"[red]Repository not found: {repo_id}[/red]")
        return None, None
    except GatedRepoError:
        console.print(f"[yellow]Repo {repo_id} is gated. Listing may be incomplete without accepting terms/token.[/yellow]")
        # Try listing again, might work if user logged in via CLI
        try:
             files = api.list_repo_files(repo_id, token=True) # Use token=True to try CLI login
        except Exception:
             files = [] # If still fails, return empty list
    except RequestsHTTPError as e:
         if e.response.status_code == 401:
             console.print(f"[red]Authentication Error (401): Cannot list files for {repo_id}. Check HF token.[/red]")
         elif e.response.status_code == 403:
             console.print(f"[red]Permission Error (403): Cannot list files for {repo_id}. Check repo access.[/red]")
         else:
             console.print(f"[red]HTTP Error {e.response.status_code} listing repo files for {repo_id}: {str(e)}[/red]")
         return None, None
    except Exception as e:
        console.print(f"[red]Error listing repo files for {repo_id}: {str(e)}[/red]")
        return None, None

    # Filter files
    gguf_files = [f for f in files if f.lower().endswith('.gguf')]
    other_files = [f for f in files if not f.lower().endswith('.gguf')]
    return gguf_files, other_files

def get_file_size(repo_id, file_name):
    try:
        from huggingface_hub.utils import build_hf_headers
        # Ensure filename doesn't have leading slashes if it comes from list_repo_files
        file_name = file_name.lstrip('/')
        # Construct URL using HfApi helper for consistency might be better, but this works
        url = f"https://huggingface.co/{repo_id}/resolve/main/{file_name}"
    except HFValidationError:
        console.print(f"[red]Invalid repo/file format for size check: {repo_id}/{file_name}[/red]")
        return None
    try:
        token = os.environ.get("HUGGING_FACE_HUB_TOKEN")
        headers = build_hf_headers(token=token) # Use token if available
        response = requests.head(url, headers=headers, allow_redirects=True, timeout=30)

        # Handle common errors gracefully
        if response.status_code == 401:
            console.print(f"[yellow]Warn: Auth error (401) getting size for {file_name}. Check token.[/yellow]")
            return None
        elif response.status_code == 403:
            console.print(f"[yellow]Warn: Access denied (403) getting size for {file_name}. Repo might be gated or private.[/yellow]")
            return None
        elif response.status_code == 404:
            console.print(f"[yellow]Warn: File not found (404) getting size for {file_name}.[/yellow]")
            return None
        response.raise_for_status() # Raise errors for other bad statuses (5xx etc.)

        # Get size from headers (prefer x-linked-size for LFS)
        size = 0
        if "x-linked-size" in response.headers:
            size = int(response.headers["x-linked-size"])
        elif "content-length" in response.headers:
            size = int(response.headers["content-length"])
        else:
            # If no size headers, maybe try a range request? Or just return None.
            console.print(f"[yellow]Warn: Could not determine size for {file_name} from headers.[/yellow]")
            return None # Cannot determine size

        return size / (1024**3) # Return size in GB

    except RequestsHTTPError as e:
        # Catch non-4xx errors raised by raise_for_status
        console.print(f"[yellow]Warn: HTTP Error ({e.response.status_code}) getting size for {file_name}.[/yellow]")
        return None
    except requests.exceptions.RequestException as e:
        # Catch connection errors, timeouts etc.
        console.print(f"[yellow]Warn: Network error getting size for {file_name}: {e}[/yellow]")
        return None
    except Exception as e:
        # Catch any other unexpected errors
        console.print(f"[yellow]Warn: Unexpected error getting size for {file_name}: {e}[/yellow]")
        return None
# FINISH ### MODEL INFO & FILE HANDLING ###


# START ### MODEL ANALYZER ###
def analyze_model(repo_id):
    try:
        # Use token=True to attempt using CLI login credentials if available
        info = model_info(repo_id, token=os.environ.get("HUGGING_FACE_HUB_TOKEN")) # Changed token handling
        table = Table(title=f"Model Info: {repo_id}")
    except RepositoryNotFoundError:
        console.print(f"[red]Repository not found: {repo_id}[/red]")
        return None
    except GatedRepoError:
        console.print(f"[yellow]Repo {repo_id} is gated. Info may require accepting terms/access.[/yellow]")
        # Attempt to fetch basic info anyway, might succeed if user has access
        try:
            api = HfApi()
            info = api.model_info(repo_id, token=os.environ.get("HUGGING_FACE_HUB_TOKEN"))
            table = Table(title=f"Model Info: {repo_id} (Gated)")
        except Exception:
             console.print(f"[yellow]Could not retrieve info even for gated repo {repo_id}.[/yellow]")
             return None # Give up if we can't even get basic info for gated
    except RequestsHTTPError as e:
         if e.response.status_code == 401:
             console.print(f"[red]Authentication Error (401): Cannot get info for {repo_id}. Check HF token.[/red]")
         elif e.response.status_code == 403:
             console.print(f"[red]Permission Error (403): Cannot get info for {repo_id}. Check repo access.[/red]")
         else:
             console.print(f"[red]HTTP Error {e.response.status_code} getting model info for {repo_id}: {str(e)}[/red]")
         return None
    except Exception as e:
        console.print(f"[red]Couldn't get model info for {repo_id}: {str(e)}[/red]")
        return None

    # Populate table (safe access using .get())
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="magenta") # Changed style for visibility

    tags = getattr(info, 'tags', [])
    if tags:
        table.add_row("Tags", ", ".join(tags))

    pipeline_tag = getattr(info, 'pipeline_tag', None)
    if pipeline_tag:
        table.add_row("Pipeline", pipeline_tag)

    downloads = getattr(info, 'downloads', 0)
    if downloads:
         # Add commas for readability
        table.add_row("Downloads", f"{downloads:,}")

    likes = getattr(info, 'likes', 0)
    if likes:
        table.add_row("Likes", str(likes))

    # Add library name if available (useful for diffusers)
    library_name = getattr(info, 'library_name', None)
    if library_name:
        table.add_row("Library", library_name)

    console.print(table)
    return info
# FINISH ### MODEL ANALYZER ###

# START ### MODEL DATABASE ###
def get_model_database():
    MODEL_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    if MODEL_DB_PATH.exists():
        try:
            with open(MODEL_DB_PATH, 'r') as f: # Explicit read mode
                data = json.load(f)
            # Basic validation
            if isinstance(data, dict) and "models" in data and isinstance(data['models'], dict):
                return data
            else:
                console.print(f"[yellow]DB file {MODEL_DB_PATH} invalid format. Resetting.[/yellow]")
                return {"models": {}}
        except json.JSONDecodeError:
             console.print(f"[red]Error decoding JSON from {MODEL_DB_PATH}. Resetting.[/red]")
             return {"models": {}}
        except Exception as e:
            console.print(f"[red]Error reading DB {MODEL_DB_PATH}: {e}. Resetting.[/red]")
            return {"models": {}}
    return {"models": {}} # Return default if file doesn't exist

def save_model_database(db):
    # Use atomic write pattern
    temp_db_path = MODEL_DB_PATH.with_suffix(MODEL_DB_PATH.suffix + '.tmp')
    try:
        MODEL_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    except Exception as dir_err:
        print_styled(f"Error creating DB directory {MODEL_DB_PATH.parent}: {dir_err}", "error_red")
        return # Cannot proceed if directory cannot be created

    try:
        with open(temp_db_path, "w") as f:
            json.dump(db, f, indent=2)
        # Atomic replace
        os.replace(temp_db_path, MODEL_DB_PATH)
    except Exception as e:
        print_styled(f"Error saving database to {MODEL_DB_PATH}: {str(e)}", "error_red")
    finally:
          # Clean up temp file if it still exists (e.g., on error)
          if temp_db_path.exists():
              try:
                  temp_db_path.unlink()
              except OSError:
                  # Log or ignore if cleanup fails
                  pass

def update_gguf_db_entry(repo_id, file_name, local_path, model_info_dict):
     db = get_model_database()
     models_db = db.setdefault("models", {}) # Ensure 'models' key exists
     repo_entry = models_db.setdefault(repo_id, {"files": {}, "info": {}, "type": "gguf"})

     # Ensure structure before updating
     repo_entry["type"] = "gguf" # Correct type if it was somehow different
     repo_entry.setdefault("files", {})[file_name] = str(local_path) # Store as string

     # Ensure 'info' is a dictionary before trying to update
     if not isinstance(repo_entry.get("info"), dict):
         repo_entry["info"] = {}
     if model_info_dict and isinstance(model_info_dict, dict):
         repo_entry["info"].update(model_info_dict) # Update with new info only if valid

     save_model_database(db)

def update_transformers_db_entry(repo_id, cache_dir, model_info_obj):
    db = get_model_database()
    models_db = db.setdefault("models", {}) # Ensure 'models' key exists
    repo_entry = models_db.setdefault(repo_id, {"cache": {}, "info": {}, "type": "transformers"}) # Assume transformers if not present

    # Decide type based on model_info if available
    model_type = "transformers" # Default
    if model_info_obj:
        tags = getattr(model_info_obj, 'tags', [])
        pipeline = getattr(model_info_obj, 'pipeline_tag', None)
        library = getattr(model_info_obj, 'library_name', None)
        if "diffusers" in tags or (pipeline and "diffusers" in pipeline) or library == "diffusers":
            model_type = "diffusers"

    repo_entry["type"] = model_type # Set determined type
    repo_entry["cache"] = {
        "path": str(cache_dir), # Store path as string
        "cached_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    # Update info from model_info_obj if available
    if model_info_obj:
         if not isinstance(repo_entry.get("info"), dict):
             repo_entry["info"] = {}
         # Convert model_info_obj to a dictionary selectively
         info_dict = {
             "tags": getattr(model_info_obj, 'tags', []),
             "pipeline_tag": getattr(model_info_obj, 'pipeline_tag', None),
             "library_name": getattr(model_info_obj, 'library_name', None),
             # Add other relevant fields if needed
         }
         repo_entry["info"].update(info_dict)

    save_model_database(db)


# Checks DB only for GGUF path
def check_gguf_exists_in_db(repo_id, file_name):
    db = get_model_database()
    file_path_str = db.get("models", {}).get(repo_id, {}).get("files", {}).get(file_name)
    # Check if path exists in DB AND the file actually exists on disk
    if file_path_str and Path(file_path_str).exists() and Path(file_path_str).is_file():
        return file_path_str
    return None # Return None if not in DB or file missing on disk

# Checks DB only for Transformers/Diffusers cache path
def check_transformers_cache_in_db(repo_id):
    db = get_model_database()
    cache_path_str = db.get("models", {}).get(repo_id, {}).get("cache", {}).get("path")
    # Check if path exists in DB AND it's a valid directory with config.json
    if cache_path_str:
        cache_path = Path(cache_path_str)
        # Check for config.json or model_index.json for diffusers
        config_exists = (cache_path / "config.json").exists() or (cache_path / "model_index.json").exists()
        if cache_path.exists() and cache_path.is_dir() and config_exists:
            return cache_path_str
    return None # Return None if not in DB or cache dir is invalid

# FINISH ### MODEL DATABASE ###

# START ### GGUF DOWNLOAD MANAGER ###
def setup_model_directory(repo_id, quant_type):
    """Set up GGUF model directory under repo owner."""
    # Extract owner and model name
    try:
        owner, model_name = repo_id.split('/')
    except ValueError:
        # Handle cases where repo_id might not have a slash (e.g., user error)
        console.print(f"[yellow]Warning: Invalid repo_id format '{repo_id}'. Using full ID as model name.[/yellow]")
        owner = "_" # Placeholder owner
        model_name = repo_id.replace("/", "_") # Replace slash just in case

    # Create path: ~/.models/OWNER/MODEL_NAME/QUANT_TYPE
    if quant_type != "base":
        model_dir = GGUF_BASE_MODEL_DIR / owner / model_name / quant_type
    else:
        # If no specific quant, put file directly under model name directory
        model_dir = GGUF_BASE_MODEL_DIR / owner / model_name

    model_dir.mkdir(parents=True, exist_ok=True)
    return model_dir

def download_model(repo_id, file_name, model_info_dict):
    """Download GGUF model using requests/tqdm + Enhanced Error Handling."""
    try:
        quant_type = next((k for k in QUANT_INFO.keys() if k in file_name), "base")
        # Use the corrected setup_model_directory logic
        model_dir = setup_model_directory(repo_id, quant_type)
        local_path = model_dir / file_name
        console.print(f"\n[cyan]Target Download Location:[/cyan] {local_path}")

        # Construct URL carefully
        from huggingface_hub.utils import build_hf_headers, hf_raise_for_status
        file_name_url_encoded = requests.utils.quote(file_name.lstrip('/')) # URL encode filename
        url = f"https://huggingface.co/{repo_id}/resolve/main/{file_name_url_encoded}"
        token = os.environ.get("HUGGING_FACE_HUB_TOKEN")
        headers = build_hf_headers(token=token)

        # Attempt to get size first
        total_size = 0
        size_gb = model_info_dict.get("size_gb") # Use info from initial check if available
        if size_gb is None:
             size_gb = get_file_size(repo_id, file_name) # Only fetch if not already known
        if size_gb is not None and size_gb > 0:
            total_size = int(size_gb * 1024**3)

        if total_size > 0:
            console.print(f"\n[cyan]Starting GGUF download: {file_name}[/cyan]")
            console.print(f"[cyan]Expected Size:[/cyan] {size_gb:.2f} GB")
        else:
            console.print(f"\n[yellow]Warning: Could not determine GGUF file size. Progress bar may be inaccurate.[/yellow]")

        # Perform the download using streaming
        response = requests.get(url, headers=headers, stream=True, timeout=60) # Added timeout

        # Check for specific errors before raising generic HTTPError
        if response.status_code == 401:
             console.print(Panel(f"[bold red]AUTH ERROR (401)[/]\n\nFailed to download '{file_name}'.\nCheck HF token in .env or CLI login.", title="Authentication Failed", border_style="red")); return None
        if response.status_code == 403:
             # Check if it's gated
             is_gated = "request accepted, loading ..." in response.text.lower() or "gated" in response.text.lower()
             error_title = "Gated Model Access Required" if is_gated else "Permission Denied (403)"
             error_msg = ( f"Access to '[yellow]{repo_id}[/]' restricted.\n" f"Accept terms on Hugging Face website first.\n\n"
                           f"1. Visit: [link=https://huggingface.co/{repo_id}]https://huggingface.co/{repo_id}[/link]\n" f"2. Log in & accept terms.\n" f"3. Re-run script." ) if is_gated else (
                           f"Permission denied downloading '{file_name}'. Ensure you have access." )
             console.print(Panel(f"[bold red]ACCESS DENIED ({response.status_code})[/]\n\n{error_msg}", title=error_title, border_style="red")); return None
        if response.status_code == 404:
             console.print(f"[red]File not found (404): '{file_name}' in repo '{repo_id}'[/red]"); return None

        # Raise for other HTTP errors (e.g., 5xx Server Errors)
        hf_raise_for_status(response) # Use HF utility for better messages

        # Ensure target directory exists
        local_path.parent.mkdir(parents=True, exist_ok=True)

        # Download with tqdm progress bar
        with open(local_path, "wb") as f, tqdm(
            desc=f"Downloading {file_name}",
            total=total_size if total_size > 0 else None,
            disable=total_size == 0, # Disable bar if size is unknown
            unit='B', unit_scale=True, unit_divisor=1024
            ) as pbar:
            for data in response.iter_content(chunk_size=1024*1024): # 1MB chunks
                if data:
                    write_size = f.write(data)
                    pbar.update(write_size)

        # Verify downloaded size if expected size was known
        downloaded_size = local_path.stat().st_size
        if total_size > 0 and downloaded_size < total_size * 0.95: # Allow small tolerance
             console.print(f"[red]Error: Downloaded size ({downloaded_size / (1024**3):.2f} GB) mismatch for {file_name}. Expected ~{size_gb:.2f} GB. Deleting partial file.[/red]")
             try:
                 local_path.unlink()
             except OSError as delete_err:
                 console.print(f"[yellow]Warning: Could not delete mismatched/partial file {local_path}: {delete_err}[/yellow]")
             return None # Download failed

        # Update database only on successful download
        update_gguf_db_entry(repo_id, file_name, local_path, model_info_dict)
        console.print(f"\n[green]✓ GGUF Download complete![/green]")
        console.print(f"[dim]Saved to: {local_path}[/dim]")
        return str(local_path)

    # Catch specific request exceptions
    except requests.exceptions.Timeout:
        console.print(f"[red]Network Timeout downloading GGUF: {file_name}[/red]"); return None
    except requests.exceptions.ConnectionError:
        console.print(f"[red]Network Connection Error downloading GGUF: {file_name}[/red]"); return None
    except RequestsHTTPError as e: # Catch errors raised by hf_raise_for_status
        console.print(f"[red]HTTP Error downloading GGUF ({e.response.status_code}): {file_name}[/red]"); return None
    except Exception as e:
        console.print(f"[red]Unexpected error downloading GGUF model {file_name}: {e}[/red]")
        console.print_exception(show_locals=False) # Show traceback for unexpected errors
        # Clean up potentially partial file on generic error
        if 'local_path' in locals() and local_path.exists():
             try:
                 # Optionally check size before deleting?
                 local_path.unlink()
                 console.print(f"[yellow]Cleaned up potentially partial file: {local_path}[/yellow]")
             except OSError: pass
        return None
# FINISH ### GGUF DOWNLOAD MANAGER ###


# START ### TRANSFORMERS DOWNLOAD/CACHE MANAGER ###
def ensure_transformers_model(repo_id, model_info_obj):
    cache_path_db = check_transformers_cache_in_db(repo_id)
    if cache_path_db:
        console.print(f"[green]✓ Transformers/Diffusers cache found in DB:[/green] {cache_path_db}")
        # Optionally verify cache dir integrity here if needed
        return repo_id # Return repo_id to signify success

    console.print(f"\n[yellow]Transformers/Diffusers cache for '{repo_id}' not found in DB or invalid.[/yellow]")

    # Check Hugging Face cache path directly as a fallback
    try:
        from huggingface_hub.constants import HUGGINGFACE_HUB_CACHE
        hf_cache_path = Path(HUGGINGFACE_HUB_CACHE)
        mangled_repo = "models--" + repo_id.replace("/", "--")
        potential_cache_root = hf_cache_path / mangled_repo

        snapshot_subdirs = list(potential_cache_root.glob("snapshots/*")) if potential_cache_root.exists() else []
        if snapshot_subdirs:
            # Find the latest snapshot directory (often by commit hash name)
            latest_snapshot_dir = max(snapshot_subdirs, key=os.path.getmtime) # Or find based on hash name logic if needed
            config_exists = (latest_snapshot_dir / "config.json").exists() or (latest_snapshot_dir / "model_index.json").exists()
            if config_exists:
                console.print(f"[green]✓ Found existing cache in default HF location:[/green] {latest_snapshot_dir}")
                if Prompt.ask(f"Use this existing cache?", choices=["y", "n"], default="y") == "y":
                    # Update DB with this found path
                    update_transformers_db_entry(repo_id, latest_snapshot_dir, model_info_obj)
                    return repo_id
                else:
                    console.print("[yellow]User chose not to use existing cache. Proceeding to download prompt.[/yellow]")
            else:
                 console.print(f"[dim]Found cache dir {latest_snapshot_dir} but missing config/index. Invalid.[/dim]")
        else:
             console.print(f"[dim]No valid cache found in default HF location: {potential_cache_root}[/dim]")

    except ImportError:
        console.print("[yellow]Warning: Cannot check default Hugging Face cache path (huggingface_hub library issue?).[/yellow]")
    except Exception as cache_check_err:
        console.print(f"[yellow]Warning: Error checking default HF cache path: {cache_check_err}[/yellow]")


    # If not found in DB or user declined existing cache, prompt for download
    if Prompt.ask(f"Download/Cache model repo '{repo_id}'?", choices=["y", "n"], default="y") == "n":
         console.print("[yellow]Download/Cache skipped by user.[/yellow]")
         return None # User skipped

    console.print(f"\n[cyan]Attempting to cache/download Transformers/Diffusers model: {repo_id}[/cyan]")
    try:
        token = os.environ.get("HUGGING_FACE_HUB_TOKEN") # Use env var
        # Define sensible ignore patterns - exclude large specific files unlikely needed for generic transformers/diffusers loading
        ignore_patterns = os.environ.get("TRANSFORMERS_IGNORE_PATTERNS", "*.gguf,*.ggml,*.bin,*.ckpt,*.pt,*.onnx,*.tflite").split(',')
        ignore_patterns = [p.strip() for p in ignore_patterns if p.strip()]
        console.print(f"[dim]Using ignore patterns: {ignore_patterns}[/dim]")

        # Use snapshot_download to get the whole repo structure
        cache_dir = snapshot_download(
            repo_id=repo_id,
            local_files_only=False, # Force download if not cached
            resume_download=True,
            token=token, # Pass token for private/gated repos
            ignore_patterns=ignore_patterns if ignore_patterns else None,
            # Consider adding cache_dir argument if you want to control location
            # cache_dir="/path/to/my/cache"
        )

        # Update the database with the actual cache directory path
        update_transformers_db_entry(repo_id, cache_dir, model_info_obj)
        console.print(f"[green]✓ Transformers/Diffusers model '{repo_id}' cached successfully:[/green] {cache_dir}")
        return repo_id # Success

    except (GatedRepoError, RequestsHTTPError) as e:
        is_gated = isinstance(e, GatedRepoError) or (isinstance(e, RequestsHTTPError) and e.response.status_code == 403)
        is_auth = isinstance(e, RequestsHTTPError) and e.response.status_code == 401

        if is_gated:
            console.print(Panel(f"[bold red]ACCESS DENIED (Gated/403)[/]\n\nAccess to '[yellow]{repo_id}[/]' requires accepting terms or permissions.\n1. Visit: [link=https://huggingface.co/{repo_id}]https://huggingface.co/{repo_id}[/link]\n2. Log in & accept terms (if any).\n3. Ensure your token has access.\n4. Re-run script.", title="Gated Model Access / Permission Required", border_style="red"))
        elif is_auth:
            console.print(Panel(f"[bold red]AUTH ERROR (401)[/]\n\nFailed to cache '{repo_id}'.\nCheck your Hugging Face token (is it valid? has 'read' permissions?).\nTry `huggingface-cli login`.", title="Authentication Failed", border_style="red"))
        else:
            # Handle other HTTP errors
            console.print(f"[red]HTTP ERROR during cache/download ({getattr(e, 'response', None)}): {e}[/red]")
            console.print_exception(show_locals=False)
        return None # Download failed
    except RepositoryNotFoundError:
        console.print(f"[red]Repository not found: {repo_id}[/red]")
        return None
    except Exception as e:
        console.print(f"[red]Unexpected error during cache/download for {repo_id}: {e}[/red]")
        console.print_exception(show_locals=False)
        return None # Download failed
# FINISH ### TRANSFORMERS DOWNLOAD/CACHE MANAGER ###


# START ### FastAPI SERVER CONFIG GENERATOR ###
def generate_fastapi_config(repo_id, system_specs, model_info_obj):
    # Check if essential libraries are available before proceeding
    if not TORCH_AVAILABLE:
         print_styled("Error: PyTorch is required for FastAPI server generation.", "error_red")
         return None
    if not TRANSFORMERS_AVAILABLE:
        print_styled("Error: Transformers library is required for FastAPI server generation.", "error_red")
        return None

    if not repo_id:
        print_styled("Error: No repo_id provided for FastAPI config generation.", "error_red")
        return None

    # Determine device and default dtype based on availability
    device = "cpu"
    torch_dtype = "float32" # Default to float32 for CPU or if checks fail
    gpu_ram_gb = system_specs.get("detected_gpu_ram_gb", 0)

    if torch.cuda.is_available() and torch.cuda.device_count() > 0:
        device = "cuda"
        try:
            if torch.cuda.is_bf16_supported():
                torch_dtype = "bfloat16"
                console.print("[dim]BF16 supported on GPU, default dtype = bfloat16[/dim]")
            elif gpu_ram_gb >= 6: # Heuristic: GPUs with >= 6GB often handle float16 well
                torch_dtype = "float16"
                console.print("[dim]GPU detected, default dtype = float16[/dim]")
            else:
                torch_dtype = "float32" # Fallback for lower VRAM GPUs
                console.print("[yellow]Warning: Low GPU VRAM detected, defaulting to float32.[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Warning: Error checking GPU dtype support: {e}. Using auto (likely float32).[/yellow]")
            torch_dtype = "auto" # Let transformers decide if checks fail
    elif hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
        device = "mps"
        # MPS usually works best with float32 or sometimes float16
        torch_dtype = "float32" # Safer default for MPS
        console.print("[dim]Apple Metal (MPS) detected, default dtype = float32[/dim]")
    else:
        console.print("[yellow]No CUDA or MPS detected. Using CPU, default dtype = float32.[/yellow]")

    # Allow overriding dtype via environment variable
    env_torch_dtype = os.environ.get("TRANSFORMERS_TORCH_DTYPE")
    if env_torch_dtype and env_torch_dtype.lower() in ["float16", "bfloat16", "float32", "auto"]:
        # Basic validation against device capabilities
        if env_torch_dtype.lower() == "bfloat16" and device == "cuda" and not torch.cuda.is_bf16_supported():
             console.print(f"[yellow]Warning: Env var requested bfloat16, but GPU doesn't support it. Using float16/float32 instead.[/yellow]")
             torch_dtype = "float16" if gpu_ram_gb >= 6 else "float32"
        elif env_torch_dtype.lower() in ["float16", "bfloat16"] and device == "cpu":
             console.print(f"[yellow]Warning: Env var requested {env_torch_dtype} but device is CPU. Using float32.[/yellow]")
             torch_dtype = "float32"
        else:
             torch_dtype = env_torch_dtype.lower()
             console.print(f"[cyan]Using torch_dtype from environment variable: {torch_dtype}[/cyan]")

    # --- Quantization Setup ---
    quantization = os.environ.get("TRANSFORMERS_QUANT", "none").lower()
    quantization_config_args = None
    bnb_available = BITSANDBYTES_AVAILABLE

    if quantization in ["4bit", "8bit"] and device == "cuda":
        if bnb_available:
            compute_dtype = None
            if torch_dtype == "bfloat16": compute_dtype = torch.bfloat16
            elif torch_dtype == "float16": compute_dtype = torch.float16
            else: compute_dtype = torch.float16; console.print("[yellow]Quantization needs float16/bfloat16 compute type, defaulting to float16.[/yellow]") # Default compute type

            if quantization == "4bit":
                 quant_type = os.environ.get("BNB_4BIT_QUANT_TYPE", "nf4").lower()
                 use_double_quant = os.environ.get("BNB_4BIT_USE_DOUBLE_QUANT", "False").lower() == "true"
                 quantization_config_args = {
                     "load_in_4bit": True,
                     "bnb_4bit_quant_type": quant_type,
                     "bnb_4bit_use_double_quant": use_double_quant,
                     "bnb_4bit_compute_dtype": compute_dtype
                 }
                 console.print(f"[cyan]Using 4-bit quantization (type={quant_type}, double={use_double_quant}, compute={str(compute_dtype).split('.')[-1]})[/cyan]")
            else: # 8bit
                 quantization_config_args = {"load_in_8bit": True}
                 console.print("[cyan]Using 8-bit quantization.[/cyan]")
        else:
            console.print(f"[yellow]bitsandbytes library not found. Cannot use {quantization} quantization. Disabling.[/yellow]")
            quantization = "none"
    elif quantization != "none":
        console.print(f"[yellow]Quantization mode '{quantization}' not supported or device is not CUDA. Disabling.[/yellow]")
        quantization = "none"


    # --- Attention Implementation Setup ---
    use_flash_attn_env = os.environ.get("USE_FLASH_ATTENTION", "auto").lower()
    attn_implementation = None
    is_cuda_bf16_fp16 = (device == "cuda" and torch_dtype in ["float16", "bfloat16"])

    if use_flash_attn_env == "true":
        if is_cuda_bf16_fp16:
             attn_implementation="flash_attention_2"
             console.print("[cyan]Forcing Flash Attention 2 via environment variable.[/cyan]")
        else:
             console.print("[yellow]Warning: Forcing Flash Attention 2 requested, but device/dtype not optimal. May fail.[/yellow]")
             attn_implementation="flash_attention_2" # Still set it, let transformers handle potential error
    elif use_flash_attn_env == "auto" and is_cuda_bf16_fp16:
        try:
            # Check if flash_attn is installed *and* compatible version
            import flash_attn
            # Add version check if necessary based on transformers requirements
            attn_implementation="flash_attention_2"
            console.print("[cyan]Attempting Flash Attention 2 (auto mode).[/cyan]")
        except ImportError:
            console.print("[yellow]Flash Attention 2 (auto) desired but `flash_attn` package not found. Using default attention.[/yellow]")
            # Fallback to sdpa if supported? Or let transformers choose.
            if hasattr(torch.nn.functional, 'scaled_dot_product_attention'):
                 attn_implementation="sdpa"; console.print("[dim]Falling back to SDPA attention implementation.[/dim]")
            else: attn_implementation=None; console.print("[dim]Using default Eager attention implementation.[/dim]")
    elif use_flash_attn_env == "false":
        console.print("[cyan]Flash Attention explicitly disabled via environment variable.[/cyan]")
        # Optionally force SDPA if available and flash is disabled
        if hasattr(torch.nn.functional, 'scaled_dot_product_attention'):
             attn_implementation="sdpa"; console.print("[dim]Using SDPA attention implementation (Flash disabled).[/dim]")
    elif not is_cuda_bf16_fp16:
         # Default for CPU, MPS, or float32 GPU
         if hasattr(torch.nn.functional, 'scaled_dot_product_attention'):
             attn_implementation="sdpa"; console.print("[dim]Using SDPA attention implementation (default for device/dtype).[/dim]")
         else: attn_implementation=None; console.print("[dim]Using default Eager attention implementation.[/dim]")

    # --- Final Config Assembly ---
    config = {
        "repo_id": repo_id,
        "host": os.environ.get("TRANSFORMERS_HOST", "0.0.0.0"),
        "port": int(os.environ.get("TRANSFORMERS_PORT", 8081)), # Default API port
        "device": device, # cpu, cuda, mps
        "torch_dtype": torch_dtype, # float16, bfloat16, float32, auto
        "quantization": quantization, # 4bit, 8bit, none
        "quantization_config_args": quantization_config_args, # Dict or None
        "device_map": os.environ.get("TRANSFORMERS_DEVICE_MAP", "auto"),
        "trust_remote_code": os.environ.get("TRUST_REMOTE_CODE", "false").lower() == "true",
        "attn_implementation": attn_implementation, # flash_attention_2, sdpa, None (eager)
        # --- Generation Parameters ---
        "model_alias": os.environ.get("TRANSFORMERS_MODEL_ALIAS", repo_id.split('/')[-1]),
        "max_new_tokens": int(os.environ.get("MAX_NEW_TOKENS", 512)),
        "temperature": float(os.environ.get("TEMPERATURE", 0.7)),
        "do_sample": os.environ.get("DO_SAMPLE", "true").lower() == "true",
        "top_p": float(os.environ.get("TOP_P", 1.0)), # Often set closer to 0.9 or 0.95 for sampling
        "top_k": int(os.environ.get("TOP_K", 50)), # Only active if do_sample is True
        # --- Server Config ---
        "uvicorn_workers": int(os.environ.get("UVICORN_WORKERS", 1)) # Usually 1 for LLMs unless specifically designed for multi-worker
    }

    console.print(Panel.fit("[green]Generated FastAPI Server Config:[/green]", border_style="green"))
    try:
        from rich.pretty import pprint
        pprint(config, expand_all=True)
    except ImportError:
        console.print(json.dumps(config, indent=2, default=lambda o: str(o) if isinstance(o, type) else repr(o)))

    return config
    
# START ### SERVICE LAUNCHER ###
# This remains specific to 'run_bolt.py', might need generalization
# or removal if not used.
def launch_bolt():
    try:
        deploy_bolt_dir = Path.home() / "deploy.bolt"
        run_script = deploy_bolt_dir / "run_bolt.py"
        if not run_script.exists():
             console.print(f"[red]Error: run_bolt.py not found in {deploy_bolt_dir}[/red]")
             return False

        # Check if terminator exists
        if subprocess.run(['which', 'terminator'], capture_output=True, text=True).returncode != 0:
            console.print("[red]Error: 'terminator' command not found. Cannot launch bolt UI automatically.[/red]")
            console.print("[yellow]Suggestion: Manually navigate to deploy.bolt directory and run 'python3 run_bolt.py'[/yellow]")
            return False

        # Launch using terminator
        process = subprocess.Popen(
            ['terminator', '--working-directory', str(deploy_bolt_dir), '-x', f'python3 {run_script}']
        )
        console.print(f"[cyan]Launched run_bolt.py in new Terminator window (PID: {process.pid}).[/cyan]")
        return True

    except Exception as e:
        console.print(f"[red]Error launching run_bolt.py: {str(e)}[/red]")
        return False
# FINISH ### SERVICE LAUNCHER ###


# START ### MAIN FUNCTION ###
def main():
    console.print(Panel.fit("[cyan]MODEL SETUP & SERVER GENERATOR[/cyan]", border_style="cyan"))
    url = Prompt.ask("\nEnter Hugging Face URL or Repo ID\n[dim](e.g., google/gemma-2b or TheBloke/Mistral-7B-Instruct-v0.2-GGUF)[/dim]")
    repo_id = validate_hf_url(url)
    if not repo_id: console.print("[red]Invalid URL/Repo ID.[/red]"); sys.exit(1)
    console.print(f"\n[cyan]Processing Repo:[/cyan] {repo_id}")

    # --- Fetch model info upfront ---
    model_info_obj = None
    try:
        # Analyze first, which prints the table
        model_info_obj = analyze_model(repo_id)
        if not model_info_obj:
            # If analyze_model printed an error but returned None (e.g., gated repo access failed)
            print_styled(f"Warning: Could not retrieve detailed model info for {repo_id}. Type detection might be less reliable.", "warn_yellow")
            # Attempt basic info fetch again just to get tags if possible
            try:
                api = HfApi()
                model_info_obj = api.model_info(repo_id, token=True) # Use token=True for CLI login check
            except Exception as basic_info_err:
                # If even basic info fails, we probably can't proceed reasonably
                print_styled(f"Fatal: Unable to fetch even basic model info required for type detection: {basic_info_err}", "error_red")
                sys.exit(1)

    except SystemExit: raise # Don't catch sys.exit from analyze_model
    except Exception as e:
        print_styled(f"Fatal: Unexpected error during model analysis phase: {e}", "error_red")
        sys.exit(1)

    # --- Get System Specs ---
    sys_specs = check_system_specs()
    if sys_specs:
        console.print(f"\n[cyan]System Specs:[/cyan]"); console.print(f"  RAM: [yellow]{sys_specs['total_ram']:.1f}GB[/yellow]")
        if sys_specs.get("gpu_name"): console.print(f"  GPU: [yellow]{sys_specs['gpu_name']} ({sys_specs.get('detected_gpu_ram_gb', 0):.1f}GB)[/yellow]")
        else: console.print("  GPU: [yellow]Not Detected/Check Failed[/yellow]")
        if sys_specs.get("recommended_quant"): console.print(f"  Recommended Quant (GGUF): [green]{sys_specs['recommended_quant']}[/green]\n")
    else: console.print("[red]Could not determine system specs. Proceeding with defaults.[/red]"); sys_specs={} # Set empty dict


    # --- Get File List ---
    gguf_files, other_files = get_model_files(repo_id)
    if gguf_files is None and other_files is None:
        # Error message already printed by get_model_files
        sys.exit(1)

    # --- Determine Model Type (Improved Logic) ---
    console.print("[cyan]Detecting model type...[/cyan]")
    model_type = None

    # 1. Check for GGUF files first
    if gguf_files:
        console.print("[green]Detected GGUF model type (found .gguf files).[/green]")
        model_type = "gguf"
    else:
        # Use model_info_obj if available for more reliable detection
        if model_info_obj:
            tags = getattr(model_info_obj, 'tags', [])
            pipeline = getattr(model_info_obj, 'pipeline_tag', None)
            library = getattr(model_info_obj, 'library_name', None)

            # 2. Check for Diffusers via tags, pipeline, or library name
            if "diffusers" in tags or library == "diffusers" or (pipeline and "diffusers" in pipeline):
                 console.print("[green]Detected Diffusers model type (via tags/pipeline/library).[/green]")
                 model_type = "diffusers"
            # 3. Check for standard Transformers via config.json + weights (if not diffusers)
            elif library == "transformers" or (any(f.lower()=='config.json' for f in other_files) and any(f.lower().endswith(('.safetensors','.bin', '.pth', '.pt')) for f in other_files)):
                 console.print("[green]Detected standard Transformers model type (via tags/files).[/green]")
                 model_type = "transformers"
            else:
                # Model info existed but didn't match known patterns
                console.print("[yellow]Warning: Model info found, but couldn't classify as GGUF, Diffusers, or standard Transformers based on tags/files.[/yellow]")
                console.print(f"[dim]Tags:[/dim] {tags}")
                console.print(f"[dim]Pipeline:[/dim] {pipeline}")
                console.print(f"[dim]Library:[/dim] {library}")
                # Attempt file structure check as last resort
                if other_files and "model_index.json" in other_files:
                     console.print("[yellow]Assuming Diffusers model type based on model_index.json.[/yellow]")
                     model_type = "diffusers"
                elif other_files and any(f.lower()=='config.json' for f in other_files) and any(f.lower().endswith(('.safetensors','.bin', '.pth', '.pt')) for f in other_files):
                     console.print("[yellow]Assuming standard Transformers model type based on root config/weights.[/yellow]")
                     model_type = "transformers"
                else:
                     console.print("[red]Could not determine model type from available info and files.[/red]")
                     sys.exit(1)

        else:
             # Fallback if model_info failed earlier (less reliable)
             console.print("[yellow]Warning: No detailed model info available. Detecting type based on file structure only.[/yellow]")
             if other_files and "model_index.json" in other_files:
                  console.print("[green]Detected Diffusers model type (via model_index.json).[/green]")
                  model_type = "diffusers"
             elif other_files and any(f.lower()=='config.json' for f in other_files) and any(f.lower().endswith(('.safetensors','.bin', '.pth', '.pt')) for f in other_files):
                  console.print("[green]Detected standard Transformers model type (via root config/weights).[/green]")
                  model_type = "transformers"
             else:
                  console.print("[red]Could not determine model type from file structure alone.[/red]")
                  sys.exit(1)

    # --- Handle Based on Type ---
    if model_type == "gguf":
        handle_gguf_workflow(repo_id, sys_specs, gguf_files) # Pass gguf_files list
    elif model_type in ["transformers", "diffusers"]:
        # Pass model_info_obj to the handler
        handle_transformers_workflow(repo_id, sys_specs, model_info_obj)
    # No else needed as we exit if type is unknown

    console.print("\n[cyan]Setup script finished.[/cyan]")

# END ### MAIN FUNCTION ###


# START ### GGUF WORKFLOW FUNCTION ###
def handle_gguf_workflow(repo_id, sys_specs, gguf_files):
    console.print("\n[cyan]Available GGUF model files:[/cyan]")
    valid_choices = []
    displayed_files = [] # Keep track of files actually displayed

    if not gguf_files:
        console.print("[red]No GGUF files found in the repository listing.[/red]")
        return # Exit if no GGUF files were passed or found

    # Display available files with size and quant info
    for i, file in enumerate(gguf_files, 1):
        # Fetch size for display, handle potential errors
        size_gb = get_file_size(repo_id, file)
        size_str = f"({size_gb:.2f}GB)" if size_gb is not None else "(size unknown)"

        # Determine quant type and find associated info
        quant_type = next((k for k in QUANT_INFO.keys() if k in file), None)
        quant_details = ""
        if quant_type and quant_type in QUANT_INFO:
            info = QUANT_INFO[quant_type]
            quant_details = f"\n   [dim]Quality: {info['quality']} | RAM: {info['ram']}[/dim]"

        # Print file option
        console.print(f"{i}. [yellow]{file}[/yellow] {size_str}{quant_details}")
        valid_choices.append(str(i))
        displayed_files.append({"name": file, "size_gb": size_gb}) # Store name and size

    # --- File Selection ---
    selected_file_info = None
    if not displayed_files:
        console.print("[red]Error: Could not display any GGUF files.[/red]")
        return

    if len(displayed_files) > 1:
        choice = Prompt.ask("\n[cyan]Which GGUF file do you want to download/use?[/cyan]", choices=valid_choices)
        try:
            selected_file_info = displayed_files[int(choice) - 1]
        except (ValueError, IndexError):
             console.print("[red]Invalid selection.[/red]"); return
    else:
        selected_file_info = displayed_files[0] # Auto-select if only one
        console.print(f"\n[yellow]Auto-selected the only GGUF file:[/yellow] {selected_file_info['name']}")

    if not selected_file_info: return # Should not happen if logic is correct

    selected_file_name = selected_file_info["name"]
    console.print(f"\n[green]Selected GGUF:[/green] {selected_file_name}")

    # --- Check if File Exists Locally (DB then Filesystem) ---
    existing_path_str = check_gguf_exists_in_db(repo_id, selected_file_name)

    if not existing_path_str:
        # If not in DB (or file missing from DB path), check expected filesystem path
        quant_type_local = next((k for k in QUANT_INFO.keys() if k in selected_file_name), "base")
        expected_local_dir = setup_model_directory(repo_id, quant_type_local)
        expected_local_path = expected_local_dir / selected_file_name
        if expected_local_path.exists() and expected_local_path.is_file():
            console.print(f"[green]Model found at expected local path (but not DB):[/green] {expected_local_path}")
            # Ask to use it and update DB
            if Prompt.ask("Use this file and update database?", choices=["y", "n"], default="y") == "y":
                 existing_path_str = str(expected_local_path)
                 console.print("[dim]Updating database entry for existing file...[/dim]")
                 model_info_payload = {"repo_id": repo_id, "file": selected_file_name, "type": "gguf", "size_gb": selected_file_info["size_gb"]}
                 update_gguf_db_entry(repo_id, selected_file_name, expected_local_path, model_info_payload)
            else:
                 console.print("[yellow]User chose not to use existing file. Will prompt for download.[/yellow]")
                 existing_path_str = None # Treat as not existing if user declines
        # else: File doesn't exist locally either

    # --- Handle Download/Use Decision ---
    downloaded_path = None
    model_info_payload = {"repo_id": repo_id, "file": selected_file_name, "type": "gguf", "size_gb": selected_file_info["size_gb"]}

    if existing_path_str:
        console.print(f"[green]Model found in DB/locally:[/green] {existing_path_str}")
        if Prompt.ask("Re-download this file anyway?", choices=["y","n"], default="n") == "y":
             console.print("[yellow]Proceeding with re-download...[/yellow]")
             downloaded_path = download_model(repo_id, selected_file_name, model_info_payload)
        else:
             downloaded_path = existing_path_str # User chose not to re-download, use existing path
             console.print("[cyan]Using existing local file.[/cyan]")
    else:
        # File doesn't exist locally or user wants to ignore existing file
        console.print(f"[yellow]Model '{selected_file_name}' not found locally or user opted to ignore.[/yellow]")
        if Prompt.ask("\n[cyan]Download this GGUF model?[/cyan]", choices=["y", "n"], default="y") == "y":
            downloaded_path = download_model(repo_id, selected_file_name, model_info_payload)
        else:
            console.print("[red]Download skipped by user.[/red]")
            return # User skipped download, nothing more to do for this model

    # --- Final Check ---
    if not downloaded_path:
        console.print("[red]Model acquisition failed (download or selection error).[/red]")
        return
    else:
         console.print(f"[green]✓ Ready to use GGUF model:[/green] {downloaded_path}")
         # Future: Add logic here to configure llama.cpp or other GGUF servers if needed

# FINISH ### GGUF WORKFLOW FUNCTION ###


# START ### TRANSFORMERS WORKFLOW FUNCTION ###
def handle_transformers_workflow(repo_id, sys_specs, model_info_obj):
    model_type = "Transformers/Diffusers" # Generic term
    if model_info_obj:
        tags = getattr(model_info_obj, 'tags', [])
        library = getattr(model_info_obj, 'library_name', None)
        if "diffusers" in tags or library == "diffusers": model_type = "Diffusers"
        elif library == "transformers": model_type = "Transformers"

    console.print(f"\n[cyan]Preparing setup for {model_type} model...[/cyan]")

    # Ensure the model is cached using the updated function
    model_repo_id_confirmed = ensure_transformers_model(repo_id, model_info_obj)

    if not model_repo_id_confirmed:
        console.print(f"[red]{model_type} model caching/download failed or skipped.[/red]")
        return # Cannot proceed without the model cache

    console.print(f"\n[green]✓ {model_type} model '{repo_id}' cache ready.[/green]")

   # START ### TRANSFORMERS WORKFLOW FUNCTION ###
def handle_transformers_workflow(repo_id, sys_specs, model_info_obj):
    model_type = "Transformers/Diffusers" # Generic term
    if model_info_obj:
        tags = getattr(model_info_obj, 'tags', [])
        library = getattr(model_info_obj, 'library_name', None)
        pipeline = getattr(model_info_obj, 'pipeline_tag', None) # Get pipeline tag too
        if "diffusers" in tags or library == "diffusers" or (pipeline and "diffusers" in pipeline):
             model_type = "Diffusers"
        elif library == "transformers" or pipeline == "text-generation" or "text-generation" in tags:
             model_type = "Transformers (Text Gen)"
        else:
             # Fallback if library/tags aren't conclusive
             model_type = f"Transformers/Other ({pipeline or 'Unknown Pipeline'})"


    console.print(f"\n[cyan]Preparing setup for {model_type} model...[/cyan]")

    # Ensure the model is cached using the updated function
    model_repo_id_confirmed = ensure_transformers_model(repo_id, model_info_obj)

    if not model_repo_id_confirmed:
        console.print(f"[red]{model_type} model caching/download failed or skipped.[/red]")
        return # Cannot proceed without the model cache

    console.print(f"\n[green]✓ {model_type} model '{repo_id}' cache ready.[/green]")
    # --- FastAPI Server Generation (Conditional) ---
    # Check if it's likely a text-generation model before offering server script
    is_text_gen_model = False
    if model_info_obj:
        pipeline = getattr(model_info_obj, 'pipeline_tag', None)
        tags = getattr(model_info_obj, 'tags', [])
        # Broader check for text generation capabilities
        if pipeline in ["text-generation", "text2text-generation", "summarization"] or \
           any(t in tags for t in ["text-generation", "conversational"]):
            is_text_gen_model = True

    if is_text_gen_model:
        if Prompt.ask(f"[cyan]Generate FastAPI server script for this {model_type} model?", choices=["y", "n"], default="y") == "y":
            console.print("[cyan]>> Generating FastAPI server config...[/cyan]")
            # Pass model_info_obj to generator
            config = generate_fastapi_config(repo_id, sys_specs, model_info_obj)
            if config:
                script_path = create_fastapi_script(config)
                if script_path:
                    # Ask to launch only if script created successfully
                    if Prompt.ask("\n[cyan]Start the FastAPI server now?", choices=["y", "n"], default="n") == "y":
                        console.print(f"[cyan]Attempting to execute FastAPI server: python3 {script_path}[/cyan]")
                        try:
                            # Run in background, don't wait for it
                            # Ensure script path is handled correctly
                            server_process = subprocess.Popen(['python3', str(script_path)])
                            console.print(f"[green]FastAPI server process started (PID: {server_process.pid}). Monitor its logs separately.[/green]")
                        except FileNotFoundError:
                            console.print(f"[red]Error: 'python3' command not found. Cannot start server.[/red]")
                        except Exception as e:
                            console.print(f"[red]Failed to start FastAPI server process: {e}[/red]")
                            console.print_exception(show_locals=False)
                else:
                    # Error message already printed by create_fastapi_script
                    pass
            else:
                # Error message already printed by generate_fastapi_config
                console.print("[red]Failed to generate FastAPI server config (required for script creation).[/red]")
        else:
            console.print("[yellow]FastAPI server script generation skipped by user.[/yellow]")
    else:
        console.print(f"[yellow]Skipping FastAPI server generation prompt (model type detected as '{model_type}', not typical text-generation).[/yellow]")
        console.print("[dim]Note: FastAPI server generation is currently only supported for text-generation models.[/dim]")
        # Future: Could offer different types of server generation here based on model type (e.g., diffusers API)

# FINISH ### TRANSFORMERS WORKFLOW FUNCTION ###


# START ### SCRIPT RUNNER ###
if __name__ == "__main__":
    try:
        # --- Environment Checks (Optional but recommended) ---
        print_styled("Checking environment...", "dim_text")
        if sys.version_info < (3, 8):
             print_styled("Error: Python 3.8+ is required.", "error_red")
             sys.exit(1)
        # Could add checks for pip, git, etc. here if needed

        # --- Main Execution ---
        main() # Call the main function defined earlier
        sys.exit(0) # Explicitly exit with 0 on successful completion of main()

    except KeyboardInterrupt:
        print_styled("\nSetup interrupted by user (Ctrl+C).", "warn_yellow")
        sys.exit(130) # Standard exit code for Ctrl+C

    except SystemExit as e:
        # Catch intentional exits (like validation failures) and propagate code
        # Optionally print a message if exit code is non-zero?
        if e.code != 0:
             print_styled(f"Script exited with code: {e.code}", "warn_yellow")
        sys.exit(e.code)

    except Exception as e:
        # Catch any unexpected errors during main execution
        import traceback
        print_styled(f"\n--- UNHANDLED CRITICAL ERROR ---", "error_red")
        print_styled(f"Error Type: {type(e).__name__}", "error_red")
        print_styled(f"Error Message: {str(e)}", "error_red")
        console.print("\n[bold red]Traceback:[/bold red]")
        console.print(f"{traceback.format_exc()}") # Print full traceback
        print_styled(f"---------------------------------", "error_red")
        sys.exit(1) # Exit with non-zero code on error
# FINISH ### SCRIPT RUNNER ##
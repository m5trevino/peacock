# START ### FastAPI SERVER CONFIG/SCRIPT ###
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
            console.print(f"[yellow]Warning: Error checking GPU dtype support: {{e}}. Using auto (likely float32).[/yellow]")
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
             console.print(f"[yellow]Warning: Env var requested {{env_torch_dtype}} but device is CPU. Using float32.[/yellow]")
             torch_dtype = "float32"
        else:
             torch_dtype = env_torch_dtype.lower()
             console.print(f"[cyan]Using torch_dtype from environment variable: {{torch_dtype}}[/cyan]")

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
                 quantization_config_args = {{
                     "load_in_4bit": True,
                     "bnb_4bit_quant_type": quant_type,
                     "bnb_4bit_use_double_quant": use_double_quant,
                     "bnb_4bit_compute_dtype": compute_dtype
                 }}
                 console.print(f"[cyan]Using 4-bit quantization (type={{quant_type}}, double={{use_double_quant}}, compute={{str(compute_dtype).split('.')[-1]}})[/cyan]")
            else: # 8bit
                 quantization_config_args = {{"load_in_8bit": True}}
                 console.print("[cyan]Using 8-bit quantization.[/cyan]")
        else:
            console.print(f"[yellow]bitsandbytes library not found. Cannot use {{quantization}} quantization. Disabling.[/yellow]")
            quantization = "none"
    elif quantization != "none":
        console.print(f"[yellow]Quantization mode '{{quantization}}' not supported or device is not CUDA. Disabling.[/yellow]")
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
            import flash_attn
            attn_implementation="flash_attention_2"
            console.print("[cyan]Attempting Flash Attention 2 (auto mode).[/cyan]")
        except ImportError:
            console.print("[yellow]Flash Attention 2 (auto) desired but `flash_attn` package not found. Using default attention.[/yellow]")
            if hasattr(torch.nn.functional, 'scaled_dot_product_attention'):
                 attn_implementation="sdpa"; console.print("[dim]Falling back to SDPA attention implementation.[/dim]")
            else: attn_implementation=None; console.print("[dim]Using default Eager attention implementation.[/dim]")
    elif use_flash_attn_env == "false":
        console.print("[cyan]Flash Attention explicitly disabled via environment variable.[/cyan]")
        if hasattr(torch.nn.functional, 'scaled_dot_product_attention'):
             attn_implementation="sdpa"; console.print("[dim]Using SDPA attention implementation (Flash disabled).[/dim]")
    elif not is_cuda_bf16_fp16:
         if hasattr(torch.nn.functional, 'scaled_dot_product_attention'):
             attn_implementation="sdpa"; console.print("[dim]Using SDPA attention implementation (default for device/dtype).[/dim]")
         else: attn_implementation=None; console.print("[dim]Using default Eager attention implementation.[/dim]")

    # --- Final Config Assembly ---
    config = {{
        "repo_id": repo_id,
        "host": os.environ.get("TRANSFORMERS_HOST", "0.0.0.0"),
        "port": int(os.environ.get("TRANSFORMERS_PORT", 8081)), # Default API port
        "device": device,
        "torch_dtype": torch_dtype,
        "quantization": quantization,
        "quantization_config_args": quantization_config_args,
        "device_map": os.environ.get("TRANSFORMERS_DEVICE_MAP", "auto"),
        "trust_remote_code": os.environ.get("TRUST_REMOTE_CODE", "false").lower() == "true",
        "attn_implementation": attn_implementation,
        "model_alias": os.environ.get("TRANSFORMERS_MODEL_ALIAS", repo_id.split('/')[-1]),
        "max_new_tokens": int(os.environ.get("MAX_NEW_TOKENS", 512)),
        "temperature": float(os.environ.get("TEMPERATURE", 0.7)),
        "do_sample": os.environ.get("DO_SAMPLE", "true").lower() == "true",
        "top_p": float(os.environ.get("TOP_P", 1.0)),
        "top_k": int(os.environ.get("TOP_K", 50)),
        "uvicorn_workers": int(os.environ.get("UVICORN_WORKERS", 1))
    }}

    console.print(Panel.fit("[green]Generated FastAPI Server Config:[/green]", border_style="green"))
    try:
        from rich.pretty import pprint
        pprint(config, expand_all=True)
    except ImportError:
        console.print(json.dumps(config, indent=2, default=lambda o: str(o) if isinstance(o, type) else repr(o)))

    return config

# Corrected create_fastapi_script function with escaped braces
def create_fastapi_script(config):
    if not config:
        print_styled("Error: No configuration provided for FastAPI script generation.", "error_red")
        return None
    if not all([FASTAPI_AVAILABLE, UVICORN_AVAILABLE, PYDANTIC_AVAILABLE, TORCH_AVAILABLE, TRANSFORMERS_AVAILABLE]):
        missing = [lib for lib, available in [("FastAPI", FASTAPI_AVAILABLE), ("Uvicorn", UVICORN_AVAILABLE), ("Pydantic", PYDANTIC_AVAILABLE), ("PyTorch", TORCH_AVAILABLE), ("Transformers", TRANSFORMERS_AVAILABLE)] if not available]
        console.print(f"[red]Error: Cannot create FastAPI script. Missing required libraries: {{', '.join(missing)}}[/red]")
        return None
    if config.get("quantization") != "none" and not BITSANDBYTES_AVAILABLE:
        console.print(f"[red]Error: Quantization '{{config.get('quantization')}}' selected, but 'bitsandbytes' library is missing.[/red]")
        return None
    if config.get("attn_implementation") == "flash_attention_2":
        try: import flash_attn
        except ImportError: console.print(f"[red]Error: Flash Attention 2 selected, but 'flash_attn' package is missing.[/red]"); return None

    try: FASTAPI_SCRIPT_DIR.mkdir(parents=True, exist_ok=True)
    except Exception as e: print_styled(f"Error creating FastAPI script directory {{FASTAPI_SCRIPT_DIR}}: {{e}}", "error_red"); return None

    safe_alias = re.sub(r'[^a-zA-Z0-9_.-]', '_', config['model_alias'])
    script_path = FASTAPI_SCRIPT_DIR / f"run_{{safe_alias}}_fastapi_server.py"

    quant_config_init_str = "None"
    bnb_imports_str = ""
    if config.get("quantization") != "none" and config.get("quantization_config_args"):
        bnb_imports_str = "from transformers import BitsAndBytesConfig\\nimport torch"
        bnb_arg_strs = []
        for k, v in config["quantization_config_args"].items():
            if isinstance(v, type) and 'torch' in str(v): bnb_arg_strs.append(f"{{k}}=torch.{{str(v).split('.')[-1]}}")
            else: bnb_arg_strs.append(f"{{k}}={{repr(v)}}")
        quant_config_init_str = f"BitsAndBytesConfig({{', '.join(bnb_arg_strs)}})"

    attn_impl_str = f'"{{config["attn_implementation"]}}"' if config["attn_implementation"] else "None"
    flash_attn_import_str = "import flash_attn" if config["attn_implementation"] == "flash_attention_2" else ""

    # --- Start of the massive f-string template ---
    # All literal braces { } needed in the final script must be doubled {{ }}
    # Variable insertions like {config['repo_id']} remain single-braced
    script_content = f"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# FastAPI Server Script generated by huggingfaceclean.py

import os
import logging
import torch
import uvicorn
import gc
import time
import sys
from typing import Optional, Dict, Any

# Required imports
try:
    from transformers import AutoTokenizer, AutoModelForCausalLM, GenerationConfig
    {bnb_imports_str}
    {flash_attn_import_str}
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field
except ImportError as e:
    print(f"ERROR: Missing required libraries for FastAPI server: {{e}}")
    # Escape f-string braces within the error message string itself!
    print(f"Please install: pip install fastapi uvicorn transformers torch pydantic[email] accelerate {{'bitsandbytes' if {repr(config.get('quantization'))} != 'none' else ''}} {{'flash_attn' if {repr(config.get('attn_implementation'))} == 'flash_attention_2' else ''}}")
    sys.exit(1)

# --- Configuration ---
MODEL_REPO_ID = "{config['repo_id']}"
DEVICE_MAP = "{config['device_map']}"
TORCH_DTYPE_STR = "{config['torch_dtype']}"
QUANTIZATION_MODE = "{config['quantization']}"
TRUST_REMOTE_CODE = {config['trust_remote_code']}
ATTN_IMPLEMENTATION = {attn_impl_str}

HOST = "{config['host']}"
PORT = {config['port']}
UVICORN_WORKERS = {config['uvicorn_workers']}

# Default Generation Parameters
DEFAULT_MAX_NEW_TOKENS = {config['max_new_tokens']}
DEFAULT_TEMPERATURE = {config['temperature']}
DEFAULT_DO_SAMPLE = {config['do_sample']}
DEFAULT_TOP_P = {config['top_p']}
DEFAULT_TOP_K = {config['top_k']}

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(threadName)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# --- Global Variables ---
tokenizer = None
model = None
model_device = "cpu"
model_loaded = False
app_startup_error = None

# --- Pydantic Models ---
class GenerationRequest(BaseModel):
    prompt: str
    max_new_tokens: Optional[int] = Field(default=DEFAULT_MAX_NEW_TOKENS, gt=0, description="Max new tokens to generate.")
    temperature: Optional[float] = Field(default=DEFAULT_TEMPERATURE, ge=0.0, description="Sampling temperature (active if do_sample=True).")
    do_sample: Optional[bool] = Field(default=DEFAULT_DO_SAMPLE, description="Whether to use sampling.")
    top_p: Optional[float] = Field(default=DEFAULT_TOP_P, ge=0.0, le=1.0, description="Top-p nucleus sampling probability (active if do_sample=True).")
    top_k: Optional[int] = Field(default=DEFAULT_TOP_K, ge=0, description="Top-k sampling (active if do_sample=True).")

class GenerationResponse(BaseModel):
    generated_text: str
    model_id: str = MODEL_REPO_ID
    device: str
    inference_time_ms: float
    prompt_tokens: Optional[int] = None
    generated_tokens: Optional[int] = None

class HealthResponse(BaseModel):
    status: str
    model_id: str = MODEL_REPO_ID
    device: str
    model_loaded: bool
    error_message: Optional[str] = None

# --- Helper Functions ---
def get_torch_dtype(dtype_str: str):
    # Use double braces {{ }} for literal dict braces in the generated code
    dtype_map = {{
        'float16': torch.float16,
        'bfloat16': torch.bfloat16,
        'float32': torch.float32,
        'auto': 'auto'
    }}
    dtype = dtype_map.get(dtype_str.lower())
    if dtype:
        if dtype == torch.bfloat16 and torch.cuda.is_available() and not torch.cuda.is_bf16_supported():
            logger.warning("BF16 requested but not supported by CUDA device, falling back to FP16.")
            return torch.float16
        return dtype
    else:
        logger.warning(f"Invalid torch_dtype '{{dtype_str}}', using 'auto'.")
        return 'auto'

# --- FastAPI App ---
app = FastAPI(
    title=f"LLM Inference Server ({{config['model_alias']}})", # Double braces around config needed here!
    version="1.0.3", # Incremented version
    description=f"API for generating text using the {{MODEL_REPO_ID}} model.",
)

# --- Startup Event: Load Model ---
@app.on_event("startup")
async def startup_event():
    global tokenizer, model, model_device, model_loaded, app_startup_error
    app_startup_error = None
    logger.info(f"--- Server Startup: Attempting to Load Model {{MODEL_REPO_ID}} ---")
    if model_loaded:
        logger.warning("Model already marked as loaded. Skipping reload.")
        return
    try:
        quantization_config = None
        if QUANTIZATION_MODE != "none":
            logger.info(f"Quantization Mode: {{QUANTIZATION_MODE}}")
            if QUANTIZATION_MODE in ["4bit", "8bit"]:
                 try:
                     # Use direct initialization from the pre-formatted string
                     quantization_config = {quant_config_init_str}
                     if not isinstance(quantization_config, (BitsAndBytesConfig, type(None))):
                         raise ValueError(f"Generated quantization_config is not valid: {{type(quantization_config)}}")
                     logger.info(f"BitsAndBytesConfig generated: {{quantization_config}}")
                 except Exception as qc_err:
                     # Log the problematic string for debugging
                     logger.error(f"Error initializing BitsAndBytesConfig from string: {repr(quant_config_init_str)}")
                     raise ValueError(f"Error evaluating BitsAndBytesConfig string: {{qc_err}}") from qc_err

        torch_dtype_actual = get_torch_dtype(TORCH_DTYPE_STR)
        logger.info(f"Target Torch Dtype: {{torch_dtype_actual}}")

        effective_device_map = DEVICE_MAP if DEVICE_MAP.lower() != "cpu" else None
        target_device_hint = DEVICE_MAP if DEVICE_MAP.lower() != "auto" else ("cuda" if torch.cuda.is_available() else "cpu")
        if hasattr(torch.backends, 'mps') and torch.backends.mps.is_available() and target_device_hint == "cpu":
             target_device_hint = "mps"
             if effective_device_map == "auto": effective_device_map = "mps"

        logger.info(f"Effective Device Map: {{effective_device_map or 'None (CPU/Single)'}}, Target Device Hint: {{target_device_hint}}")

        logger.info(f"Loading tokenizer: {{MODEL_REPO_ID}}")
        tokenizer = AutoTokenizer.from_pretrained(MODEL_REPO_ID, trust_remote_code=TRUST_REMOTE_CODE)
        logger.info("Tokenizer loaded.")

        if tokenizer.pad_token_id is None:
            if tokenizer.eos_token_id is not None:
                tokenizer.pad_token_id = tokenizer.eos_token_id
                logger.warning(f"Tokenizer missing pad_token_id, set to eos_token_id: {{tokenizer.eos_token_id}}")
            else:
                default_pad_token = '<|pad|>'
                # Use double braces for the dict literal in the generated code
                tokenizer.add_special_tokens({{'pad_token': default_pad_token}})
                logger.warning(f"Tokenizer missing pad_token_id and eos_token_id. Added new pad_token: {{default_pad_token}}")

        logger.info(f"Loading model: {{MODEL_REPO_ID}} with dtype={{torch_dtype_actual}}, quant={{QUANTIZATION_MODE}}, attn={{ATTN_IMPLEMENTATION or 'default'}}")
        model_load_args: Dict[str, Any] = {{
            "device_map": effective_device_map,
            "torch_dtype": torch_dtype_actual if torch_dtype_actual != 'auto' else None,
            "quantization_config": quantization_config,
            "trust_remote_code": TRUST_REMOTE_CODE,
            "attn_implementation": ATTN_IMPLEMENTATION if ATTN_IMPLEMENTATION else None,
            "low_cpu_mem_usage": True if effective_device_map == "auto" else False
        }}
        model_load_args = {{k: v for k, v in model_load_args.items() if v is not None}}
        logger.debug(f"Model loading arguments: {{model_load_args}}")

        model = AutoModelForCausalLM.from_pretrained(MODEL_REPO_ID, **model_load_args)
        logger.info("Model loaded into memory.")

        if tokenizer.pad_token == '<|pad|>' and hasattr(model, 'resize_token_embeddings') and model.config.vocab_size < len(tokenizer):
            logger.info(f"Resizing token embeddings from {{model.config.vocab_size}} to {{len(tokenizer)}}")
            try: model.resize_token_embeddings(len(tokenizer))
            except Exception as resize_err: logger.error(f"Failed to resize token embeddings: {{resize_err}}", exc_info=True)

        model.eval()

        try:
             first_param_device = str(next(model.parameters()).device)
             model_device = first_param_device
             logger.info(f"Model parameters detected on device: {{model_device}}")
        except Exception as dev_err:
             model_device = target_device_hint
             logger.warning(f"Could not precisely determine model device ({{dev_err}}), assuming target hint: {{model_device}}")

        model_loaded = True
        logger.info(f"--- Model {{MODEL_REPO_ID}} successfully loaded and ready on {{model_device}} ---")

        gc.collect()
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
            logger.info("CUDA cache cleared post-load.")

    except Exception as e:
        logger.critical(f"FATAL ERROR during model loading: {{e}}", exc_info=True)
        model_loaded = False
        model = None
        tokenizer = None
        app_startup_error = f"{{type(e).__name__}}: {{str(e)}}"

# --- API Endpoints ---
@app.post("/generate",
          response_model=GenerationResponse,
          summary="Generate text based on a prompt",
          tags=["Generation"])
async def generate_text_endpoint(request: GenerationRequest):
    # Docstring needs correct indentation within the generated script
    \"\"\"Generates text completion for the given prompt using the loaded model.\"\"\"
    start_time = time.perf_counter()
    if not model_loaded or model is None or tokenizer is None:
        logger.error("Generate request received but model is not ready.")
        detail = f"Model not ready. Startup error: {{app_startup_error or 'Unknown'}}"
        raise HTTPException(status_code=503, detail=detail)

    # Use double braces {{}} for f-string literal within generated code
    logger.info(f"Received generation request: prompt='{{request.prompt[:80]}}...'")
    # Use double braces for dict exclusion braces
    logger.debug(f"Generation parameters: {{request.dict(exclude={{'prompt'}})}}")

    try:
        try:
            inputs = tokenizer(request.prompt, return_tensors="pt", return_attention_mask=True).to(model_device)
            input_token_len = inputs.input_ids.shape[1]
        except Exception as token_err:
             logger.error(f"Error during tokenization or moving inputs to device {{model_device}}: {{token_err}}", exc_info=True)
             raise HTTPException(status_code=500, detail=f"Tokenization error: {{token_err}}")

        gen_config = GenerationConfig(
            max_new_tokens=request.max_new_tokens,
            temperature=request.temperature if request.do_sample else 1.0,
            do_sample=request.do_sample,
            top_p=request.top_p if request.do_sample else None,
            top_k=request.top_k if request.do_sample else None,
            pad_token_id=tokenizer.pad_token_id,
            eos_token_id=tokenizer.eos_token_id,
        )
        logger.debug(f"Effective GenerationConfig: {{gen_config}}")

        with torch.inference_mode():
            outputs = model.generate(**inputs, generation_config=gen_config)

        if outputs is None or not hasattr(outputs, 'shape') or outputs.shape[0] == 0:
             raise ValueError("Model generation returned unexpected output.")

        output_tokens = outputs[0]
        generated_token_ids = output_tokens[input_token_len:]
        generated_tokens_count = len(generated_token_ids)
        generated_text = tokenizer.decode(generated_token_ids, skip_special_tokens=True).strip()

        end_time = time.perf_counter()
        inference_time_ms = (end_time - start_time) * 1000

        logger.info(f"Generation successful. Output length: {{len(generated_text)}} chars, {{generated_tokens_count}} tokens. Time: {{inference_time_ms:.2f}} ms")
        logger.debug(f"Generated text sample: '{{generated_text[:100]}}...'")

        return GenerationResponse(
            generated_text=generated_text,
            device=model_device,
            inference_time_ms=inference_time_ms,
            prompt_tokens=input_token_len,
            generated_tokens=generated_tokens_count
        )

    except Exception as e:
        logger.error(f"Error during text generation processing: {{e}}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error during generation: {{str(e)}}")


@app.get("/health",
         response_model=HealthResponse,
         summary="Check server health and model status",
         tags=["Health"])
async def health_check_endpoint():
    # Docstring needs correct indentation within the generated script
    \"\"\"Returns the current status of the server and the loaded model.\"\"\"
    global model_device, model_loaded, app_startup_error
    status = "ok" if model_loaded else "error"
    code = 200 if model_loaded else 503
    return JSONResponse(
        # Use double braces for dict literal
        content=HealthResponse(
            status=status,
            device=model_device,
            model_loaded=model_loaded,
            error_message=app_startup_error
        ).model_dump(exclude_none=True),
        status_code=code
    )

# --- Main Execution Guard ---
if __name__ == "__main__":
    logger.info(f"Starting FastAPI server for {{MODEL_REPO_ID}} on {{HOST}}:{{PORT}}...")
    logger.info(f"Number of workers: {{UVICORN_WORKERS}}")
    uvicorn.run(
        app="__main__:app",
        host=HOST,
        port=PORT,
        workers=UVICORN_WORKERS,
        log_level="info",
        reload=False
    )

""" # --- End of the massive f-string template ---

    # Write script content to file
    try:
        with open(script_path, "w", encoding="utf-8") as f: # Specify encoding
            f.write(script_content)
        # Make executable
        script_path.chmod(0o755)
        console.print(f"\n[green]✓ Transformers/Diffusers FastAPI server script created:[/green] {{script_path}}")
        return str(script_path)
    except Exception as e:
        console.print(f"[red]Error creating FastAPI script file {{script_path}}: {{e}}[/red]")
        return None
# FINISH ### FastAPI SERVER CONFIG/SCRIPT ###
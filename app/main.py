import os
import time
from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from dotenv import load_dotenv

# Load keys from local frequency (.env)
load_dotenv()

from app.config import MODEL_REGISTRY, AMMO_DIR, START_DIR, PROMPTS_DIR, SESSIONS_DIR, REFINED_DIR
from app.core.striker import execute_strike
from app.core.fs import get_files_with_meta, read_file_content, secure_prompt, list_prompts, save_session

app = FastAPI(title="Peacock Engine V2")

# Casino Doctrine: Allow all origins for local HUD connectivity
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class StrikeRequest(BaseModel):
    modelId: str
    prompt: str
    temp: float = 0.7
    phase: Optional[str] = None
    format_mode: Optional[str] = None
    responseFormat: Optional[Any] = None

@app.get("/")
async def root():
    return {
        "status": "OPERATIONAL",
        "engine": "PEACOCK_V2_PYTHON",
        "port": 3099,
        "vault_status": {
            "groq": "LOADED" if os.getenv("GROQ_KEYS") else "MISSING",
            "google": "LOADED" if os.getenv("GOOGLE_KEYS") else "MISSING",
            "mistral": "LOADED" if os.getenv("MISTRAL_KEYS") else "MISSING"
        }
    }

@app.get("/v1/models")
async def get_models():
    return MODEL_REGISTRY

@app.post("/v1/strike")
async def strike(req: StrikeRequest):
    try:
        result = await execute_strike(
            model_id=req.modelId, 
            prompt=req.prompt, 
            temp=req.temp, 
            format_mode=req.format_mode
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- FILESYSTEM BRIDGE ---

@app.get("/v1/fs/start")
async def get_start_files():
    return get_files_with_meta(START_DIR)

@app.get("/v1/fs/start/{file_name}")
async def read_start_file(file_name: str):
    return {"content": read_file_content(START_DIR, file_name)}

@app.get("/v1/fs/ammo")
async def get_ammo_files():
    return get_files_with_meta(AMMO_DIR)

@app.get("/v1/fs/ammo/{file_name}")
async def read_ammo_file(file_name: str):
    return {"content": read_file_content(AMMO_DIR, file_name)}

@app.get("/v1/fs/prompts/{phase}")
async def get_prompts(phase: str):
    return list_prompts(phase)

@app.post("/v1/fs/prompts/{phase}")
async def post_prompt(phase: str, data: Dict[str, str] = Body(...)):
    secure_prompt(phase, data["name"], data["content"])
    return {"status": "SECURED"}

@app.post("/v1/fs/sessions")
async def post_session(data: Dict[str, Any] = Body(...)):
    name = data.get("name", f"session_{int(time.time())}.json")
    save_session(name, data.get("data", {}))
    return {"status": "SECURED"}

@app.get("/v1/health")
async def health():
    return {"status": "ONLINE", "system": "PEACOCK_ENGINE_V2_PYTHON"}

def start():
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=3099, reload=True)

if __name__ == "__main__":
    start()
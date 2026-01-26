from typing import TypedDict, Literal

class ModelConfig(TypedDict):
    id: str
    gateway: Literal['groq', 'google', 'deepseek', 'mistral']
    tier: Literal['free', 'cheap', 'expensive', 'custom']
    note: str

MODEL_REGISTRY: list[ModelConfig] = [
    # GROQ
    {"id": "llama-3.3-70b-versatile", "gateway": "groq", "tier": "expensive", "note": "Meta Llama 3.3 70B"},
    {"id": "llama-3.1-8b-instant", "gateway": "groq", "tier": "free", "note": "Meta Llama 3.1 8B"},
    {"id": "meta-llama/llama-4-maverick-17b-128e-instruct", "gateway": "groq", "tier": "expensive", "note": "Llama 4 Maverick (17B)"},
    {"id": "qwen/qwen3-32b", "gateway": "groq", "tier": "cheap", "note": "Qwen 3 32B"},
    
    # DEEPSEEK
    {"id": "deepseek-reasoner", "gateway": "deepseek", "tier": "expensive", "note": "DeepSeek R1 (Reasoning)"},
    {"id": "deepseek-chat", "gateway": "deepseek", "tier": "cheap", "note": "DeepSeek V3 (Chat)"},
    
    # MISTRAL
    {"id": "mistral-large-latest", "gateway": "mistral", "tier": "expensive", "note": "Mistral Large"},
    {"id": "codestral-latest", "gateway": "mistral", "tier": "expensive", "note": "Codestral (Latest)"},
    
    # GOOGLE
    {"id": "models/gemini-2.0-flash-exp", "gateway": "google", "tier": "cheap", "note": "Gemini 2.0 Flash (Experimental)"},
    {"id": "models/gemini-1.5-pro", "gateway": "google", "tier": "expensive", "note": "Gemini 1.5 Pro (Stable)"},
]

# Filesystem Paths
BASE_DIR = "/home/flintx/peacock"
AMMO_DIR = "/home/flintx/peacock/ammo"
START_DIR = "/home/flintx/peacock/start"
PROMPTS_DIR = "/home/flintx/peacock/prompts"
REFINED_DIR = "/home/flintx/refined_outputs"
SESSIONS_DIR = "/home/flintx/peacock/sessions"

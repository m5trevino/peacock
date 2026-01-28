import os
import httpx
import re
import json
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from pydantic_ai import Agent
from pydantic_ai.models.groq import GroqModel
from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.models.google import GeminiModel
from app.core.keys import GroqPool, GooglePool, DeepSeekPool, MistralPool
from app.config import MODEL_REGISTRY

# --- STRUCTURED OUTPUT MODELS ---
class EagleFile(BaseModel):
    path: str
    skeleton: str
    directives: str

class EagleScaffold(BaseModel):
    project: str
    files: List[EagleFile]

# --------------------------------

def get_model_config(model_id: str):
    config = next((m for m in MODEL_REGISTRY if m['id'] == model_id), None)
    if not config:
        raise ValueError(f"Unknown Model ID: {model_id}")
    return config

async def execute_strike(model_id: str, prompt: str, temp: float = 0.7, format_mode: Optional[str] = None):
    config = get_model_config(model_id)
    gateway = config['gateway']
    
    # Determine Result Type
    result_type = str
    if format_mode == "eagle_scaffold":
        result_type = EagleScaffold

    model = None
    asset = None

    # Gateway Routing
    if gateway == 'groq':
        asset = GroqPool.get_next()
        # Initial check for Moonshot Bypass on Groq
        if format_mode == "eagle_scaffold" and ("moonshot" in model_id or "kimi" in model_id):
            return await execute_moonshot_bypass(asset.key, model_id, prompt, temp, asset.label)
            
        model = OpenAIModel(
            model_id,
            base_url='https://api.groq.com/openai/v1',
            api_key=asset.key
        )

    elif gateway == 'google':
        asset = GooglePool.get_next()
        model = GeminiModel(
            model_id,
            api_key=asset.key
        )

    elif gateway == 'deepseek':
        asset = DeepSeekPool.get_next()
        model = OpenAIModel(
            model_id,
            base_url='https://api.deepseek.com',
            api_key=asset.key
        )

    elif gateway == 'mistral':
        asset = MistralPool.get_next()
        model = OpenAIModel(
            model_id,
            base_url='https://api.mistral.ai/v1',
            api_key=asset.key
        )
    else:
        raise ValueError(f"Gateway {gateway} not supported")

    # Execute Agent (Standard Path)
    agent = Agent(model, result_type=result_type)
    try:
        result = await agent.run(prompt)
        content = result.data.model_dump() if format_mode == "eagle_scaffold" else result.data
        return {"content": content, "keyUsed": asset.label}
        
    except Exception as e:
        # TACTICAL RESCUE PROTOCOL
        if format_mode == "eagle_scaffold":
            print(f"[🛡️ RESCUE] Standard strike failed. Initiating Recovery Logic...")
            # We try to find the failed generation in error details (specific to Pydantic-AI/Provider errors)
            # This is a placeholder for the aggressive string-parsing logic we developed
            return await perform_rescue_parsing(str(e), prompt, asset.label)
        raise e

async def execute_moonshot_bypass(api_key: str, model_id: str, prompt: str, temp: float, key_label: str):
    from groq import AsyncGroq
    print(f"[💥 BYPASS] Forcing JSON Mode for Moonshot/Kimi on {key_label}")
    
    schema = json.dumps(EagleScaffold.model_json_schema(), indent=2)
    messages = [
        {"role": "system", "content": f"You are a Senior React Architect. Output valid JSON matching this schema:\n{schema}\n\nReturn ONLY the JSON object. No markdown."},
        {"role": "user", "content": prompt}
    ]
    
    client = AsyncGroq(api_key=api_key)
    completion = await client.chat.completions.create(
        model=model_id,
        messages=messages,
        temperature=temp,
        response_format={"type": "json_object"}
    )
    
    raw_json = completion.choices[0].message.content
    data = json.loads(raw_json)
    validated = EagleScaffold(**data)
    return {"content": validated.model_dump(), "keyUsed": key_label}

async def perform_rescue_parsing(model_output: str, prompt: str, key_label: str):
    print(f"[🛡️ RESCUE] Attempting hierarchical reconstruction from Model Output...")
    files = []
    
    # STRATEGY 1: Nested JSON Block Search
    try:
        json_start = model_output.find('{')
        json_end = model_output.rfind('}') + 1
        if json_start != -1 and json_end != -1:
            data = json.loads(model_output[json_start:json_end])
            if 'files' in data:
                for f in data['files']:
                    files.append(EagleFile(path=f['path'], skeleton=f.get('skeleton', ''), directives=f.get('directives', '')))
                print(f"[✅ RESCUE JSON] Recovered {len(files)} files.")
    except:
        pass

    if not files:
        # STRATEGY 2: Markdown Code Blocks with Header
        print(f"[🛡️ RESCUE] Attempting Markdown block extraction...")
        # Matches: **filename: path** ... ```code```
        pattern_md = r"\*\*filename:\s*(.*?)\*\*\s*```[\w]*\n(.*?)```"
        matches_md = re.findall(pattern_md, model_output, re.DOTALL)
        for path, code in matches_md:
            files.append(EagleFile(path=path.strip(), skeleton=code.strip(), directives="Extracted from Markdown"))

    if not files:
        # STRATEGY 3: EOF Blocks (cat << 'EOF' > path)
        print(f"[🛡️ RESCUE] Attempting EOF block mining...")
        pattern_eof = r"cat << 'EOF' >\s*(\S+)\s*\n(.*?)EOF"
        matches_eof = re.findall(pattern_eof, model_output, re.DOTALL)
        for path, code in matches_eof:
            files.append(EagleFile(path=path.strip(), skeleton=code.strip(), directives="Extracted from EOF"))

    if not files:
        # STRATEGY 4: Strategy 5 - The Indentation King (Tree Parser)
        print(f"[🛡️ RESCUE] Initiating Strategy 5: Tree Reconstruction...")
        lines = model_output.split('\n')
        path_stack = []
        directives = "Follow EAGLE's architectural blueprint."
        
        # Isolated Directives Search
        dir_match = re.search(r"### DIRECTIVES(.*?)(?:###|$)", model_output, re.DOTALL)
        if dir_match:
            directives = dir_match.group(1).strip()

        for line in lines:
            clean_line = line.strip()
            if not clean_line or any(x in clean_line for x in ["```", "###", "DIRECTIVES"]): 
                continue
            
            # 1. Determine Depth (Indentation Aware)
            marker_match = re.search(r"[├└]", line)
            if marker_match:
                current_level = marker_match.start() // 3 
            else:
                current_level = (len(line) - len(line.lstrip())) // 3

            # 2. Extract Name (Strip tree symbols)
            name = re.sub(r"^[│\s├└─/]+", "", clean_line).strip("/")
            if not name: continue

            # 3. Path Management
            path_stack = path_stack[:current_level]
            
            if clean_line.endswith("/") or "." not in name:
                # Directory
                path_stack.append(name)
            else:
                # File - Total Recovery (No Blacklist)
                full_path = "/".join(path_stack + [name])
                files.append(EagleFile(
                    path=full_path, 
                    skeleton=f"// SKELETON FOR {full_path}", 
                    directives=directives
                ))
        
        if files:
            print(f"[✅ RESCUE TREE] Hierarchy reconstructed: {len(files)} files.")

    if files:
        scaffold = EagleScaffold(project="AUTORESCUE_PROJECT", files=files)
        return {"content": scaffold.model_dump(), "keyUsed": key_label}
    
    return {"content": "RESCUE_TOTAL_FAILURE", "keyUsed": key_label}

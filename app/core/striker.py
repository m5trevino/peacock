import os
from pydantic_ai import Agent, RunContext
from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.models.gemini import GeminiModel
from app.core.keys import GroqPool, GooglePool, DeepSeekPool, MistralPool
from app.config import MODEL_REGISTRY

def get_model(model_id: str):
    config = next((m for m in MODEL_REGISTRY if m['id'] == model_id), None)
    if not config:
        raise ValueError(f"Unknown Model ID: {model_id}")
    
    gateway = config['gateway']
    
    if gateway == 'groq':
        asset = GroqPool.get_next()
        # Groq is OpenAI compatible
        model = OpenAIModel(
            model_id,
            base_url='https://api.groq.com/openai/v1',
            api_key=asset.key
        )
        return model, asset.label

    if gateway == 'google':
        asset = GooglePool.get_next()
        model = GeminiModel(
            model_id,
            api_key=asset.key
        )
        return model, asset.label

    if gateway == 'deepseek':
        asset = DeepSeekPool.get_next()
        model = OpenAIModel(
            model_id,
            base_url='https://api.deepseek.com',
            api_key=asset.key
        )
        return model, asset.label

    if gateway == 'mistral':
        asset = MistralPool.get_next()
        model = OpenAIModel(
            model_id,
            base_url='https://api.mistral.ai/v1',
            api_key=asset.key
        )
        return model, asset.label

    raise ValueError(f"Gateway {gateway} not supported")

async def execute_strike(model_id: str, prompt: str, temp: float = 0.7):
    model, key_label = get_model(model_id)
    
    # We use a simple agent for the strike
    agent = Agent(model)
    
    # Pydantic AI result
    result = await agent.run(prompt)
    
    return {
        "content": result.data,
        "keyUsed": key_label
    }

import os
import random
from typing import Optional, List

class KeyAsset:
    def __init__(self, label: str, key: str):
        self.label = label
        self.key = key

class KeyPool:
    def __init__(self, env_var: str, gateway_name: str):
        self.gateway_name = gateway_name
        self.deck: List[KeyAsset] = []
        self.pointer = 0
        
        env_string = os.getenv(env_var)
        if not env_string:
            print(f"\033[33m[⚠️] NO KEYS LOADED FOR {gateway_name}\033[0m")
            return

        entries = env_string.split(',')
        for idx, entry in enumerate(entries):
            if ':' in entry:
                label, key = entry.split(':', 1)
            else:
                label = f"{gateway_name}_DEALER_{idx+1:02}"
                key = entry
            
            self.deck.append(KeyAsset(label.strip(), key.strip()))
        
        self.shuffle()

    def shuffle(self):
        if not self.deck:
            return
        print(f"\033[1;33m[🎲] {self.gateway_name} DECK SHUFFLING...\033[0m")
        random.shuffle(self.deck)
        self.pointer = 0

    def get_next(self) -> KeyAsset:
        if not self.deck:
            raise Exception(f"NO AMMUNITION FOR {self.gateway_name}")
        
        asset = self.deck[self.pointer]
        self.pointer += 1
        
        if self.pointer >= len(self.deck):
            self.shuffle()
            
        return asset

# Initialize Pools
GroqPool = KeyPool("GROQ_KEYS", "GROQ")
GooglePool = KeyPool("GOOGLE_KEYS", "GOOGLE")
DeepSeekPool = KeyPool("DEEPSEEK_KEYS", "DEEPSEEK")
MistralPool = KeyPool("MISTRAL_KEYS", "MISTRAL")

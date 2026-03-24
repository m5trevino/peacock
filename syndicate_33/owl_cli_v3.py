#!/usr/bin/env python3
"""
PEACOCK V3: OWL_CLI v3.0 (DOMAIN-CONSTRAINT-AWARE)
The Constraint-Aware Assembler with Domain Verification.
Ingests Laws + Hard Constraints + Domain Prohibitions.
Outputs manifestation ready for Hawk verification.
"""

import os
import json
import asyncio
import httpx
import sys
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

ENGINE_URL = "http://127.0.0.1:3099/v1/strike"
MODEL = "moonshotai/kimi-k2-instruct-0905"

class DomainEnforcer:
    """
    Post-generation domain verification to catch hallucinations.
    """
    
    DOMAIN_PATTERNS = {
        "FRONTEND_MOBILE": {
            "prohibited_patterns": [
                (r"import\s+Fastify\b", "Fastify import detected"),
                (r"import\s+Express\b", "Express import detected"),
                (r"createServer\s*\(", "HTTP server creation"),
                (r"\.listen\s*\(\s*\d+", "Server port binding"),
                (r"fastify\s*\(\s*\{", "Fastify instantiation"),
                (r"grpc\s*[\.\(]", "gRPC usage"),
                (r"oidc\s*[\.\(]", "OIDC usage"),
                (r"CREATE\s+TABLE", "SQL DDL"),
                (r"SELECT\s+.*\s+FROM", "SQL query"),
            ],
            "required_patterns": [
                (r"export\s+(default\s+)?class|interface|type", "TypeScript export"),
            ]
        },
        "FRONTEND_WEB": {
            "prohibited_patterns": [
                (r"import\s+Fastify\b", "Fastify import"),
                (r"createServer\s*\(", "HTTP server"),
                (r"\.listen\s*\(\s*\d+", "Port binding"),
            ],
            "required_patterns": []
        },
        "BACKEND_API": {
            "prohibited_patterns": [],
            "required_patterns": []
        }
    }
    
    def verify(self, code: str, domain: str) -> Dict:
        if domain not in self.DOMAIN_PATTERNS:
            return {"valid": True, "violations": []}
        
        config = self.DOMAIN_PATTERNS[domain]
        violations = []
        
        for pattern, description in config["prohibited_patterns"]:
            if re.search(pattern, code, re.IGNORECASE):
                violations.append({
                    "type": "PROHIBITED_PATTERN",
                    "description": description,
                    "pattern": pattern
                })
        
        return {
            "valid": len(violations) == 0,
            "violations": violations
        }

class ConstraintEngine:
    """
    HARD CONSTRAINTS: Non-negotiable architectural rules.
    These are injected into the prompt with VIOLATION = FAILURE semantics.
    """
    
    BASE_CONSTRAINTS = [
        "STATE_IMMUTABILITY: Never mutate collections being iterated. Use set() for shares, not list.pop()",
        "RACE_PREVENTION: All async state access must check existence before read. Re-queue if missing, never block",
        "NON_BLOCKING_RETRY: Use message bus re-queue for temporal ordering. Never use recursive await",
        "ATOMIC_VERIFICATION: All ledger operations must maintain checksum chain integrity",
        "GRACEFUL_FAILURE: All exceptions must be caught, logged, and converted to state transitions",
        "DOMAIN_PURITY: Never mix backend infrastructure code (servers, HTTP, databases) into frontend logic",
        "LANGUAGE_LOCK: Output MUST be valid Python 3 code ONLY. No TypeScript, JavaScript, or other languages."
    ]
    
    def __init__(self, constraint_file: Optional[str] = None, domain: str = "GENERIC"):
        self.constraints = self.BASE_CONSTRAINTS.copy()
        self.domain = domain
        
        # Add domain-specific constraints
        if domain in ["FRONTEND_MOBILE", "FRONTEND_WEB"]:
            self.constraints.extend([
                "FRONTEND_ONLY: This code runs in a browser/React Native, NOT Node.js server",
                "NO_HTTP_SERVERS: Do not create HTTP servers, routes, or listen on ports",
                "NO_BACKEND_IMPORTS: Do not import Fastify, Express, or server frameworks"
            ])
        
        if constraint_file and os.path.exists(constraint_file):
            with open(constraint_file) as f:
                patch = json.load(f)
                self.constraints.extend(patch.get("hard_constraints", []))
    
    def get_prompt_block(self) -> str:
        return "\n".join([f"CONSTRAINT {i+1}: {c}" for i, c in enumerate(self.constraints)])
    
    def get_violation_signature(self, error_type: str, error_msg: str) -> Optional[str]:
        """Map runtime failures to constraint violations."""
        signatures = {
            "IndexError": "STATE_IMMUTABILITY",
            "KeyError": "RACE_PREVENTION", 
            "RecursionError": "NON_BLOCKING_RETRY",
            "asyncio.TimeoutError": "NON_BLOCKING_RETRY",
            "ChecksumMismatch": "ATOMIC_VERIFICATION"
        }
        for err, constraint in signatures.items():
            if err in error_type or err in error_msg:
                return constraint
        return None

class OwlAssembler:
    def __init__(self, iteration: int = 0, constraint_file: Optional[str] = None, domain: str = "GENERIC"):
        self.iteration = iteration
        self.domain = domain
        self.constraints = ConstraintEngine(constraint_file, domain)
        self.domain_enforcer = DomainEnforcer()
        self.manifest_file = "manifest.json"
        self.output_file = f"manifested_core_v{iteration}.py"
        
    def load_manifest(self) -> Dict:
        if not os.path.exists(self.manifest_file):
            print(f"\033[1;31m❌ MANIFEST NOT FOUND: {self.manifest_file}\033[0m")
            sys.exit(1)
        with open(self.manifest_file) as f:
            return json.load(f)
    
    def build_prompt(self, manifest: Dict) -> str:
        laws_block = "\n".join([
            f"LAW {i+1} [{l['family']}]: {l['law']}" 
            for i, l in enumerate(manifest["logic_stack"])
        ])
        
        constraints_block = self.constraints.get_prompt_block()
        
        # Domain-specific semantic clarifications
        semantic_notes = ""
        if self.domain in ["FRONTEND_MOBILE", "FRONTEND_WEB"]:
            semantic_notes = """
### SEMANTIC CLARIFICATIONS (CRITICAL):
- "Controller" = State management logic (like Redux/Zustand), NOT HTTP request handler
- "Service" = Internal business logic module, NOT network service
- "Server" = NOT APPLICABLE - this is client-side code only
- "Hook" = React hook (useState, useEffect), NOT webhook
"""
        
        iteration_context = ""
        if self.iteration > 0:
            iteration_context = f"""
### ITERATION {self.iteration} CONTEXT:
This is a RE-MANIFESTATION. Previous attempt violated constraints.
Previous errors have been analyzed. STRICT ADHERENCE to ALL CONSTRAINTS is mandatory.
"""
        
        return f"""
### MISSION: ARCHITECTURAL MANIFESTATION (LEVEL 5)
{iteration_context}

### DOMAIN CONTEXT:
TARGET DOMAIN: {self.domain}
{semantic_notes}

### THE INTENT:
"{manifest['intent']}"

### THE SYNDICATE LAWS (GROUND TRUTH - NON-NEGOTIABLE):
{laws_block}

### HARD CONSTRAINTS (VIOLATION = FAILURE):
{constraints_block}

### MANDATORY IMPLEMENTATION RULES:
1. YOU MUST satisfy EVERY LAW above with working code.
2. YOU MUST satisfy EVERY CONSTRAINT above without exception.
3. **LANGUAGE: Output MUST be Python 3 code ONLY. No TypeScript, JavaScript, Go, or other languages.**
4. Focus on INTEGRATION GLUE between families (e.g., how ledger events trigger saga transitions).
5. Use async/await throughout. No blocking I/O.
6. Output ONLY raw code. No markdown, no conversation, no explanations.
7. DOMAIN VERIFICATION: Before finishing, verify no prohibited technologies are present.

### VERIFICATION TARGET:
The code must pass these automated checks:
- No IndexError, KeyError, or RecursionError under any execution path
- Checksum chain integrity maintained across all ledger operations
- State transitions are atomic and verifiable
- Message bus handles out-of-order events via re-queue, not blocking
- {"No backend server code (Fastify, Express, HTTP servers) in frontend domain" if self.domain in ["FRONTEND_MOBILE", "FRONTEND_WEB"] else "Architecture appropriate for domain"}

BEGIN MANIFESTATION.
"""
    
    async def generate(self) -> Optional[str]:
        manifest = self.load_manifest()
        prompt = self.build_prompt(manifest)
        
        print(f"\033[1;94m🦉 Owl v3.0 Iteration {self.iteration} Manifesting...\033[0m")
        print(f"\033[1;37m   Domain: {self.domain}\033[0m")
        print(f"\033[1;37m   Constraints: {len(self.constraints.constraints)} hard rules\033[0m")
        print(f"\033[1;37m   Laws: {len(manifest['logic_stack'])} syndicate patterns\033[0m")
        
        payload = {
            "modelId": MODEL,
            "prompt": prompt,
            "temp": 0.0
        }
        
        start = datetime.now()
        async with httpx.AsyncClient(timeout=600.0, trust_env=False) as client:
            resp = await client.post(ENGINE_URL, json=payload)
            duration = (datetime.now() - start).total_seconds()
            
            if resp.status_code != 200:
                print(f"\033[1;31m❌ Manifestation Failed: HTTP {resp.status_code} ({resp.text})\033[0m")
                return None
            
            data = resp.json()
            code = data.get('content', '')
            
            # Clean markdown
            if "```python" in code:
                code = code.split("```python")[1].split("```")[0].strip()
            elif "```typescript" in code:
                code = code.split("```typescript")[1].split("```")[0].strip()
            elif "```" in code:
                code = code.split("```")[1].split("```")[0].strip()
            
            # DOMAIN VERIFICATION (CRITICAL)
            print(f"\033[1;95m🔍 Running Domain Verification...\033[0m")
            verification = self.domain_enforcer.verify(code, self.domain)
            
            if not verification["valid"]:
                print(f"\033[1;31m❌ DOMAIN VIOLATION DETECTED:\033[0m")
                for v in verification["violations"]:
                    print(f"   - {v['description']}")
                print(f"\033[1;33m⚠️  Code written to {self.output_file} but marked as FAILED\033[0m")
                # Still write it for analysis, but indicate failure
                with open(self.output_file, "w") as f:
                    f.write(f"// DOMAIN VERIFICATION FAILED\n// VIOLATIONS: {json.dumps(verification['violations'])}\n\n" + code)
                return None
            
            print(f"\033[1;92m✅ Domain Verification Passed\033[0m")
            
            # Write output
            with open(self.output_file, "w") as f:
                f.write(code)
            
            print(f"\033[1;92m✅ Manifested: {self.output_file} ({duration:.1f}s)\033[0m")
            return self.output_file

async def main():
    iteration = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    constraint_file = sys.argv[2] if len(sys.argv) > 2 else None
    domain = sys.argv[3] if len(sys.argv) > 3 else "GENERIC"
    
    owl = OwlAssembler(iteration, constraint_file, domain)
    result = await owl.generate()
    
    if result:
        print(f"\033[1;37m   Output: {os.path.abspath(result)}\033[0m")
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
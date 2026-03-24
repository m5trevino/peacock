#!/usr/bin/env python3
"""
💀 PEACOCK UNIFIED ORCHESTRATOR v4.0 💀
The Ultimate Command Center for Code Manifestation
Peacock → Hawk → Owl → Victory
"""

import os
import sys
import json
import asyncio
import subprocess
import tempfile
import signal
import traceback
import re
import httpx
import chromadb
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from chromadb.utils import embedding_functions
from dataclasses import dataclass, asdict

# ============================================================
# COLOR THEMES
# ============================================================

class Colors:
    """Each phase has its own identity"""
    # PEACOCK Theme - Vibrant, Showy, Majestic
    PEACOCK_PRIMARY = "\033[1;96m"      # Bright Cyan
    PEACOCK_SECONDARY = "\033[1;95m"   # Bright Magenta
    PEACOCK_ACCENT = "\033[1;93m"      # Bright Yellow
    PEACOCK_DIM = "\033[0;36m"         # Dim Cyan
    
    # HAWK Theme - Aggressive, Hunting, Danger
    HAWK_PRIMARY = "\033[1;91m"        # Bright Red
    HAWK_SECONDARY = "\033[1;93m"      # Bright Yellow
    HAWK_ACCENT = "\033[1;31m"         # Dark Red
    HAWK_DIM = "\033[0;31m"            # Dim Red
    
    # OWL Theme - Wise, Mysterious, Night
    OWL_PRIMARY = "\033[1;94m"         # Bright Blue
    OWL_SECONDARY = "\033[1;95m"       # Bright Purple
    OWL_ACCENT = "\033[1;96m"          # Bright Cyan
    OWL_DIM = "\033[0;34m"             # Dim Blue
    
    # Universal
    SUCCESS = "\033[1;92m"             # Bright Green
    WARNING = "\033[1;93m"             # Bright Yellow
    ERROR = "\033[1;91m"               # Bright Red
    INFO = "\033[1;97m"                # White
    DIM = "\033[0;90m"                 # Gray
    RESET = "\033[0m"                  # Reset

# ============================================================
# ASCII ART
# ============================================================

ASCII_PEACOCK = f"""
{Colors.PEACOCK_PRIMARY}██████╗ ███████╗ █████╗  ██████╗ ██████╗  ██████╗██╗  ██╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗██╔════╝██║ ██╔╝
██████╔╝█████╗  ███████║██║     ██║   ██║██║     █████╔╝ 
██╔═══╝ ██╔══╝  ██╔══██║██║     ██║   ██║██║     ██╔═██╗ 
██║     ███████╗██║  ██║╚██████╗╚██████╔╝╚██████╗██║  ██╗
╚═╝     ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝{Colors.RESET}
{Colors.PEACOCK_SECONDARY}              COMMANDER v4.0 - UNIFIED FACTORY{Colors.RESET}
{Colors.PEACOCK_DIM}========================================{Colors.RESET}
"""

ASCII_HAWK = f"""
{Colors.HAWK_PRIMARY}                                    G:      
 .    .                                     E#,    :
 Di   Dt              ..           ;        E#t  .GE
 E#i  E#i            ;W,         .DL        E#t j#K;
 E#t  E#t           j##, f.     :K#L     LWLE#GK#f  
 E#t  E#t          G###, EW:   ;W##L   .E#f E##D.   
 E########f.     :E####, E#t  t#KE#L  ,W#;  E##Wi   
 E#j..K#j...    ;W#DG##, E#t f#D.L#L t#K:   E#jL#D: 
 E#t  E#t      j###DW##, E#jG#f  L#LL#G     E#t ,K#j
 E#t  E#t     G##i,,G##, E###;   L###j      E#t   jD
 f#t  f#t   :K#K:   L##, E#K:    L#W;       j#t     
  ii   ii  ;##D.    L##, EG      LE.         ,;     
           ,,,      .,,  ;       ;@                 {Colors.RESET}
{Colors.HAWK_SECONDARY}           TACTICAL TORTURE TESTER v3.0{Colors.RESET}
{Colors.HAWK_DIM}========================================{Colors.RESET}
"""

ASCII_OWL = f"""
{Colors.OWL_PRIMARY}######## ######## #####  # 
######## ######## ####  ## 
###   ## #  ###   ####  ## 
##  #  #    # #   ###  ### 
#  ##  # #        ###  ### 
#  #  ## ##     # ###  ### 
##   ### ##  #  # ####  ## 
######## ######## ######## {Colors.RESET}
{Colors.OWL_SECONDARY}      WISE CONSTRAINT ASSEMBLER v3.0{Colors.RESET}
{Colors.OWL_DIM}========================================{Colors.RESET}
"""

# ============================================================
# ASCII BOXES
# ============================================================

def box_text(text: str, width: int = 70, color: str = Colors.INFO) -> str:
    """Create a fancy ASCII box around text"""
    lines = text.split('\n')
    max_len = min(max(len(l) for l in lines), width - 4)
    
    top = f"{color}╔{'═' * (max_len + 2)}╗{Colors.RESET}"
    bottom = f"{color}╚{'═' * (max_len + 2)}╝{Colors.RESET}"
    
    middle = []
    for line in lines:
        padded = line.ljust(max_len)
        middle.append(f"{color}║{Colors.RESET} {padded} {color}║{Colors.RESET}")
    
    return '\n'.join([top] + middle + [bottom])

def section_divider(char: str = '═', color: str = Colors.DIM) -> str:
    """Create a visual section divider"""
    return f"{color}{char * 80}{Colors.RESET}"

def phase_header(title: str, color: str) -> str:
    """Create a phase header"""
    return f"\n{color}▓▓▓ {title.upper()} {'▓' * (70 - len(title))}{Colors.RESET}\n"

# ============================================================
# SPINNER & ANIMATION
# ============================================================

class Spinner:
    def __init__(self, message: str, color: str = Colors.INFO):
        self.message = message
        self.color = color
        self.running = False
        self.frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.idx = 0
        
    async def spin(self):
        self.running = True
        while self.running:
            frame = self.frames[self.idx % len(self.frames)]
            sys.stdout.write(f"\r{self.color}{frame}{Colors.RESET} {self.message}")
            sys.stdout.flush()
            self.idx += 1
            await asyncio.sleep(0.08)
    
    def stop(self, final_message: str = ""):
        self.running = False
        sys.stdout.write(f"\r{' ' * (len(self.message) + 10)}\r")
        if final_message:
            print(final_message)
        sys.stdout.flush()

# ============================================================
# PEACOCK COMMANDER (Unified)
# ============================================================

ENGINE_URL = "http://127.0.0.1:3099/v1/strike"
VAULT_PATH = os.path.abspath("../peacock_logic_vault")
NEXUS_MODEL = "moonshotai/kimi-k2-instruct-0905"
OWL_MODEL = "moonshotai/kimi-k2-instruct-0905"

class DomainClassifier:
    DOMAINS = {
        "FRONTEND_MOBILE": {
            "keywords": ["react native", "mobile", "ios", "android", "expo"],
            "prohibited": ["fastify", "express", "server", "http", "grpc"],
        },
        "BACKEND_API": {
            "keywords": ["api", "server", "backend", "rest", "graphql"],
            "prohibited": [],
        },
    }
    
    def classify(self, intent: str) -> dict:
        intent_lower = intent.lower()
        if any(k in intent_lower for k in ["react native", "mobile"]):
            return {"domain": "FRONTEND_MOBILE", "confidence": 0.9}
        elif any(k in intent_lower for k in ["server", "api", "backend"]):
            return {"domain": "BACKEND_API", "confidence": 0.9}
        return {"domain": "GENERIC", "confidence": 0.5}

class UnifiedOrchestrator:
    def __init__(self):
        self.temp_dir = tempfile.mkdtemp(prefix="peacock_")
        self.generated_file = None
        self.intent = None
        self.domain_info = None
        
    def print_banner(self):
        """Show the PEACOCK entrance"""
        print(ASCII_PEACOCK)
        print(section_divider('═', Colors.PEACOCK_DIM))
        print(f"{Colors.PEACOCK_PRIMARY}🦚 Status:{Colors.RESET} {Colors.INFO}Targeting {OWL_MODEL}{Colors.RESET}")
        print(f"{Colors.PEACOCK_PRIMARY}🦚 Window:{Colors.RESET} {Colors.INFO}262k Token Context Active{Colors.RESET}")
        print(f"{Colors.PEACOCK_PRIMARY}🦚 Mode:{Colors.RESET} {Colors.INFO}Python-Only Lock Engaged{Colors.RESET}")
        print(section_divider('═', Colors.PEACOCK_DIM))
        
    async def get_intent(self) -> str:
        """Get user intent with style"""
        print(f"\n{Colors.PEACOCK_SECONDARY}📥 MISSION INTENT MODE (Multi-line Active){Colors.RESET}")
        print(f"{Colors.DIM}Paste your intent below. Press Ctrl+D (Unix) or Ctrl+Z (Win) when finished.{Colors.RESET}")
        print(section_divider('-', Colors.PEACOCK_DIM))
        
        try:
            intent = sys.stdin.read().strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{Colors.ERROR}🛑 Mission Aborted{Colors.RESET}")
            sys.exit(0)
            
        if not intent:
            print(f"{Colors.ERROR}❌ Error: Intent cannot be empty{Colors.RESET}")
            sys.exit(1)
            
        print(section_divider('-', Colors.PEACOCK_DIM))
        return intent
    
    async def execute_strike(self, model_id: str, prompt: str, phase_color: str) -> Optional[str]:
        """Fire kinetic strike at AI engine"""
        payload = {
            "modelId": model_id,
            "prompt": prompt,
            "temp": 0.0
        }
        
        spinner = Spinner("Launching strike at AI engine...", phase_color)
        spin_task = asyncio.create_task(spinner.spin())
        
        try:
            async with httpx.AsyncClient(timeout=500.0, trust_env=False) as client:
                resp = await client.post(ENGINE_URL, json=payload)
                spinner.stop()
                
                if resp.status_code == 200:
                    data = resp.json()
                    elapsed = "~30s"  # We don't track exact time in this simplified version
                    print(f"{phase_color}✓{Colors.RESET} Strike hit in {elapsed}")
                    return data.get('content')
                else:
                    print(f"{Colors.ERROR}❌ ENGINE REJECTED ({resp.status_code}): {resp.text}{Colors.RESET}")
                    return None
        except Exception as e:
            spinner.stop()
            print(f"{Colors.ERROR}❌ CONNECTION FAILURE: {e}{Colors.RESET}")
            return None
    
    async def phase_peacock(self, intent: str) -> Optional[str]:
        """Phase 1: Peacock Generation"""
        print(phase_header("Phase 1: Peacock Manifestation", Colors.PEACOCK_PRIMARY))
        
        # Domain classification
        classifier = DomainClassifier()
        self.domain_info = classifier.classify(intent)
        
        print(f"{Colors.PEACOCK_SECONDARY}🎯 Domain Classification:{Colors.RESET}")
        print(box_text(
            f"Domain: {self.domain_info['domain']}\n"
            f"Confidence: {self.domain_info['confidence']:.0%}\n"
            f"Language: Python 3 (LOCKED)",
            color=Colors.PEACOCK_DIM
        ))
        
        # Build prompt (simplified for Python-only)
        prompt = f"""
### MISSION: ARCHITECTURAL MANIFESTATION (LEVEL 5)

### DOMAIN CONTEXT:
TARGET DOMAIN: {self.domain_info['domain']}
RUNTIME: Python 3 (NOT TypeScript, NOT JavaScript)

### THE INTENT:
"{intent}"

### ABSOLUTE PROHIBITIONS (VIOLATION = CATASTROPHIC FAILURE):
- LANGUAGE: Output MUST be Python 3 code ONLY
- NO TypeScript, JavaScript, Go, or other languages
- NO Fastify, Express, or HTTP servers for FRONTEND domains

### MANDATORY REQUIREMENTS:
1. Output MUST be valid, executable Python 3
2. Use async/await throughout
3. Output ONLY raw code. No markdown, no explanations
4. All functions must be pure and testable

BEGIN MANIFESTATION.
"""
        
        # Execute strike
        print(f"\n{Colors.PEACOCK_SECONDARY}⚡ Firing {OWL_MODEL}...{Colors.RESET}")
        code = await self.execute_strike(OWL_MODEL, prompt, Colors.PEACOCK_PRIMARY)
        
        if not code:
            return None
            
        # Clean markdown
        if "```python" in code:
            code = code.split("```python")[1].split("```")[0].strip()
        elif "```" in code:
            code = code.split("```")[1].split("```")[0].strip()
        
        # Always save as .py
        filename = f"manifested_whip_{datetime.now().strftime('%H%M%S')}.py"
        with open(filename, "w") as f:
            f.write(code)
        
        self.generated_file = filename
        
        print(f"\n{Colors.SUCCESS}🎯 WHIP DELIVERED:{Colors.RESET}")
        print(box_text(
            f"Filename: {filename}\n"
            f"Size: {len(code)} bytes\n"
            f"Lines: {len(code.splitlines())}",
            color=Colors.SUCCESS
        ))
        
        # Preview
        print(f"\n{Colors.PEACOCK_DIM}📄 Preview (first 10 lines):{Colors.RESET}")
        preview_lines = code.split('\n')[:10]
        for i, line in enumerate(preview_lines, 1):
            print(f"{Colors.DIM}{i:3} │{Colors.RESET} {line[:70]}")
        if len(code.split('\n')) > 10:
            print(f"{Colors.DIM}    │ ... ({len(code.splitlines()) - 10} more lines){Colors.RESET}")
        
        return filename
    
    async def phase_hawk(self, target_file: str) -> Tuple[bool, Dict]:
        """Phase 2: Hawk Torture Test"""
        print(ASCII_HAWK)
        print(phase_header("Phase 2: Hawk Torture Test", Colors.HAWK_PRIMARY))
        
        print(f"{Colors.HAWK_SECONDARY}🦅 Target: {target_file}{Colors.RESET}")
        print(f"{Colors.HAWK_SECONDARY}🦅 Domain: {self.domain_info['domain']}{Colors.RESET}")
        print(f"{Colors.HAWK_SECONDARY}🦅 EVD Timeout: 30s{Colors.RESET}")
        print()
        
        # Run Hawk
        spinner = Spinner("Executing in isolated EVD...", Colors.HAWK_PRIMARY)
        spin_task = asyncio.create_task(spinner.spin())
        
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "hawk_cli_v3.py", target_file, "1", self.domain_info['domain'],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            spinner.stop()
            
            output = stdout.decode()
            
            # Parse results
            passed = "PASS" in output
            
            # Check for audit file
            audit_file = "hawk_audit_v1.json"
            audit_data = {}
            if os.path.exists(audit_file):
                with open(audit_file) as f:
                    audit_data = json.load(f)
            
            # Display results
            print(f"{Colors.HAWK_SECONDARY}📊 Execution Results:{Colors.RESET}")
            
            status_color = Colors.SUCCESS if passed else Colors.ERROR
            status_icon = "✅" if passed else "❌"
            status_text = "PASSED" if passed else "FAILED"
            
            result_box = (
                f"Exit Code: {audit_data.get('exit_code', 'N/A')}\n"
                f"Integrity Score: {audit_data.get('integrity_score', 0):.2f}/1.0\n"
                f"Execution Time: {audit_data.get('execution_time_ms', 0):.1f}ms\n"
                f"Status: {status_text}"
            )
            print(box_text(result_box, color=status_color))
            
            # Show violations if any
            violations = audit_data.get('domain_violations', [])
            if violations:
                print(f"\n{Colors.HAWK_ACCENT}⚠️  Domain Violations:{Colors.RESET}")
                for v in violations[:3]:
                    print(f"   {Colors.HAWK_ACCENT}•{Colors.RESET} Line {v.get('line_number', '?')}: {v.get('description', 'Unknown')}")
            
            signatures = audit_data.get('signatures', [])
            if signatures:
                print(f"\n{Colors.HAWK_ACCENT}💀 Failure Signatures:{Colors.RESET}")
                for sig in signatures[:3]:
                    print(f"   {Colors.HAWK_ACCENT}•{Colors.RESET} {sig.get('severity', 'UNKNOWN')}: {sig.get('error_type', 'Unknown')}")
            
            if passed:
                print(f"\n{Colors.SUCCESS}{'🎉' * 5} TORTURE TEST SURVIVED! {'🎉' * 5}{Colors.RESET}")
            else:
                print(f"\n{Colors.ERROR}💀 TARGET ELIMINATED - FAILURES DETECTED 💀{Colors.RESET}")
            
            return passed, audit_data
            
        except Exception as e:
            spinner.stop()
            print(f"{Colors.ERROR}❌ Hawk execution failed: {e}{Colors.RESET}")
            return False, {}
    
    async def phase_owl_loop(self, target_file: str) -> bool:
        """Phase 3: Owl + Mercenary Loop Auto-Fix"""
        print(ASCII_OWL)
        print(phase_header("Phase 3: Owl Auto-Fix Loop", Colors.OWL_PRIMARY))
        
        print(f"{Colors.OWL_SECONDARY}🦉 Initiating constraint-driven re-manifestation...{Colors.RESET}")
        print(f"{Colors.OWL_SECONDARY}🦉 Max Iterations: 5{Colors.RESET}")
        print()
        
        # Run Mercenary Loop
        spinner = Spinner("Running Owl → Hawk iterations...", Colors.OWL_PRIMARY)
        spin_task = asyncio.create_task(spinner.spin())
        
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "mercenary_loop_v2.py", self.domain_info['domain'],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            spinner.stop()
            
            output = stdout.decode()
            
            # Check results
            if "SUCCESS" in output or "🎉" in output:
                print(f"\n{Colors.SUCCESS}✅ AUTO-FIX SUCCESSFUL!{Colors.RESET}")
                # Find the successful file
                for i in range(5, 0, -1):
                    test_file = f"manifested_core_v{i}.py"
                    if os.path.exists(test_file):
                        self.generated_file = test_file
                        break
                return True
            else:
                print(f"\n{Colors.ERROR}❌ AUTO-FIX FAILED - Max iterations reached{Colors.RESET}")
                return False
                
        except Exception as e:
            spinner.stop()
            print(f"{Colors.ERROR}❌ Owl loop failed: {e}{Colors.RESET}")
            return False
    
    async def ask_yes_no(self, question: str, color: str) -> bool:
        """Ask user yes/no with style"""
        print()
        print(f"{color}┌─ DECISION REQUIRED ─{'─' * 60}┐{Colors.RESET}")
        print(f"{color}│{Colors.RESET} {question} {color}[Y/n]:{Colors.RESET}", end=" ")
        
        try:
            response = input().strip().lower()
            return response in ['', 'y', 'yes', 'yeah', 'yep']
        except (EOFError, KeyboardInterrupt):
            print()
            return False
    
    async def run(self):
        """Main orchestration flow"""
        self.print_banner()
        
        # Phase 1: Get intent and generate
        intent = await self.get_intent()
        self.intent = intent
        
        print(f"\n{Colors.PEACOCK_SECONDARY}🚀 Initiating Peacock Manifestation...{Colors.RESET}")
        result = await self.phase_peacock(intent)
        
        if not result:
            print(f"\n{Colors.ERROR}💀 MANIFESTATION FAILED{Colors.RESET}")
            return
        
        # Decision point 1: Run Hawk?
        run_hawk = await self.ask_yes_no(
            "Run HAWK torture test on generated code?",
            Colors.HAWK_PRIMARY
        )
        
        if not run_hawk:
            print(f"\n{Colors.WARNING}⚠️ Skipping Hawk. Code saved to: {self.generated_file}{Colors.RESET}")
            return
        
        # Phase 2: Hawk
        passed, audit = await self.phase_hawk(self.generated_file)
        
        if passed:
            print(f"\n{box_text('🎉 MISSION COMPLETE - CODE IS BATTLE-TESTED 🎉', color=Colors.SUCCESS)}")
            print(f"\n{Colors.INFO}📁 Final artifact: {self.generated_file}{Colors.RESET}")
            return
        
        # Decision point 2: Run Owl loop?
        print()
        run_owl = await self.ask_yes_no(
            "Run OWL auto-fix loop to correct violations?",
            Colors.OWL_PRIMARY
        )
        
        if not run_owl:
            print(f"\n{Colors.WARNING}⚠️ Skipping Owl. Fix manually or retry.{Colors.RESET}")
            print(f"{Colors.INFO}📁 Code saved to: {self.generated_file}{Colors.RESET}")
            return
        
        # Phase 3: Owl Loop
        fixed = await self.phase_owl_loop(self.generated_file)
        
        if fixed:
            print(f"\n{box_text('🎉 MISSION COMPLETE - AUTO-FIX SUCCESSFUL 🎉', color=Colors.SUCCESS)}")
            print(f"\n{Colors.INFO}📁 Final artifact: {self.generated_file}{Colors.RESET}")
        else:
            print(f"\n{box_text('💀 MISSION FAILED - MANUAL INTERVENTION REQUIRED 💀', color=Colors.ERROR)}")
            print(f"\n{Colors.WARNING}Try adjusting your intent or running with different parameters.{Colors.RESET}")

# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    orchestrator = UnifiedOrchestrator()
    asyncio.run(orchestrator.run())

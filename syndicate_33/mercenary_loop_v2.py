import os
import sys
import json
import asyncio
import subprocess
from datetime import datetime

class MercenaryLoop:
    MAX_ITERATIONS = 5
    CONSTRAINT_FILE = "constraint_patch.json"
    
    def __init__(self, max_iter: int = 5, domain: str = "GENERIC"):
        self.max_iter = max_iter
        self.domain = domain
        self.iteration = 0
        self.history = []
        
    def log(self, msg: str, level: str = "INFO"):
        colors = {"INFO": "\033[1;37m", "SUCCESS": "\033[1;92m", "WARN": "\033[1;33m", "ERROR": "\033[1;31m"}
        print(f"{colors.get(level, '')}[LOOP:{self.iteration}] {msg}\033[0m")
    
    async def run_owl(self) -> str:
        cmd = [
            sys.executable, 
            "owl_cli_v3.py", 
            str(self.iteration), 
            self.CONSTRAINT_FILE if os.path.exists(self.CONSTRAINT_FILE) else "",
            self.domain
        ]
        
        proc = await asyncio.create_subprocess_exec(
            *cmd, 
            stdout=asyncio.subprocess.PIPE, 
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        if proc.returncode != 0:
            error_output = stderr.decode() or stdout.decode()
            self.log(f"Owl failed: {error_output[:300]}", "ERROR")
            return None
        
        target = f"manifested_core_v{self.iteration}.py"
        return target if os.path.exists(target) else None

    async def run_hawk(self, target: str) -> bool:
        cmd = [
            sys.executable,
            "hawk_cli_v3.py",
            target,
            str(self.iteration),
            self.domain
        ]
        
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        output = stdout.decode()
        if "PASS" in output:
            self.log("Hawk verification PASSED", "SUCCESS")
            return True
        else:
            self.log("Hawk verification FAILED", "WARN")
            # Check for patch
            audit_file = f"hawk_audit_v{self.iteration}.json"
            if os.path.exists(audit_file):
                with open(audit_file) as f:
                    audit = json.load(f)
                    if audit.get("constraint_patch"):
                        with open(self.CONSTRAINT_FILE, "w") as f:
                            json.dump(audit["constraint_patch"], f, indent=2)
                        self.log(f"Constraint patch written to {self.CONSTRAINT_FILE}", "INFO")
            return False

    async def iterate(self):
        self.iteration += 1
        self.log(f"🚀 ITERATION {self.iteration} STARTING (Domain: {self.domain})", "INFO")
        
        target = await self.run_owl()
        if not target: 
            return False

        # Run Hawk verification
        passed = await self.run_hawk(target)
        
        if passed:
            self.log(f"🎉 SUCCESS: {target} verified and ready.", "SUCCESS")
            return True
        else:
            self.log("⚠️  Issues detected. Constraint patch applied for next iteration.", "WARN")
            return False

    async def run(self):
        while self.iteration < self.max_iter:
            success = await self.iterate()
            if success: 
                break
            await asyncio.sleep(2)
        
        if self.iteration >= self.max_iter and not success:
            self.log("💀 MAX ITERATIONS REACHED. Manual intervention required.", "ERROR")

if __name__ == "__main__":
    # Auto-detect domain from manifest if available
    domain = "GENERIC"
    if os.path.exists("manifest.json"):
        try:
            with open("manifest.json") as f:
                manifest = json.load(f)
                # Try to infer domain from intent
                intent = manifest.get("intent", "").lower()
                if any(x in intent for x in ["react native", "mobile"]):
                    domain = "FRONTEND_MOBILE"
                elif any(x in intent for x in ["react", "frontend", "web"]):
                    domain = "FRONTEND_WEB"
                elif any(x in intent for x in ["server", "api", "backend"]):
                    domain = "BACKEND_API"
        except:
            pass
    
    if len(sys.argv) > 1:
        domain = sys.argv[1]
    
    asyncio.run(MercenaryLoop(domain=domain).run())
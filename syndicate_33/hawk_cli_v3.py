#!/usr/bin/env python3
"""
PEACOCK V3: HAWK_CLI v3.0 (DOMAIN-AWARE EVD TORTURE TESTER)
The Enterprise Virtual Device with Domain Consistency Checks.
Executes code in isolated environment, captures failure signatures,
verifies domain purity, outputs structured audit.
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
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict

@dataclass
class FailureSignature:
    error_type: str
    error_message: str
    violated_constraint: Optional[str]
    line_number: Optional[int]
    context: str
    severity: str  # "FATAL", "WARNING", "INTEGRITY"

@dataclass
class DomainViolation:
    pattern: str
    description: str
    line_number: Optional[int]

@dataclass
class HawkAudit:
    iteration: int
    target_file: str
    domain: str
    execution_time_ms: float
    exit_code: int
    stdout: str
    stderr: str
    signatures: List[FailureSignature]
    domain_violations: List[DomainViolation]
    integrity_score: float  # 0.0 - 1.0
    passed: bool
    constraint_patch: Optional[Dict]

class DomainVerifier:
    """
    Static analysis for domain consistency.
    Catches hallucinations that slipped through Owl.
    """
    
    PATTERNS = {
        "FRONTEND_MOBILE": [
            (r"import\s+Fastify\b", "Fastify server framework import"),
            (r"import\s+Express\b", "Express server framework import"),
            (r"from\s+['\"]fastify['\"]", "Fastify module import"),
            (r"from\s+['\"]express['\"]", "Express module import"),
            (r"createServer\s*\(", "HTTP server creation"),
            (r"\.listen\s*\(\s*3000|\.listen\s*\(\s*8080|\.listen\s*\(\s*5000", "Common server port binding"),
            (r"fastify\s*\(\s*\{", "Fastify instantiation"),
            (r"grpc\s*[\.\(]", "gRPC usage"),
            (r"@grpc", "gRPC decorator"),
            (r"oidc\s*[\.\(]", "OIDC usage"),
            (r"mTLS", "mTLS infrastructure"),
            (r"CREATE\s+TABLE\s+", "SQL DDL statement"),
            (r"INSERT\s+INTO\s+", "SQL insert statement"),
            (r"SELECT\s+.*\s+FROM\s+", "SQL select statement"),
            (r"require\s*\(\s*['\"]http['\"]\s*\)", "Node.js HTTP module"),
            (r"require\s*\(\s*['\"]https['\"]\s*\)", "Node.js HTTPS module"),
            (r"Kubernetes|k8s|istio|traefik|vault|terraform", "Infrastructure reference"),
        ],
        "FRONTEND_WEB": [
            (r"import\s+Fastify\b", "Fastify import"),
            (r"createServer\s*\(", "HTTP server"),
            (r"\.listen\s*\(\s*\d+", "Port binding"),
        ],
        "BACKEND_API": [
            # Backend allows these, but check for frontend anti-patterns if any
        ]
    }
    
    def __init__(self, domain: str = "GENERIC"):
        self.domain = domain
    
    def analyze(self, code: str) -> List[DomainViolation]:
        if self.domain not in self.PATTERNS:
            return []
        
        violations = []
        patterns = self.PATTERNS[self.domain]
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern, description in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    violations.append(DomainViolation(
                        pattern=pattern,
                        description=description,
                        line_number=line_num
                    ))
        
        return violations

class EVDController:
    """
    Enterprise Virtual Device: Isolated execution environment.
    Sandboxed, time-limited, with full failure capture.
    """
    
    def __init__(self, timeout_seconds: int = 30):
        self.timeout = timeout_seconds
        self.temp_dir = tempfile.mkdtemp(prefix="evd_")
        
    async def execute(self, target_file: str) -> Tuple[int, str, str, float]:
        """Execute code in EVD, return (exit_code, stdout, stderr, duration_ms)."""
        if not os.path.exists(target_file):
            return 1, "", f"File not found: {target_file}", 0.0
        
        # Create isolated copy
        evd_file = os.path.join(self.temp_dir, "target.py")
        with open(target_file) as f:
            code = f.read()
        with open(evd_file, "w") as f:
            f.write(code)
        
        start = datetime.now()
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, evd_file,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.temp_dir,
                limit=1024*1024  # 1MB output limit
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), 
                    timeout=self.timeout
                )
                duration = (datetime.now() - start).total_seconds() * 1000
                
                return (
                    proc.returncode or 0,
                    stdout.decode('utf-8', errors='replace'),
                    stderr.decode('utf-8', errors='replace'),
                    duration
                )
            except asyncio.TimeoutError:
                proc.kill()
                return 1, "", f"TIMEOUT: Execution exceeded {self.timeout}s", self.timeout * 1000
                
        except Exception as e:
            duration = (datetime.now() - start).total_seconds() * 1000
            return 1, "", f"EVD_ERROR: {str(e)}\n{traceback.format_exc()}", duration

class FailureAnalyzer:
    """
    Neural Signature Detection: Maps runtime failures to constraint violations.
    """
    
    SIGNATURE_PATTERNS = [
        # (regex pattern, error_type, violated_constraint, severity)
        (r"IndexError.*list index out of range", "IndexError", "STATE_IMMUTABILITY", "FATAL"),
        (r"IndexError.*pop from empty list", "IndexError", "STATE_IMMUTABILITY", "FATAL"),
        (r"KeyError.*'CRATE_", "KeyError", "RACE_PREVENTION", "FATAL"),
        (r"KeyError.*'.*'", "KeyError", "RACE_PREVENTION", "WARNING"),
        (r"RecursionError.*maximum recursion depth", "RecursionError", "NON_BLOCKING_RETRY", "FATAL"),
        (r"asyncio.TimeoutError", "TimeoutError", "NON_BLOCKING_RETRY", "WARNING"),
        (r"RuntimeWarning.*coroutine.*was never awaited", "CoroutineWarning", "NON_BLOCKING_RETRY", "WARNING"),
        (r"Task exception was never retrieved", "UnhandledTaskError", "GRACEFUL_FAILURE", "WARNING"),
        (r"checksum.*mismatch|chain.*broken|integrity.*fail", "ChecksumError", "ATOMIC_VERIFICATION", "FATAL"),
        (r"Fastify|Express|createServer|\.listen", "DomainHallucination", "DOMAIN_PURITY", "FATAL"),
    ]
    
    def analyze(self, stderr: str, stdout: str) -> List[FailureSignature]:
        signatures = []
        combined = stderr + "\n" + stdout
        
        for pattern, err_type, constraint, severity in self.SIGNATURE_PATTERNS:
            matches = re.finditer(pattern, combined, re.IGNORECASE)
            for match in matches:
                # Extract line number if available
                line_no = None
                line_pattern = rf"File.*line (\d+).*"
                line_match = re.search(line_pattern, combined[max(0, match.start()-500):match.start()])
                if line_match:
                    line_no = int(line_match.group(1))
                
                # Extract context (surrounding lines)
                context_start = max(0, match.start() - 200)
                context_end = min(len(combined), match.end() + 200)
                context = combined[context_start:context_end].replace('\n', ' ')
                
                signatures.append(FailureSignature(
                    error_type=err_type,
                    error_message=match.group(0),
                    violated_constraint=constraint,
                    line_number=line_no,
                    context=context[:300],
                    severity=severity
                ))
        
        # Deduplicate by error message
        seen = set()
        unique = []
        for sig in signatures:
            if sig.error_message not in seen:
                seen.add(sig.error_message)
                unique.append(sig)
        
        return unique
    
    def generate_patch(self, signatures: List[FailureSignature], domain_violations: List[DomainViolation]) -> Optional[Dict]:
        """Generate constraint patch from detected violations."""
        if not signatures and not domain_violations:
            return None
        
        fatal_violations = [s for s in signatures if s.severity == "FATAL"]
        
        # Build specific constraints from violations
        new_constraints = []
        
        for sig in fatal_violations:
            if sig.violated_constraint == "STATE_IMMUTABILITY":
                new_constraints.append(
                    "CRITICAL_FIX: Use set() for share collection. "
                    "Never use list.pop() or del while iterating. "
                    "Copy-on-read if mutation required."
                )
            elif sig.violated_constraint == "RACE_PREVENTION":
                new_constraints.append(
                    "CRITICAL_FIX: Check state existence with .get() before access. "
                    "If missing, re-queue message to bus with delay. "
                    "Never raise KeyError in async context."
                )
            elif sig.violated_constraint == "NON_BLOCKING_RETRY":
                new_constraints.append(
                    "CRITICAL_FIX: Replace recursive await with message re-queue. "
                    "Use asyncio.create_task for delayed retry. "
                    "Never block the event loop waiting for state."
                )
            elif sig.violated_constraint == "DOMAIN_PURITY":
                new_constraints.append(
                    "CRITICAL_FIX: This is FRONTEND code. "
                    "Remove all backend server imports (Fastify, Express, HTTP). "
                    "Use state management patterns (Zustand/Redux) instead."
                )
        
        # Add domain-specific fixes
        for dv in domain_violations:
            new_constraints.append(
                f"DOMAIN_FIX: Remove {dv.description} at line {dv.line_number}. "
                f"This is prohibited in {dv.pattern} context."
            )
        
        if not new_constraints:
            return None
        
        return {
            "detected_violations": [s.violated_constraint for s in fatal_violations] + [f"DOMAIN:{dv.description}" for dv in domain_violations],
            "hard_constraints": new_constraints,
            "patch_version": datetime.now().isoformat()
        }

class HawkTortureTester:
    def __init__(self, iteration: int = 0, domain: str = "GENERIC"):
        self.iteration = iteration
        self.domain = domain
        self.evd = EVDController(timeout_seconds=30)
        self.analyzer = FailureAnalyzer()
        self.domain_verifier = DomainVerifier(domain)
        
    async def execute(self, target_file: str) -> HawkAudit:
        print(f"\033[1;95m🦅 Hawk v3.0 Iteration {self.iteration} Torture Testing...\033[0m")
        print(f"\033[1;37m   Target: {target_file}\033[0m")
        print(f"\033[1;37m   Domain: {self.domain}\033[0m")
        print(f"\033[1;37m   EVD Timeout: 30s | Signature Patterns: {len(self.analyzer.SIGNATURE_PATTERNS)}\033[0m")
        
        # Read code for static analysis
        with open(target_file) as f:
            code = f.read()
        
        # 1. STATIC DOMAIN VERIFICATION (catches hallucinations without execution)
        print(f"\033[1;94m🔍 Phase 1: Static Domain Verification...\033[0m")
        domain_violations = self.domain_verifier.analyze(code)
        
        if domain_violations:
            print(f"\033[1;31m   ❌ Domain Violations Detected: {len(domain_violations)}\033[0m")
            for dv in domain_violations[:3]:
                print(f"      Line {dv.line_number}: {dv.description}")
        else:
            print(f"\033[1;92m   ✅ Domain Verification Passed\033[0m")
        
        # 2. DYNAMIC EXECUTION (if static check passes or for runtime errors)
        print(f"\033[1;94m⚡ Phase 2: Dynamic Execution in EVD...\033[0m")
        exit_code, stdout, stderr, duration = await self.evd.execute(target_file)
        
        # Analyze failures
        signatures = self.analyzer.analyze(stderr, stdout)
        
        # Calculate integrity score
        integrity_score = self._calculate_integrity(stdout, stderr, signatures, domain_violations)
        
        # Generate patch if failures found
        patch = self.analyzer.generate_patch(signatures, domain_violations) if (signatures or domain_violations) else None
        
        # Determine pass/fail
        fatal_count = len([s for s in signatures if s.severity == "FATAL"])
        domain_fatal = len(domain_violations) > 0 and self.domain in ["FRONTEND_MOBILE", "FRONTEND_WEB"]
        passed = (exit_code == 0 and fatal_count == 0 and not domain_fatal and integrity_score > 0.8)
        
        audit = HawkAudit(
            iteration=self.iteration,
            target_file=target_file,
            domain=self.domain,
            execution_time_ms=duration,
            exit_code=exit_code,
            stdout=stdout[-2000:],  # Truncate for JSON
            stderr=stderr[-2000:],
            signatures=signatures,
            domain_violations=domain_violations,
            integrity_score=integrity_score,
            passed=passed,
            constraint_patch=patch
        )
        
        # Write audit log
        audit_file = f"hawk_audit_v{self.iteration}.json"
        with open(audit_file, "w") as f:
            json.dump(asdict(audit), f, indent=2, default=str)
        
        # Print summary
        status_color = "\033[1;92m" if passed else "\033[1;31m"
        print(f"{status_color}   Result: {'PASS' if passed else 'FAIL'} | "
              f"Fatal: {fatal_count} | Domain Issues: {len(domain_violations)} | Integrity: {integrity_score:.2f}\033[0m")
        
        if signatures:
            for sig in signatures[:3]:  # Show top 3
                print(f"\033[1;33m   ⚠️  {sig.severity}: {sig.error_type} "
                      f"(Law: {sig.violated_constraint})\033[0m")
        
        if patch:
            print(f"\033[1;96m   📝 Constraint Patch Generated: {len(patch['hard_constraints'])} fixes\033[0m")
        
        return audit
    
    def _calculate_integrity(self, stdout: str, stderr: str, signatures: List[FailureSignature], domain_violations: List[DomainViolation]) -> float:
        """Calculate system integrity score based on output analysis."""
        score = 1.0
        
        # Check for success indicators
        if "SUCCESS" in stdout or "✅" in stdout:
            score += 0.2
        if "checksum chain valid" in stdout.lower() or "integrity verified" in stdout.lower():
            score += 0.3
        
        # Penalties
        for sig in signatures:
            if sig.severity == "FATAL":
                score -= 0.3
            elif sig.severity == "WARNING":
                score -= 0.1
        
        # Domain violation penalties (heavy for frontend domains)
        for dv in domain_violations:
            score -= 0.4  # Heavy penalty for domain confusion
        
        return max(0.0, min(1.0, score))

async def main():
    if len(sys.argv) < 2:
        print("Usage: hawk_cli_v3.py <target_file> [iteration] [domain]")
        sys.exit(1)
    
    target = sys.argv[1]
    iteration = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    domain = sys.argv[3] if len(sys.argv) > 3 else "GENERIC"
    
    hawk = HawkTortureTester(iteration, domain)
    audit = await hawk.execute(target)
    
    sys.exit(0 if audit.passed else 1)

if __name__ == "__main__":
    asyncio.run(main())
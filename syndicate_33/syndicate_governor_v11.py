#!/usr/bin/env python3
"""
💎 SYNDICATE GOVERNOR v11.0 - DIAMOND EDITION 💎
Diamonds... a developer's best friend...

Features:
- Network: Proxy/TUN0/Direct support
- Token tracking & redline protection
- Progress visualization
- Context limit chunking
- Comprehensive logging
"""

import os
import sys
import json
import time
import asyncio
import argparse
import hashlib
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
from collections import deque
from itertools import cycle
import statistics

import httpx

# ============================================================
# 💎 ASCII BANNER
# ============================================================
BANNER = """
\033[1;96m██████╗ ██╗ █████╗ ███╗   ███╗ ██████╗ ███╗   ██╗██████╗ ███████╗\033[0m
\033[1;96m██╔══██╗██║██╔══██╗████╗ ████║██╔═══██╗████╗  ██║██╔══██╗██╔════╝\033[0m
\033[1;96m██║  ██║██║███████║██╔████╔██║██║   ██║██╔██╗ ██║██║  ██║███████╗\033[0m
\033[1;96m██║  ██║██║██╔══██║██║╚██╔╝██║██║   ██║██║╚██╗██║██║  ██║╚════██║\033[0m
\033[1;96m██████╔╝██║██║  ██║██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██████╔╝███████║\033[0m
\033[1;96m╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚══════╝\033[0m
\033[1;95m                                                                 \033[0m
\033[1;93m              💎 Diamonds... a developer's best friend... 💎      \033[0m
\033[1;90m═══════════════════════════════════════════════════════════════════\033[0m
"""

# ============================================================
# 💎 CONFIGURATION
# ============================================================
DEFAULT_CONFIG = {
    "handler_url": "http://127.0.0.1:3099/v1/profile/syndicate",
    "health_url": "http://127.0.0.1:3099/health",
    "proxy": None,  # "socks5://127.0.0.1:1081" or None
    "interface": None,  # "tun0" or None
    "timeout": 600.0,
    "max_retries": 3,
    "cooldown_seconds": 15,
    "circuit_breaker_threshold": 5,
    "token_limit_per_min": 100000,  # Gemini context
    "chunk_size_tokens": 800000,  # 80% of 1M limit
}

# Model decks with tiers
MODEL_DECKS = {
    "FAST": ["gemini-2.5-flash-lite", "gemini-2.5-flash"],
    "BALANCED": ["gemini-3-flash-preview", "gemini-2.5-flash-lite"],
    "SMART": ["gemini-3.1-flash-lite-preview", "gemini-3-flash-preview"],
}

# ============================================================
# 💎 DATA STRUCTURES
# ============================================================
@dataclass
class ShardMetrics:
    """Metrics for a single shard processing"""
    shard_id: str
    start_time: float
    end_time: Optional[float] = None
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    status: str = "pending"  # pending, success, failed
    error: str = ""
    retries: int = 0

@dataclass
class SessionStats:
    """Aggregated session statistics"""
    start_time: float = field(default_factory=time.time)
    total_shards: int = 0
    completed: int = 0
    failed: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    model_usage: Dict[str, int] = field(default_factory=dict)
    shard_times: List[float] = field(default_factory=list)
    
    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time
    
    @property
    def avg_time_per_shard(self) -> float:
        if not self.shard_times:
            return 0.0
        return statistics.mean(self.shard_times)
    
    @property
    def eta_seconds(self) -> float:
        remaining = self.total_shards - self.completed - self.failed
        if self.avg_time_per_shard == 0:
            return 0.0
        return remaining * self.avg_time_per_shard
    
    @property
    def progress_pct(self) -> float:
        if self.total_shards == 0:
            return 0.0
        return ((self.completed + self.failed) / self.total_shards) * 100

# ============================================================
# 💎 PROGRESS BAR
# ============================================================
def draw_progress_bar(percent: float, width: int = 40) -> str:
    """Draw ASCII progress bar"""
    filled = int(width * percent / 100)
    bar = "█" * filled + "░" * (width - filled)
    return f"[{bar}] {percent:.1f}%"

def format_time(seconds: float) -> str:
    """Format seconds to human readable"""
    if seconds < 60:
        return f"{seconds:.0f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}m"
    else:
        return f"{seconds/3600:.1f}h"

# ============================================================
# 💎 NETWORK CONFIGURATION
# ============================================================
def create_http_client(config: Dict) -> httpx.AsyncClient:
    """Create HTTP client with proper network configuration"""
    
    mounts = {}
    
    # Configure proxy if specified
    if config.get("proxy"):
        mounts["all://"] = httpx.AsyncHTTPTransport(proxy=config["proxy"])
    else:
        mounts["all://"] = httpx.AsyncHTTPTransport()
    
    # Note: Interface binding (tun0) requires OS-level configuration
    # This is handled at the system level, not httpx level
    
    return httpx.AsyncClient(
        timeout=config["timeout"],
        trust_env=False,
        mounts=mounts
    )

def check_interface(interface: str) -> bool:
    """Check if network interface exists"""
    import subprocess
    try:
        result = subprocess.run(
            ["ip", "link", "show", interface],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except:
        return False

# ============================================================
# 💎 TOKEN ESTIMATION (Rough)
# ============================================================
def estimate_tokens(text: str) -> int:
    """Rough token estimation (1 token ≈ 4 chars for English/code)"""
    return len(text) // 4

def chunk_prompt(prompt: str, max_tokens: int = 800000) -> List[str]:
    """Split large prompt into chunks"""
    estimated = estimate_tokens(prompt)
    if estimated <= max_tokens:
        return [prompt]
    
    # Split by sections (assumes markdown headers)
    import re
    sections = re.split(r'\n(?=#{1,3}\s)', prompt)
    
    chunks = []
    current_chunk = ""
    current_tokens = 0
    
    for section in sections:
        section_tokens = estimate_tokens(section)
        
        if current_tokens + section_tokens > max_tokens and current_chunk:
            chunks.append(current_chunk)
            current_chunk = section
            current_tokens = section_tokens
        else:
            current_chunk += "\n" + section
            current_tokens += section_tokens
    
    if current_chunk:
        chunks.append(current_chunk)
    
    return chunks

# ============================================================
# 💎 CIRCUIT BREAKER
# ============================================================
class CircuitBreaker:
    def __init__(self, threshold: int = 5, cooldown: int = 60):
        self.threshold = threshold
        self.cooldown = cooldown
        self.failures = 0
        self.last_failure = 0
        self.state = "closed"  # closed, open, half-open
    
    def record_success(self):
        self.failures = 0
        self.state = "closed"
    
    def record_failure(self) -> bool:
        """Returns True if circuit is now open"""
        self.failures += 1
        self.last_failure = time.time()
        
        if self.failures >= self.threshold:
            self.state = "open"
            return True
        return False
    
    def can_execute(self) -> bool:
        if self.state == "closed":
            return True
        if self.state == "open":
            if time.time() - self.last_failure > self.cooldown:
                self.state = "half-open"
                return True
            return False
        return True  # half-open allows one test

# ============================================================
# 💎 MASTER GOVERNOR
# ============================================================
class DiamondGovernor:
    def __init__(self, config: Dict, input_dir: Path, output_dir: Path):
        self.config = config
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.raw_dir = output_dir / "raw_responses"
        self.log_dir = output_dir / "logs"
        
        # Create directories
        for d in [self.output_dir, self.raw_dir, self.log_dir]:
            d.mkdir(parents=True, exist_ok=True)
        
        # HTTP client
        self.client = create_http_client(config)
        
        # State
        self.queue = asyncio.Queue()
        self.stats = SessionStats()
        self.circuit_breaker = CircuitBreaker(
            config.get("circuit_breaker_threshold", 5),
            60
        )
        
        # Token rate limiting
        self.token_window = deque()  # (timestamp, tokens)
        self.token_lock = asyncio.Lock()
        
        # Model rotation
        self.deck_cycle = cycle(["FAST", "BALANCED", "SMART"])
        self.model_cycles = {k: cycle(v) for k, v in MODEL_DECKS.items()}
        
        # Logging
        self.log_file = self.log_dir / f"governor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
    
    def log_event(self, event: Dict):
        """Log structured event"""
        event["timestamp"] = datetime.now().isoformat()
        with open(self.log_file, "a") as f:
            f.write(json.dumps(event) + "\n")
    
    async def check_token_rate(self, estimated_tokens: int) -> bool:
        """Check if we're within token rate limits"""
        async with self.token_lock:
            now = time.time()
            # Clean old entries (older than 60s)
            while self.token_window and self.token_window[0][0] < now - 60:
                self.token_window.popleft()
            
            current_rate = sum(tokens for _, tokens in self.token_window)
            
            if current_rate + estimated_tokens > self.config["token_limit_per_min"]:
                return False
            
            self.token_window.append((now, estimated_tokens))
            return True
    
    async def process_shard(self, shard_path: Path, worker_id: int) -> ShardMetrics:
        """Process a single shard"""
        shard_id = shard_path.stem
        metrics = ShardMetrics(shard_id=shard_id, start_time=time.time())
        
        # Read prompt
        with open(shard_path, "r", encoding="utf-8") as f:
            prompt_content = f.read()
        
        # Check chunking
        chunks = chunk_prompt(prompt_content, self.config["chunk_size_tokens"])
        if len(chunks) > 1:
            print(f"  \033[1;33m⚠️  Shard {shard_id} split into {len(chunks)} chunks\033[0m")
        
        # Select model tier based on complexity (simple heuristic)
        tier = next(self.deck_cycle)
        model = next(self.model_cycles[tier])
        metrics.model = model
        
        # Check token rate
        estimated_input = estimate_tokens(prompt_content)
        while not await self.check_token_rate(estimated_input):
            print(f"  \033[1;33m⏳ Worker {worker_id}: Token limit hit, cooling...\033[0m")
            await asyncio.sleep(5)
        
        # Circuit breaker
        if not self.circuit_breaker.can_execute():
            print(f"  \033[1;31m🔥 Worker {worker_id}: CIRCUIT OPEN - cooling 60s\033[0m")
            await asyncio.sleep(60)
        
        # Execute request
        for attempt in range(self.config["max_retries"]):
            try:
                resp = await self.client.post(
                    self.config["handler_url"],
                    json={
                        "modelId": model,
                        "prompt": prompt_content,
                    },
                    timeout=self.config["timeout"]
                )
                
                # Save raw response
                raw_path = self.raw_dir / f"{shard_id}_{int(time.time())}.json"
                raw_data = {
                    "shard_id": shard_id,
                    "model": model,
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "body": resp.json() if resp.status_code == 200 else resp.text,
                    "timestamp": datetime.now().isoformat()
                }
                with open(raw_path, "w") as f:
                    json.dump(raw_data, f, indent=2)
                
                if resp.status_code == 200:
                    data = resp.json()
                    
                    # Extract token usage if available
                    usage = data.get("usage", {})
                    metrics.input_tokens = usage.get("input_tokens", 0) or estimated_input
                    metrics.output_tokens = usage.get("output_tokens", estimate_tokens(data.get("content", "")))
                    
                    # Save processed output
                    out_path = self.output_dir / f"molecule_{shard_id}.json"
                    with open(out_path, "w") as f:
                        json.dump(data, f, indent=2)
                    
                    metrics.status = "success"
                    metrics.end_time = time.time()
                    self.circuit_breaker.record_success()
                    
                    self.log_event({
                        "type": "shard_complete",
                        "shard_id": shard_id,
                        "model": model,
                        "input_tokens": metrics.input_tokens,
                        "output_tokens": metrics.output_tokens,
                        "duration": metrics.end_time - metrics.start_time
                    })
                    
                    return metrics
                
                elif resp.status_code == 429:
                    # Rate limited
                    wait_time = int(resp.headers.get("Retry-After", 30))
                    print(f"  \033[1;33m⏳ Rate limited, waiting {wait_time}s...\033[0m")
                    await asyncio.sleep(wait_time)
                    metrics.retries += 1
                    
                else:
                    # Other error
                    print(f"  \033[1;31m❌ HTTP {resp.status_code} on {shard_id}\033[0m")
                    if self.circuit_breaker.record_failure():
                        print(f"  \033[1;31m🔥 CIRCUIT BREAKER OPENED\033[0m")
                    await asyncio.sleep(self.config["cooldown_seconds"])
                    metrics.retries += 1
                    
            except Exception as e:
                print(f"  \033[1;31m❌ Exception on {shard_id}: {str(e)[:80]}\033[0m")
                if self.circuit_breaker.record_failure():
                    print(f"  \033[1;31m🔥 CIRCUIT BREAKER OPENED\033[0m")
                await asyncio.sleep(self.config["cooldown_seconds"])
                metrics.retries += 1
        
        # All retries exhausted
        metrics.status = "failed"
        metrics.error = "Max retries exceeded"
        metrics.end_time = time.time()
        
        self.log_event({
            "type": "shard_failed",
            "shard_id": shard_id,
            "error": metrics.error,
            "retries": metrics.retries
        })
        
        return metrics
    
    async def worker(self, worker_id: int):
        """Worker loop"""
        while True:
            try:
                shard_path = self.queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            
            metrics = await self.process_shard(shard_path, worker_id)
            
            # Update stats
            self.stats.shard_times.append(metrics.end_time - metrics.start_time)
            self.stats.total_input_tokens += metrics.input_tokens
            self.stats.total_output_tokens += metrics.output_tokens
            self.stats.model_usage[metrics.model] = self.stats.model_usage.get(metrics.model, 0) + 1
            
            if metrics.status == "success":
                self.stats.completed += 1
            else:
                self.stats.failed += 1
            
            self.queue.task_done()
    
    def print_dashboard(self):
        """Print real-time dashboard"""
        # Clear screen (optional)
        # print("\033[2J\033[H")
        
        print("\n" + "\033[1;96m" + "="*70 + "\033[0m")
        print("\033[1;93m                    💎 DIAMOND GOVERNOR v11.0 💎\033[0m")
        print("\033[1;96m" + "="*70 + "\033[0m")
        
        # Progress bar
        progress = draw_progress_bar(self.stats.progress_pct)
        print(f"\n  {progress}")
        
        # Counters
        remaining = self.stats.total_shards - self.stats.completed - self.stats.failed
        print(f"\n  \033[1;37mShards: \033[1;32m{self.stats.completed} done\033[0m | "
              f"\033[1;31m{self.stats.failed} failed\033[0m | "
              f"\033[1;33m{remaining} pending\033[0m | "
              f"\033[1;37m{self.stats.total_shards} total\033[0m")
        
        # Timing
        elapsed = format_time(self.stats.elapsed)
        eta = format_time(self.stats.eta_seconds)
        avg = format_time(self.stats.avg_time_per_shard) if self.stats.avg_time_per_shard else "N/A"
        
        print(f"\n  \033[1;90mTime: {elapsed} elapsed | {eta} ETA | {avg} avg/shard\033[0m")
        
        # Token stats
        print(f"\n  \033[1;90mTokens: {self.stats.total_input_tokens:,} in | "
              f"{self.stats.total_output_tokens:,} out | "
              f"{self.stats.total_input_tokens + self.stats.total_output_tokens:,} total\033[0m")
        
        # Model usage
        if self.stats.model_usage:
            print(f"\n  \033[1;90mModel Calls:\033[0m")
            for model, count in sorted(self.stats.model_usage.items()):
                print(f"    {model}: {count}")
        
        print("\n" + "\033[1;96m" + "="*70 + "\033[0m")
    
    async def run(self, num_workers: int = 3):
        """Main execution"""
        print(BANNER)
        
        # Health check
        try:
            resp = await self.client.get(self.config["health_url"])
            if resp.status_code == 200:
                print("\033[1;92m✓ Engine Online\033[0m\n")
            else:
                print("\033[1;31m⚠ Engine unhealthy\033[0m\n")
        except Exception as e:
            print(f"\033[1;31m✗ Engine unreachable: {e}\033[0m\n")
            return
        
        # Load shards
        shards = sorted(self.input_dir.glob("*.prompt"))
        if not shards:
            print("\033[1;31mNo .prompt files found in input directory\033[0m")
            return
        
        self.stats.total_shards = len(shards)
        print(f"\033[1;94mLoaded {len(shards)} shards\033[0m\n")
        
        # Queue shards
        for shard in shards:
            self.queue.put_nowait(shard)
        
        # Start workers
        workers = [asyncio.create_task(self.worker(i)) for i in range(num_workers)]
        
        # Progress display loop
        while not self.queue.empty():
            self.print_dashboard()
            await asyncio.sleep(2)
        
        # Wait for completion
        await self.queue.join()
        for w in workers:
            w.cancel()
        
        # Final stats
        self.print_dashboard()
        print("\n\033[1;92m💎 Mission Complete 💎\033[0m\n")
        
        # Summary report
        report_path = self.log_dir / f"summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, "w") as f:
            json.dump({
                "config": self.config,
                "stats": {
                    "total_shards": self.stats.total_shards,
                    "completed": self.stats.completed,
                    "failed": self.stats.failed,
                    "elapsed_seconds": self.stats.elapsed,
                    "total_input_tokens": self.stats.total_input_tokens,
                    "total_output_tokens": self.stats.total_output_tokens,
                    "model_usage": self.stats.model_usage,
                }
            }, f, indent=2)
        
        print(f"\033[1;90mReport saved: {report_path}\033[0m\n")
        
        await self.client.aclose()

# ============================================================
# 💎 CLI
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="Diamond Governor v11.0")
    parser.add_argument("--input", "-i", type=Path, required=True,
                       help="Directory containing .prompt files")
    parser.add_argument("--output", "-o", type=Path, required=True,
                       help="Output directory for molecules")
    parser.add_argument("--workers", "-w", type=int, default=3,
                       help="Number of parallel workers (default: 3)")
    parser.add_argument("--proxy", "-p", type=str, default=None,
                       help="Proxy URL (e.g., socks5://127.0.0.1:1081)")
    parser.add_argument("--interface", type=str, default=None,
                       help="Network interface (e.g., tun0)")
    parser.add_argument("--token-limit", type=int, default=100000,
                       help="Token per minute limit (default: 100000)")
    
    args = parser.parse_args()
    
    # Build config
    config = DEFAULT_CONFIG.copy()
    if args.proxy:
        config["proxy"] = args.proxy
    if args.interface:
        config["interface"] = args.interface
        if args.interface == "tun0" and not check_interface("tun0"):
            print("\033[1;33m⚠ Warning: tun0 not found, using default\033[0m")
            config["interface"] = None
    config["token_limit_per_min"] = args.token_limit
    
    # Run
    governor = DiamondGovernor(config, args.input, args.output)
    try:
        asyncio.run(governor.run(args.workers))
    except KeyboardInterrupt:
        print("\n\033[1;31m🛑 Aborted by user\033[0m")

if __name__ == "__main__":
    main()

import re
import time
import subprocess
import urllib.request
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple

from .config import UTILS_DIR

TARGETS_FILE = UTILS_DIR / "targets.txt"


def parse_targets(file_path: Path = TARGETS_FILE) -> Dict[str, str]:
    """Parse targets from targets.txt file."""
    targets = {}
    if not file_path.exists():
        return targets

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z0-9_]+)\s*=\s*[\"']?(.*?)[\"']?$", line)
            if m:
                key = m.group(1).strip()
                val = m.group(2).strip().strip("\"'")
                targets[key] = val
    return targets


def check_target(name: str, target: str, timeout: float = 5.0) -> Tuple[str, bool, float, str]:
    """
    Check availability of single target.
    Returns: (name, success, latency_ms, detail)
    """
    start = time.perf_counter()
    if target.startswith("PING:"):
        ip = target.replace("PING:", "").strip()
        try:
            res = subprocess.run(
                ["ping", "-c", "1", "-W", str(int(timeout)), ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            elapsed = (time.perf_counter() - start) * 1000
            return (name, res.returncode == 0, elapsed, "Ping OK" if res.returncode == 0 else "Ping Timeout")
        except Exception as e:
            return (name, False, 0.0, str(e))

    # HTTP/HTTPS target
    url = target
    for attempt in range(2):
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
                    "Accept": "*/*"
                }
            )
            with urllib.request.urlopen(req, timeout=timeout) as response:
                elapsed = (time.perf_counter() - start) * 1000
                code = response.getcode()
                ok = (200 <= code < 400)
                return (name, ok, elapsed, f"HTTP {code}")
        except Exception as e:
            # If response was received with error code like 403/404, TLS and connection still succeeded!
            if hasattr(e, "code"):
                elapsed = (time.perf_counter() - start) * 1000
                return (name, True, elapsed, f"HTTP {e.code}")

            if attempt == 0:
                time.sleep(0.3)
                continue

            elapsed = (time.perf_counter() - start) * 1000
            err_msg = str(e).lower()
            if "timed out" in err_msg:
                detail = "Timeout"
            elif "errno -3" in err_msg or "name resolution" in err_msg:
                detail = "DNS Error"
            elif "connection reset" in err_msg:
                detail = "Conn Reset (DPI)"
            elif "connection refused" in err_msg:
                detail = "Conn Refused"
            else:
                detail = str(e)[:25]
            return (name, False, elapsed, detail)


def run_target_tests(targets: Dict[str, str] = None, max_workers: int = 4) -> List[Tuple[str, bool, float, str]]:
    """Test all targets in parallel."""
    if targets is None:
        targets = parse_targets()

    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(check_target, name, target): name
            for name, target in targets.items()
        }
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                name = futures[future]
                results.append((name, False, 0.0, str(e)))

    # Sort in original order of targets dict
    order = list(targets.keys())
    results.sort(key=lambda x: order.index(x[0]) if x[0] in order else 999)
    return results

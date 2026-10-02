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
            line = re.sub(r"#.*$", "", line).strip()
            if not line:
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
        attempt_start = time.perf_counter()
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
                    "Accept": "*/*"
                }
            )
            with urllib.request.urlopen(req, timeout=timeout) as response:
                elapsed = (time.perf_counter() - attempt_start) * 1000
                code = response.getcode()
                ok = (200 <= code < 400)
                return (name, ok, elapsed, f"HTTP {code}")
        except Exception as e:
            # If response was received with error code like 403/404, TLS and connection still succeeded!
            if hasattr(e, "code"):
                elapsed = (time.perf_counter() - attempt_start) * 1000
                return (name, True, elapsed, f"HTTP {e.code}")

            if attempt == 0:
                time.sleep(0.3)
                continue

            elapsed = (time.perf_counter() - attempt_start) * 1000
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


def benchmark_all_strategies(cfg: dict = None, on_progress=None) -> List[Tuple[str, str, bool, bool, float]]:
    """
    Test YouTube and Discord connectivity against each strategy in sequence.
    Returns: list of (strategy_name, strategy_filename, youtube_ok, discord_ok, avg_latency_ms)
    """
    from .config import load_config
    from .strategy import list_strategies, get_strategy
    from .runner import Runner, get_running_status, is_systemd_service_active

    cfg = cfg or load_config()
    was_running, prev_pid, prev_strat_name = get_running_status()
    prev_strat = get_strategy(prev_strat_name) if prev_strat_name else None
    had_systemd = is_systemd_service_active()

    runner = Runner(cfg)
    strategies = list_strategies()
    all_targets = parse_targets()
    test_targets = {
        k: all_targets[k]
        for k in ["YouTubeWeb", "DiscordMain", "DiscordGateway"]
        if k in all_targets
    }

    results = []
    try:
        if had_systemd:
            subprocess.run(["systemctl", "stop", "gnupret.service"], stderr=subprocess.DEVNULL)
        elif was_running:
            runner.stop_background()

        for s_id, strat in strategies.items():
            if on_progress:
                on_progress(strat.name, "starting")
            try:
                runner.start_background(strat)
                time.sleep(0.8)
                t_res = run_target_tests(test_targets, max_workers=3)
                yt_ok = any(r[1] for r in t_res if "YouTube" in r[0])
                dc_ok = any(r[1] for r in t_res if "Discord" in r[0])
                latencies = [r[2] for r in t_res if r[1] and r[2] > 0]
                avg_lat = sum(latencies) / len(latencies) if latencies else 0.0

                results.append((strat.name, strat.filename, yt_ok, dc_ok, avg_lat))
                if on_progress:
                    on_progress(strat.name, "done", yt_ok, dc_ok, avg_lat)
            except Exception as e:
                results.append((strat.name, strat.filename, False, False, 0.0))
                if on_progress:
                    on_progress(strat.name, f"error: {e}", False, False, 0.0)
            finally:
                runner.stop_background()
    finally:
        # Restore original running state
        if had_systemd:
            subprocess.run(["systemctl", "start", "gnupret.service"], stderr=subprocess.DEVNULL)
        elif was_running and prev_strat:
            try:
                runner.start_background(prev_strat)
            except Exception:
                pass

    return results

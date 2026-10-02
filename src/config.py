import os
import json
import shutil
import subprocess
import urllib.request
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
BIN_DIR = BASE_DIR / "bin"
LISTS_DIR = BASE_DIR / "lists"
UTILS_DIR = BASE_DIR / "utils"
CONFIG_FILE = BASE_DIR / "config.json"

MASTER_IPSET = LISTS_DIR / "ipset-all.txt.master"
BACKUP_IPSET = LISTS_DIR / "ipset-all.txt.backup"
REMOTE_IPSET_URL = "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/.service/ipset-service.txt"


def get_pid_file() -> Path:
    """Return secure path to PID file (/run for root, user-isolated /tmp for testing)."""
    run_dir = Path("/run")
    if run_dir.exists() and os.access(run_dir, os.W_OK):
        return run_dir / "gnupret.pid"
    return Path(f"/tmp/gnupret_{os.getuid()}.pid")


PID_FILE = get_pid_file()

DEFAULT_CONFIG = {
    "strategy": "general.conf",
    "game_filter_mode": "disabled",  # "disabled", "all", "tcp", "udp"
    "game_filter_tcp": "1024-65535",
    "game_filter_udp": "1024-65535",
    "interface": "any",              # "any" (all non-lo), "auto", or specific e.g. "eth0"
    "firewall_backend": "auto",      # "auto", "nftables", "iptables"
    "qnum": 200,
    "fwmark": "0x40000000"
}


def load_config() -> dict:
    """Load configuration from config.json, merging with defaults."""
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                user_cfg = json.load(f)
                cfg.update(user_cfg)
        except Exception:
            pass
    return cfg


def save_config(cfg: dict) -> None:
    """Save configuration to config.json atomically."""
    temp_file = CONFIG_FILE.with_name(f".{CONFIG_FILE.name}.tmp.{os.getpid()}")
    try:
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=4, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        temp_file.replace(CONFIG_FILE)
    finally:
        if temp_file.exists():
            try:
                temp_file.unlink()
            except OSError:
                pass


def ensure_user_lists() -> None:
    """Ensure user lists exist with dummy data so nfqws won't fail."""
    LISTS_DIR.mkdir(parents=True, exist_ok=True)

    defaults = {
        "list-general-user.txt": "# Never leave this file empty\ndomain.example.abc\n",
        "list-exclude-user.txt": "domain.example.abc\n",
        "ipset-exclude-user.txt": "203.0.113.113/32\n",
    }

    for filename, content in defaults.items():
        filepath = LISTS_DIR / filename
        if not filepath.exists() or filepath.stat().st_size == 0:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)

    # If master ipset is missing but legacy backup exists, migrate it
    if not MASTER_IPSET.exists() and BACKUP_IPSET.exists():
        try:
            shutil.copyfile(BACKUP_IPSET, MASTER_IPSET)
        except Exception:
            pass


def get_ipset_status() -> str:
    """
    Check IPSet filter status according to Flowseal's logic:
    - 'any': file empty or missing
    - 'none': contains 203.0.113.113/32 (dummy subnet)
    - 'loaded': contains real subnets
    """
    ipset_file = LISTS_DIR / "ipset-all.txt"
    if not ipset_file.exists():
        return "any"

    try:
        with open(ipset_file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read().strip()
        if not content:
            return "any"
        if "203.0.113.113/32" in content:
            return "none"
        return "loaded"
    except Exception:
        return "any"


def download_master_ipset() -> bool:
    """Download full master IPSet (33,000+ subnets) from Flowseal repository."""
    try:
        req = urllib.request.Request(REMOTE_IPSET_URL, headers={"User-Agent": "gnupret"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read()
            if data and len(data) > 1000:
                LISTS_DIR.mkdir(parents=True, exist_ok=True)
                MASTER_IPSET.write_bytes(data)
                return True
    except Exception:
        pass
    return False


def set_ipset_mode(mode: str) -> bool:
    """
    Change IPSet filter mode:
    - 'loaded': copy full IP list from master into active ipset
    - 'none': write dummy IP 203.0.113.113/32
    - 'any': empty file
    """
    ipset_file = LISTS_DIR / "ipset-all.txt"
    ensure_user_lists()

    if mode == "none":
        with open(ipset_file, "w", encoding="utf-8") as f:
            f.write("203.0.113.113/32\n")
        return True
    elif mode == "any":
        with open(ipset_file, "w", encoding="utf-8") as f:
            f.write("")
        return True
    elif mode == "loaded":
        if not MASTER_IPSET.exists() or MASTER_IPSET.stat().st_size < 1000:
            if not download_master_ipset():
                if BACKUP_IPSET.exists():
                    shutil.copyfile(BACKUP_IPSET, MASTER_IPSET)
                else:
                    return False
        shutil.copyfile(MASTER_IPSET, ipset_file)
        return True
    return False


def detect_default_interface() -> str:
    """Detect the active network interface for outgoing internet traffic."""
    # 1. Ask kernel directly which interface handles route to public internet
    try:
        out = subprocess.check_output(["ip", "route", "get", "1.1.1.1"], text=True)
        parts = out.strip().split()
        if "dev" in parts:
            idx = parts.index("dev") + 1
            if idx < len(parts):
                return parts[idx]
    except Exception:
        pass

    # 2. Fallback to default route
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
        lines = out.strip().splitlines()
        if lines:
            parts = lines[0].split()
            if "dev" in parts:
                idx = parts.index("dev") + 1
                if idx < len(parts):
                    return parts[idx]
    except Exception:
        pass
    return "any"

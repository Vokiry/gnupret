import os
import json
import subprocess
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
BIN_DIR = BASE_DIR / "bin"
LISTS_DIR = BASE_DIR / "lists"
UTILS_DIR = BASE_DIR / "utils"
CONFIG_FILE = BASE_DIR / "config.json"
PID_FILE = Path("/tmp/gnupret.pid")

DEFAULT_CONFIG = {
    "strategy": "general.bat",
    "game_filter_mode": "disabled", # "disabled", "all", "tcp", "udp"
    "game_filter_tcp": "1024-65535",
    "game_filter_udp": "1024-65535",
    "interface": "auto",           # "auto", "any", or specific interface e.g. "eth0"
    "firewall_backend": "auto",     # "auto", "nftables", "iptables"
    "qnum": 200,
    "fwmark": "0x40000000",
    "auto_update_check": True
}


def load_config():
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


def save_config(cfg):
    """Save configuration to config.json."""
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=4, ensure_ascii=False)


def ensure_user_lists():
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


def get_ipset_status():
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


def set_ipset_mode(mode: str):
    """
    Change IPSet filter mode:
    - 'loaded': restore real IP list from backup if available
    - 'none': write dummy IP 203.0.113.113/32
    - 'any': empty file
    """
    ipset_file = LISTS_DIR / "ipset-all.txt"
    backup_file = LISTS_DIR / "ipset-all.txt.backup"
    
    current = get_ipset_status()
    if current == mode:
        return True
    
    if mode == "none":
        if current == "loaded" and ipset_file.exists():
            try:
                ipset_file.replace(backup_file)
            except Exception:
                pass
        with open(ipset_file, "w", encoding="utf-8") as f:
            f.write("203.0.113.113/32\n")
    elif mode == "any":
        if current == "loaded" and ipset_file.exists():
            try:
                ipset_file.replace(backup_file)
            except Exception:
                pass
        with open(ipset_file, "w", encoding="utf-8") as f:
            f.write("")
    elif mode == "loaded":
        if backup_file.exists():
            backup_file.replace(ipset_file)
        else:
            # If no backup, try downloading from Flowseal's repo or notify
            return False
    return True


def update_upstream_lists() -> bool:
    """Download updated ipset and domain lists from Flowseal repository."""
    import urllib.request
    base_url = "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/lists"
    files = ["ipset-all.txt", "list-general.txt", "list-google.txt", "list-exclude.txt", "ipset-exclude.txt"]
    for fname in files:
        url = f"{base_url}/{fname}"
        dst = LISTS_DIR / fname
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "gnupret"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = resp.read()
                if data:
                    dst.write_bytes(data)
        except Exception as e:
            print(f"Warning: could not update {fname}: {e}")
    return True


def detect_default_interface():
    """Detect the active physical network interface with default gateway."""
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
        # Prioritize physical ethernet or wifi over virtual/tun interfaces
        lines = out.strip().splitlines()
        for line in lines:
            parts = line.split()
            if "dev" in parts:
                idx = parts.index("dev") + 1
                if idx < len(parts):
                    iface = parts[idx]
                    # Skip common VPN/tunnel interfaces if physical is available
                    if not iface.startswith(("tun", "tap", "wg", "tailscale", "docker", "br-", "veth", "happ-")):
                        return iface
        # If all were vpn/tun, return the first one
        if lines:
            parts = lines[0].split()
            if "dev" in parts:
                idx = parts.index("dev") + 1
                return parts[idx]
    except Exception:
        pass
    return "any"

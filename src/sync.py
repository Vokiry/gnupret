import os
import re
import json
import time
import shutil
import tempfile
import subprocess
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Dict, Tuple, Optional

from .config import BIN_DIR, LISTS_DIR, MASTER_IPSET, get_ipset_status
from .strategy import parse_conf_file, STRATEGIES_DIR

FLOWSEAL_TREE_API = "https://api.github.com/repos/Flowseal/zapret-discord-youtube/git/trees/main?recursive=1"
FLOWSEAL_RAW_BASE = "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main"


def sanitize_strategy_id(raw_id: str) -> str:
    """Sanitize strategy identifier to prevent Path Traversal and invalid filenames."""
    cleaned = re.sub(r"[^a-zA-Z0-9_\-]", "", raw_id.strip().lower().replace(" ", "_"))
    if not cleaned or cleaned.startswith((".", "-")):
        cleaned = f"imported_{int(time.time())}"
    return cleaned


def convert_bat_to_conf(bat_content: str, filename: str) -> Tuple[str, str, str]:
    """
    Parse Windows .bat content and convert to native gnupret .conf format.
    Returns: (strategy_id, strategy_name, conf_content)
    """
    # Merge multiline lines ending with ^
    content = re.sub(r"\^\s*[\r\n]+", " ", bat_content)

    # Locate the winws execution line
    winws_match = re.search(r'winws(?:\.exe)?[\"\'\s]+(.*?)(?:\r?\n|$)', content, re.IGNORECASE)
    if not winws_match:
        raise ValueError("Could not find winws execution line in .bat file")

    raw_args = winws_match.group(1).strip()

    # Extract TCP and UDP ports
    tcp_match = re.search(r"--wf-tcp=([^\s]+)", raw_args)
    udp_match = re.search(r"--wf-udp=([^\s]+)", raw_args)

    raw_tcp = tcp_match.group(1) if tcp_match else "80,443,2053,2083,2087,2096,8443,{GAME_FILTER_TCP}"
    raw_udp = udp_match.group(1) if udp_match else "443,19294-19344,50000-50100,{GAME_FILTER_UDP}"

    # Normalize GameFilter variables
    for k in ("%GameFilterTCP%", "%GameFilter%"):
        raw_tcp = raw_tcp.replace(k, "{GAME_FILTER_TCP}")
    for k in ("%GameFilterUDP%", "%GameFilter%"):
        raw_udp = raw_udp.replace(k, "{GAME_FILTER_UDP}")

    # Remove wf-tcp and wf-udp from arguments
    cleaned = re.sub(r"--wf-(?:tcp|udp)=[^\s]+", "", raw_args).strip()

    # Normalize paths and variables
    cleaned = cleaned.replace("%BIN%", "{BIN}/")
    cleaned = cleaned.replace("%LISTS%", "{LISTS}/")
    cleaned = cleaned.replace("%GameFilterTCP%", "{GAME_FILTER_TCP}")
    cleaned = cleaned.replace("%GameFilterUDP%", "{GAME_FILTER_UDP}")
    cleaned = cleaned.replace("%GameFilter%", "{GAME_FILTER_TCP}")
    cleaned = cleaned.replace("^!", "!")

    # Format blocks separated by --new
    blocks = [b.strip() for b in re.split(r"\s+--new(?:\s+|$)", cleaned) if b.strip()]
    formatted_args = "\n--new\n".join(blocks)

    # Derive clean ID and display name
    clean_stem = Path(filename).stem
    if clean_stem.lower() == "general":
        strategy_id = "general"
        name = "Default (general)"
    else:
        m = re.search(r"general\s*\((.*?)\)", clean_stem, re.IGNORECASE)
        if m:
            name = m.group(1).strip()
            strategy_id = sanitize_strategy_id(name)
        else:
            name = clean_stem
            strategy_id = sanitize_strategy_id(clean_stem)

    conf_content = f"""# gnupret strategy: {name}
NAME={name}
TCP_PORTS={raw_tcp}
UDP_PORTS={raw_udp}

{formatted_args}
"""
    return strategy_id, name, conf_content


def verify_conf_content(strategy_id: str, conf_content: str) -> Tuple[bool, str]:
    """Verify that converted strategy passes nfqws --dry-run safely."""
    nfqws = BIN_DIR / "nfqws"
    if not nfqws.exists():
        return True, "nfqws not present to verify, skipped dry-run"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", encoding="utf-8") as temp_conf:
        temp_conf.write(conf_content)
        temp_conf.flush()
        strat = parse_conf_file(Path(temp_conf.name))
        if not strat:
            return False, "Failed to parse generated .conf"

        args = [str(nfqws), "--dry-run"] + strat.build_nfqws_args(qnum=200)
        res = subprocess.run(args, capture_output=True, text=True)
        if res.returncode != 0:
            return False, res.stderr.strip() or res.stdout.strip()
        return True, "OK"


def import_bat_file(source: str) -> Tuple[bool, str, Optional[str]]:
    """
    Import a .bat strategy from a local path or URL securely.
    Returns: (success, message, strategy_id)
    """
    if source.startswith(("http://", "https://")):
        try:
            req = urllib.request.Request(source, headers={"User-Agent": "gnupret"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                bat_text = resp.read().decode("utf-8", errors="ignore")
            filename = source.rstrip("/").split("/")[-1]
        except Exception as e:
            return False, f"Failed to download .bat from {source}: {e}", None
    else:
        p = Path(source)
        if not p.exists():
            return False, f"File {source} does not exist", None
        try:
            bat_text = p.read_text(encoding="utf-8", errors="ignore")
            filename = p.name
        except Exception as e:
            return False, f"Failed to read {source}: {e}", None

    try:
        strat_id, name, conf_content = convert_bat_to_conf(bat_text, filename)
    except Exception as e:
        return False, f"Conversion failed: {e}", None

    strat_id = sanitize_strategy_id(strat_id)
    ok, err = verify_conf_content(strat_id, conf_content)
    if not ok:
        return False, f"Validation failed with nfqws: {err}", None

    dst = (STRATEGIES_DIR / f"{strat_id}.conf").resolve()
    if not dst.is_relative_to(STRATEGIES_DIR.resolve()):
        return False, "Invalid strategy path (path traversal prevented)", None

    dst.write_text(conf_content, encoding="utf-8")
    return True, f"Strategy '{name}' imported and verified -> strategies/{dst.name}", strat_id


def sync_flowseal() -> Dict[str, list]:
    """
    Synchronize all strategies, fake payloads, and lists with upstream Flowseal.
    Returns summary dict of actions taken.
    """
    summary = {
        "strategies_new": [],
        "strategies_updated": [],
        "strategies_unchanged": 0,
        "bins_downloaded": [],
        "lists_updated": [],
        "errors": []
    }

    headers = {"User-Agent": "gnupret"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        req = urllib.request.Request(FLOWSEAL_TREE_API, headers=headers)
        with urllib.request.urlopen(req, timeout=12) as resp:
            tree_data = json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 403:
            raise RuntimeError("GitHub API rate limit exceeded. Please wait a short while or provide GITHUB_TOKEN.")
        raise RuntimeError(f"GitHub API returned error {e.code}: {e.reason}")
    except Exception as e:
        raise RuntimeError(f"Failed to fetch Flowseal repository tree: {e}")

    items = tree_data.get("tree", [])

    # 1. Sync Strategies (.bat -> .conf)
    bat_items = [
        item for item in items
        if item["path"].endswith(".bat") and not item["path"].startswith("service")
    ]

    for item in bat_items:
        quoted_path = urllib.parse.quote(item["path"])
        bat_url = f"{FLOWSEAL_RAW_BASE}/{quoted_path}"
        try:
            req = urllib.request.Request(bat_url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                bat_text = resp.read().decode("utf-8", errors="ignore")

            strat_id, name, conf_content = convert_bat_to_conf(bat_text, item["path"])
            strat_id = sanitize_strategy_id(strat_id)
            dest_conf = (STRATEGIES_DIR / f"{strat_id}.conf").resolve()
            if not dest_conf.is_relative_to(STRATEGIES_DIR.resolve()):
                continue

            if dest_conf.exists():
                existing = dest_conf.read_text(encoding="utf-8")
                if existing.strip() == conf_content.strip():
                    summary["strategies_unchanged"] += 1
                    continue
                else:
                    ok, err = verify_conf_content(strat_id, conf_content)
                    if ok:
                        dest_conf.write_text(conf_content, encoding="utf-8")
                        summary["strategies_updated"].append(name)
                    else:
                        summary["errors"].append(f"Validation failed for updated {name}: {err}")
            else:
                ok, err = verify_conf_content(strat_id, conf_content)
                if ok:
                    dest_conf.write_text(conf_content, encoding="utf-8")
                    summary["strategies_new"].append(name)
                else:
                    summary["errors"].append(f"Validation failed for new {name}: {err}")
        except Exception as e:
            summary["errors"].append(f"Error syncing {item['path']}: {e}")

    # 2. Sync Binary Fake Payloads (bin/*.bin)
    bin_items = [
        item for item in items
        if item["path"].startswith("bin/") and item["path"].endswith(".bin")
    ]

    for item in bin_items:
        rel_filename = Path(item["path"]).name
        dst_bin = BIN_DIR / rel_filename

        needs_download = False
        if not dst_bin.exists():
            needs_download = True
        elif "size" in item and dst_bin.stat().st_size != item["size"]:
            needs_download = True

        if needs_download:
            quoted_path = urllib.parse.quote(item["path"])
            bin_url = f"{FLOWSEAL_RAW_BASE}/{quoted_path}"
            try:
                req = urllib.request.Request(bin_url, headers=headers)
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = resp.read()
                    dst_bin.write_bytes(data)
                summary["bins_downloaded"].append(rel_filename)
            except Exception as e:
                summary["errors"].append(f"Failed to download payload {rel_filename}: {e}")

    # 3. Sync Lists (lists/*.txt) - Excluding dummy ipset-all.txt and user lists
    list_items = [
        item for item in items
        if item["path"].startswith("lists/") and item["path"].endswith(".txt") and "user" not in item["path"]
    ]

    for item in list_items:
        rel_filename = Path(item["path"]).name
        # Skip ipset-all.txt here - master is synced separately
        if rel_filename == "ipset-all.txt":
            continue

        dst_list = LISTS_DIR / rel_filename
        needs_download = False
        if not dst_list.exists():
            needs_download = True
        elif "size" in item and dst_list.stat().st_size != item["size"]:
            needs_download = True

        if needs_download:
            quoted_path = urllib.parse.quote(item["path"])
            list_url = f"{FLOWSEAL_RAW_BASE}/{quoted_path}"
            try:
                req = urllib.request.Request(list_url, headers=headers)
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = resp.read()
                    dst_list.write_bytes(data)
                summary["lists_updated"].append(rel_filename)
            except Exception as e:
                summary["errors"].append(f"Failed to update list {rel_filename}: {e}")

    # 4. Sync Master IPSet from .service/ipset-service.txt
    try:
        master_url = f"{FLOWSEAL_RAW_BASE}/.service/ipset-service.txt"
        req = urllib.request.Request(master_url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read()
            if data and len(data) > 1000:
                if not MASTER_IPSET.exists() or MASTER_IPSET.read_bytes() != data:
                    MASTER_IPSET.write_bytes(data)
                    summary["lists_updated"].append("ipset-all.txt.master (33k subnets)")
                    # If user currently has 'loaded' mode active, refresh active file
                    if get_ipset_status() == "loaded":
                        active_ipset = LISTS_DIR / "ipset-all.txt"
                        shutil.copyfile(MASTER_IPSET, active_ipset)
    except Exception as e:
        summary["errors"].append(f"Failed to sync master ipset: {e}")

    # 5. Sync hosts
    hosts_dst = LISTS_DIR / "hosts"
    try:
        hosts_url = f"{FLOWSEAL_RAW_BASE}/.service/hosts"
        req = urllib.request.Request(hosts_url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = resp.read()
            if not hosts_dst.exists() or hosts_dst.read_bytes() != data:
                hosts_dst.write_bytes(data)
    except Exception:
        pass

    return summary

import os
import re
import shutil
import urllib.request
from pathlib import Path
from .config import BASE_DIR

HOSTS_PATH = Path("/etc/hosts")
BACKUP_HOSTS_PATH = Path("/etc/hosts.gnupret.bak")
LOCAL_HOSTS_FILE = BASE_DIR / "lists" / "hosts"
REMOTE_HOSTS_URL = "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/refs/heads/main/.service/hosts"

MARKER_BEGIN = "# --- GNUPRET DISCORD/TELEGRAM HOSTS BEGIN ---"
MARKER_END = "# --- GNUPRET DISCORD/TELEGRAM HOSTS END ---"


def _atomic_write_hosts(content: str) -> None:
    """Safely and atomically update /etc/hosts, creating a permanent backup on first modification."""
    if not HOSTS_PATH.exists():
        raise FileNotFoundError("/etc/hosts does not exist")

    # Create original backup if not present
    if not BACKUP_HOSTS_PATH.exists():
        try:
            shutil.copy2(HOSTS_PATH, BACKUP_HOSTS_PATH)
        except Exception:
            pass

    tmp_path = HOSTS_PATH.with_name(f".hosts.tmp.{os.getpid()}")
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        tmp_path.chmod(0o644)
        tmp_path.replace(HOSTS_PATH)
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


def fetch_latest_hosts() -> str:
    """Fetch the latest hosts content from the Flowseal repo or local fallback."""
    try:
        req = urllib.request.Request(REMOTE_HOSTS_URL, headers={"User-Agent": "gnupret"})
        with urllib.request.urlopen(req, timeout=6) as response:
            return response.read().decode("utf-8")
    except Exception:
        if LOCAL_HOSTS_FILE.exists():
            return LOCAL_HOSTS_FILE.read_text(encoding="utf-8")
        raise RuntimeError("Could not fetch hosts file from remote or local storage.")


def get_hosts_status() -> dict:
    """Check whether gnupret hosts block is installed in /etc/hosts."""
    if not HOSTS_PATH.exists():
        return {"installed": False, "lines_count": 0}

    try:
        content = HOSTS_PATH.read_text(encoding="utf-8")
    except Exception:
        return {"installed": False, "lines_count": 0}

    pattern = re.compile(
        re.escape(MARKER_BEGIN) + r"(.*?)" + re.escape(MARKER_END),
        re.DOTALL
    )
    match = pattern.search(content)
    if match:
        block = match.group(1).strip()
        lines = [l for l in block.splitlines() if l.strip() and not l.startswith("#")]
        return {"installed": True, "lines_count": len(lines)}
    return {"installed": False, "lines_count": 0}


def update_hosts() -> bool:
    """Update or add gnupret block in /etc/hosts safely."""
    hosts_data = fetch_latest_hosts().strip()
    new_block = f"{MARKER_BEGIN}\n{hosts_data}\n{MARKER_END}\n"

    try:
        content = HOSTS_PATH.read_text(encoding="utf-8")
    except Exception as e:
        raise PermissionError(f"Cannot read /etc/hosts (are you root?): {e}")

    pattern = re.compile(
        re.escape(MARKER_BEGIN) + r".*?" + re.escape(MARKER_END) + r"\n?",
        re.DOTALL
    )

    if pattern.search(content):
        updated_content = pattern.sub(lambda _: new_block, content)
    else:
        updated_content = content.rstrip() + "\n\n" + new_block

    try:
        _atomic_write_hosts(updated_content)
        return True
    except Exception as e:
        raise PermissionError(f"Cannot write to /etc/hosts: {e}")


def remove_hosts() -> bool:
    """Remove gnupret block from /etc/hosts cleanly."""
    if not HOSTS_PATH.exists():
        return True

    try:
        content = HOSTS_PATH.read_text(encoding="utf-8")
    except Exception as e:
        raise PermissionError(f"Cannot read /etc/hosts: {e}")

    pattern = re.compile(
        r"\n*" + re.escape(MARKER_BEGIN) + r".*?" + re.escape(MARKER_END) + r"\n*",
        re.DOTALL
    )

    updated_content = pattern.sub("\n", content).rstrip() + "\n"

    try:
        _atomic_write_hosts(updated_content)
        return True
    except Exception as e:
        raise PermissionError(f"Cannot write to /etc/hosts: {e}")

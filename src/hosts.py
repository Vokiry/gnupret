import re
import urllib.request
from pathlib import Path
from .config import BASE_DIR

HOSTS_PATH = Path("/etc/hosts")
LOCAL_HOSTS_FILE = BASE_DIR / ".service" / "hosts"
REMOTE_HOSTS_URL = "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/refs/heads/main/.service/hosts"

MARKER_BEGIN = "# --- GNUPRET DISCORD/TELEGRAM HOSTS BEGIN ---"
MARKER_END = "# --- GNUPRET DISCORD/TELEGRAM HOSTS END ---"


def fetch_latest_hosts() -> str:
    """Fetch the latest hosts content from the Flowseal repo or local fallback."""
    try:
        req = urllib.request.Request(REMOTE_HOSTS_URL, headers={"User-Agent": "gnupret"})
        with urllib.request.urlopen(req, timeout=5) as response:
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
    """Update or add gnupret block in /etc/hosts."""
    hosts_data = fetch_latest_hosts().strip()
    new_block = f"{MARKER_BEGIN}\n{hosts_data}\n{MARKER_END}\n"

    try:
        content = HOSTS_PATH.read_text(encoding="utf-8") if HOSTS_PATH.exists() else ""
    except Exception as e:
        raise PermissionError(f"Cannot read /etc/hosts (are you root?): {e}")

    pattern = re.compile(
        re.escape(MARKER_BEGIN) + r".*?" + re.escape(MARKER_END) + r"\n?",
        re.DOTALL
    )

    if pattern.search(content):
        updated_content = pattern.sub(new_block, content)
    else:
        updated_content = content.rstrip() + "\n\n" + new_block

    try:
        HOSTS_PATH.write_text(updated_content, encoding="utf-8")
        return True
    except Exception as e:
        raise PermissionError(f"Cannot write to /etc/hosts (are you root?): {e}")


def remove_hosts() -> bool:
    """Remove gnupret block from /etc/hosts."""
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
        HOSTS_PATH.write_text(updated_content, encoding="utf-8")
        return True
    except Exception as e:
        raise PermissionError(f"Cannot write to /etc/hosts: {e}")

import sys
import shutil
import subprocess
from pathlib import Path
from .config import BASE_DIR

SERVICE_NAME = "gnupret.service"
SERVICE_PATH = Path(f"/etc/systemd/system/{SERVICE_NAME}")


def is_systemd_available() -> bool:
    """Check if systemd is available and running on the system."""
    return shutil.which("systemctl") is not None and Path("/run/systemd/system").exists()


def get_service_status() -> dict:
    """Return status of systemd service."""
    if not is_systemd_available():
        return {"available": False, "installed": False, "active": False, "enabled": False, "output": "systemd not available"}

    installed = SERVICE_PATH.exists()
    active = False
    enabled = False
    output = ""

    if installed:
        try:
            res_act = subprocess.run(
                ["systemctl", "is-active", SERVICE_NAME],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )
            active = (res_act.stdout.strip() == "active")

            res_enb = subprocess.run(
                ["systemctl", "is-enabled", SERVICE_NAME],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )
            enabled = (res_enb.stdout.strip() == "enabled")

            res_stat = subprocess.run(
                ["systemctl", "status", SERVICE_NAME],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            output = res_stat.stdout
        except Exception as e:
            output = str(e)

    return {
        "available": True,
        "installed": installed,
        "active": active,
        "enabled": enabled,
        "output": output
    }


def install_service() -> bool:
    """Generate and install gnupret.service unit file."""
    if not is_systemd_available():
        raise RuntimeError("systemd is not available on this system.")

    python_bin = sys.executable
    gnupret_bin = BASE_DIR / "gnupret"

    unit_content = f"""[Unit]
Description=gnupret - Linux DPI bypass service for Discord and YouTube
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={BASE_DIR}
ExecStart={python_bin} {gnupret_bin} daemon
ExecStopPost={python_bin} {gnupret_bin} firewall-cleanup
Restart=always
RestartSec=3
KillMode=mixed
TimeoutStopSec=5

[Install]
WantedBy=multi-user.target
"""
    try:
        SERVICE_PATH.write_text(unit_content, encoding="utf-8")
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        return True
    except Exception as e:
        raise PermissionError(f"Failed to install systemd service: {e}")


def remove_service() -> bool:
    """Stop, disable and remove systemd service."""
    if not is_systemd_available():
        return True

    try:
        subprocess.run(["systemctl", "stop", SERVICE_NAME], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["systemctl", "disable", SERVICE_NAME], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if SERVICE_PATH.exists():
            SERVICE_PATH.unlink()
        subprocess.run(["systemctl", "daemon-reload"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception as e:
        raise PermissionError(f"Failed to remove systemd service: {e}")


def start_service() -> bool:
    res = subprocess.run(["systemctl", "start", SERVICE_NAME])
    return res.returncode == 0


def stop_service() -> bool:
    res = subprocess.run(["systemctl", "stop", SERVICE_NAME])
    return res.returncode == 0


def restart_service() -> bool:
    res = subprocess.run(["systemctl", "restart", SERVICE_NAME])
    return res.returncode == 0


def enable_service() -> bool:
    res = subprocess.run(["systemctl", "enable", SERVICE_NAME])
    return res.returncode == 0


def disable_service() -> bool:
    res = subprocess.run(["systemctl", "disable", SERVICE_NAME])
    return res.returncode == 0

import os
import signal
import sys
import time
import shutil
import platform
import tarfile
import urllib.request
import subprocess
from pathlib import Path
from typing import Optional, Tuple

from .config import BASE_DIR, BIN_DIR, PID_FILE, load_config
from .strategy import Strategy, get_strategy
from .firewall import FirewallManager


ZAPRET_RELEASE_TAG = "v72.13"
ZAPRET_TAR_URL = f"https://github.com/bol-van/zapret/releases/download/{ZAPRET_RELEASE_TAG}/zapret-{ZAPRET_RELEASE_TAG}.tar.gz"


def get_nfqws_path() -> Path:
    """Return path to nfqws binary, ensuring executable permissions."""
    path = BIN_DIR / "nfqws"
    if path.exists():
        path.chmod(0o755)
    return path


def ensure_nfqws_binary() -> bool:
    """Check if nfqws is present; download precompiled static binary if not."""
    nfqws_path = get_nfqws_path()
    if nfqws_path.exists():
        return True

    arch = platform.machine().lower()
    arch_map = {
        "x86_64": "linux-x86_64",
        "amd64": "linux-x86_64",
        "aarch64": "linux-arm64",
        "arm64": "linux-arm64",
        "armv7l": "linux-arm",
    }

    target_dir = arch_map.get(arch)
    if not target_dir:
        raise RuntimeError(f"Unsupported architecture for precompiled nfqws: {arch}")

    print(f"Downloading static nfqws ({arch}) from bol-van/zapret {ZAPRET_RELEASE_TAG}...")
    temp_archive = Path("/tmp/zapret.tar.gz")
    try:
        urllib.request.urlretrieve(ZAPRET_TAR_URL, temp_archive)
        with tarfile.open(temp_archive, "r:gz") as tar:
            target_path = f"zapret-{ZAPRET_RELEASE_TAG}/binaries/{target_dir}/nfqws"
            member = tar.getmember(target_path)
            f = tar.extractfile(member)
            if f:
                BIN_DIR.mkdir(parents=True, exist_ok=True)
                with open(nfqws_path, "wb") as out:
                    out.write(f.read())
                nfqws_path.chmod(0o755)
        print("nfqws downloaded and installed successfully.")
        return True
    except Exception as e:
        raise RuntimeError(f"Failed to download nfqws: {e}")
    finally:
        if temp_archive.exists():
            temp_archive.unlink()


def check_conflicts() -> list:
    """Check if other zapret or bypass services are running."""
    conflicts = []
    current_pid = None
    if PID_FILE.exists():
        try:
            current_pid = int(PID_FILE.read_text().strip())
        except Exception:
            pass

    try:
        out = subprocess.check_output(["pgrep", "-a", "nfqws"], text=True)
        for line in out.strip().splitlines():
            parts = line.split(maxsplit=1)
            if parts:
                pid = int(parts[0])
                if pid != current_pid:
                    conflicts.append(f"Another nfqws process is running (PID: {pid})")
    except subprocess.CalledProcessError:
        pass

    try:
        out = subprocess.check_output(["systemctl", "is-active", "zapret_discord_youtube.service"], text=True, stderr=subprocess.DEVNULL)
        if "active" in out:
            conflicts.append("zapret_discord_youtube.service (systemd) is active")
    except Exception:
        pass

    return conflicts


def get_running_status() -> Tuple[bool, Optional[int], Optional[str]]:
    """Return (is_running, pid, strategy_name)"""
    if not PID_FILE.exists():
        return False, None, None

    try:
        pid = int(PID_FILE.read_text().strip())
        # Check if process is alive and is nfqws
        os.kill(pid, 0)
        # Process exists
        try:
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().decode("utf-8", errors="ignore")
            if "nfqws" in cmdline:
                cfg = load_config()
                return True, pid, cfg.get("strategy", "Unknown")
        except Exception:
            pass
    except (OSError, ValueError):
        pass

    # Stale pid file
    try:
        PID_FILE.unlink()
    except Exception:
        pass
    return False, None, None


class Runner:
    def __init__(self, config: Optional[dict] = None):
        self.config = config or load_config()
        self.firewall = FirewallManager(self.config.get("firewall_backend", "auto"))
        self.nfqws_path = get_nfqws_path()

    def run_foreground(self, strategy: Strategy):
        """Run strategy in foreground, handling clean exit."""
        ensure_nfqws_binary()

        tcp_ports, udp_ports = strategy.get_firewall_ports(
            game_filter_mode=self.config.get("game_filter_mode", "disabled"),
            tcp_range=self.config.get("game_filter_tcp", "1024-65535"),
            udp_range=self.config.get("game_filter_udp", "1024-65535"),
        )

        qnum = int(self.config.get("qnum", 200))
        iface = self.config.get("interface", "auto")
        if iface == "auto":
            from .config import detect_default_interface
            iface = detect_default_interface()

        fwmark = self.config.get("fwmark", "0x40000000")

        args = strategy.build_nfqws_args(
            qnum=qnum,
            game_filter_mode=self.config.get("game_filter_mode", "disabled"),
            tcp_range=self.config.get("game_filter_tcp", "1024-65535"),
            udp_range=self.config.get("game_filter_udp", "1024-65535"),
        )

        print(f"Applying firewall rules for interface: {iface}...")
        self.firewall.setup(tcp_ports, udp_ports, interface=iface, qnum=qnum, fwmark=fwmark)

        proc = None
        try:
            cmd = [str(self.nfqws_path)] + args
            print(f"Starting nfqws (strategy: {strategy.name})...")
            print("Press Ctrl+C to stop.")
            proc = subprocess.Popen(cmd)
            proc.wait()
        except KeyboardInterrupt:
            print("\nStopping gnupret...")
        finally:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
            print("Cleaning up firewall rules...")
            self.firewall.teardown()
            print("gnupret stopped cleanly.")

    def start_background(self, strategy: Strategy) -> int:
        """Start nfqws as a background process and save PID."""
        ensure_nfqws_binary()

        is_running, pid, _ = get_running_status()
        if is_running:
            raise RuntimeError(f"gnupret is already running with PID {pid}")

        tcp_ports, udp_ports = strategy.get_firewall_ports(
            game_filter_mode=self.config.get("game_filter_mode", "disabled"),
            tcp_range=self.config.get("game_filter_tcp", "1024-65535"),
            udp_range=self.config.get("game_filter_udp", "1024-65535"),
        )

        qnum = int(self.config.get("qnum", 200))
        iface = self.config.get("interface", "auto")
        if iface == "auto":
            from .config import detect_default_interface
            iface = detect_default_interface()

        fwmark = self.config.get("fwmark", "0x40000000")

        args = strategy.build_nfqws_args(
            qnum=qnum,
            game_filter_mode=self.config.get("game_filter_mode", "disabled"),
            tcp_range=self.config.get("game_filter_tcp", "1024-65535"),
            udp_range=self.config.get("game_filter_udp", "1024-65535"),
        )

        self.firewall.setup(tcp_ports, udp_ports, interface=iface, qnum=qnum, fwmark=fwmark)

        cmd = [str(self.nfqws_path), "--daemon"] + args
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid
        )

        # Allow daemon fork
        time.sleep(0.3)

        # Look up spawned nfqws PID
        child_pid = None
        try:
            out = subprocess.check_output(["pgrep", "-n", "-f", f"{self.nfqws_path}.*--qnum.*{qnum}"], text=True)
            child_pid = int(out.strip())
        except Exception:
            child_pid = proc.pid

        PID_FILE.write_text(str(child_pid))
        return child_pid

    def stop_background(self) -> bool:
        """Stop background nfqws process and clean up firewall rules."""
        is_running, pid, _ = get_running_status()
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
                for _ in range(20):
                    time.sleep(0.1)
                    try:
                        os.kill(pid, 0)
                    except OSError:
                        break
                else:
                    os.kill(pid, signal.SIGKILL)
            except OSError:
                pass

        if PID_FILE.exists():
            try:
                PID_FILE.unlink()
            except Exception:
                pass

        self.firewall.teardown()
        return True

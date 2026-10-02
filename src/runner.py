import os
import signal
import sys
import time
import platform
import subprocess
from pathlib import Path
from typing import Optional, Tuple

from .config import BIN_DIR, PID_FILE, load_config
from .strategy import Strategy
from .firewall import FirewallManager


def get_nfqws_path() -> Path:
    """Return path to nfqws binary, ensuring executable permissions safely."""
    path = BIN_DIR / "nfqws"
    if path.exists() and not os.access(path, os.X_OK):
        try:
            path.chmod(0o755)
        except OSError:
            pass
    return path


def check_environment() -> None:
    """Validate that machine architecture is x86_64 and nfqws binary is present."""
    arch = platform.machine().lower()
    if arch not in ("x86_64", "amd64"):
        raise RuntimeError(
            f"gnupret is designed for x86_64 architecture (detected: {arch}).\n"
            "To run on this device, place a compatible nfqws binary into bin/nfqws."
        )

    nfqws_path = get_nfqws_path()
    if not nfqws_path.exists():
        raise FileNotFoundError(
            f"nfqws binary not found at {nfqws_path}.\n"
            "Please make sure bin/nfqws is present in the repository."
        )


def is_safe_nfqws_pid(pid: int) -> bool:
    """Verify that a given PID belongs to an active nfqws process before signaling."""
    if not pid or pid <= 1:
        return False
    try:
        comm_path = Path(f"/proc/{pid}/comm")
        if comm_path.exists():
            return comm_path.read_text(encoding="utf-8").strip() == "nfqws"
    except (OSError, PermissionError):
        pass
    try:
        cmdline_path = Path(f"/proc/{pid}/cmdline")
        if cmdline_path.exists():
            cmdline = cmdline_path.read_bytes().decode("utf-8", errors="ignore")
            return "nfqws" in cmdline
    except Exception:
        pass
    return False


def get_service_main_pid() -> Optional[int]:
    """Retrieve MainPID of gnupret.service via systemctl."""
    try:
        out = subprocess.check_output(
            ["systemctl", "show", "-p", "MainPID", "--value", "gnupret.service"],
            text=True,
            stderr=subprocess.DEVNULL
        ).strip()
        pid = int(out)
        return pid if pid > 0 else None
    except Exception:
        return None


def is_systemd_service_active() -> bool:
    """Check if gnupret.service is currently active in systemd."""
    try:
        res = subprocess.run(
            ["systemctl", "is-active", "--quiet", "gnupret.service"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return res.returncode == 0
    except Exception:
        return False


def check_conflicts() -> list:
    """Check if other zapret or bypass services are running, excluding our own."""
    conflicts = []

    # Get our known PIDs
    known_pids = set()
    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text().strip())
            if pid > 0:
                known_pids.add(pid)
        except Exception:
            pass

    srv_pid = get_service_main_pid()
    if srv_pid:
        known_pids.add(srv_pid)

    # Check for external nfqws processes
    try:
        out = subprocess.check_output(["pgrep", "-a", "nfqws"], text=True)
        for line in out.strip().splitlines():
            parts = line.split(maxsplit=1)
            if parts:
                pid = int(parts[0])
                if pid not in known_pids:
                    conflicts.append(f"Another nfqws process is running (PID: {pid})")
    except subprocess.CalledProcessError:
        pass

    # Check for legacy windows/zapret services
    try:
        out = subprocess.check_output(
            ["systemctl", "is-active", "zapret_discord_youtube.service"],
            text=True,
            stderr=subprocess.DEVNULL
        )
        if "active" in out:
            conflicts.append("zapret_discord_youtube.service (systemd) is active")
    except Exception:
        pass

    return conflicts


def get_running_status() -> Tuple[bool, Optional[int], Optional[str]]:
    """Return (is_running, pid, strategy_name) for standalone daemon or systemd."""
    # 1. Check systemd service first
    if is_systemd_service_active():
        srv_pid = get_service_main_pid()
        cfg = load_config()
        return True, srv_pid, cfg.get("strategy", "Unknown")

    # 2. Check standalone PID file
    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text().strip())
            if is_safe_nfqws_pid(pid):
                cfg = load_config()
                return True, pid, cfg.get("strategy", "Unknown")
        except Exception:
            pass

        # Stale PID file cleanup
        try:
            PID_FILE.unlink()
        except OSError:
            pass

    return False, None, None


class Runner:
    def __init__(self, config: Optional[dict] = None):
        self.config = config or load_config()
        self.firewall = FirewallManager(self.config.get("firewall_backend", "auto"))
        self.nfqws_path = get_nfqws_path()

    def run_foreground(self, strategy: Strategy):
        """Run strategy in foreground, handling clean exit and SIGTERM."""
        check_environment()

        tcp_ports, udp_ports = strategy.get_firewall_ports(
            game_filter_mode=self.config.get("game_filter_mode", "disabled"),
            tcp_range=self.config.get("game_filter_tcp", "1024-65535"),
            udp_range=self.config.get("game_filter_udp", "1024-65535"),
        )

        qnum = int(self.config.get("qnum", 200))
        iface = self.config.get("interface", "any")
        if iface == "auto":
            from .config import detect_default_interface
            iface = detect_default_interface()

        fwmark = self.config.get("fwmark", "0x40000000")

        args = strategy.build_nfqws_args(
            qnum=qnum,
            game_filter_mode=self.config.get("game_filter_mode", "disabled"),
            tcp_range=self.config.get("game_filter_tcp", "1024-65535"),
            udp_range=self.config.get("game_filter_udp", "1024-65535"),
            custom_fwmark=fwmark,
        )

        print(f"Applying firewall rules for interface: {iface}...")
        self.firewall.setup(tcp_ports, udp_ports, interface=iface, qnum=qnum, fwmark=fwmark)

        proc = None

        def sigterm_handler(signum, frame):
            sys.exit(0)

        prev_handler = signal.signal(signal.SIGTERM, sigterm_handler)

        try:
            cmd = [str(self.nfqws_path)] + args
            print(f"Starting nfqws (strategy: {strategy.name})...")
            print("Press Ctrl+C to stop.")
            proc = subprocess.Popen(cmd)
            proc.wait()
        except (KeyboardInterrupt, SystemExit):
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
            try:
                signal.signal(signal.SIGTERM, prev_handler)
            except Exception:
                pass

    def start_background(self, strategy: Strategy) -> int:
        """Start nfqws as a background daemon using native --pidfile."""
        check_environment()

        if is_systemd_service_active():
            raise RuntimeError("gnupret is already running as a systemd service.")

        is_running, pid, _ = get_running_status()
        if is_running:
            raise RuntimeError(f"gnupret is already running with PID {pid}")

        tcp_ports, udp_ports = strategy.get_firewall_ports(
            game_filter_mode=self.config.get("game_filter_mode", "disabled"),
            tcp_range=self.config.get("game_filter_tcp", "1024-65535"),
            udp_range=self.config.get("game_filter_udp", "1024-65535"),
        )

        qnum = int(self.config.get("qnum", 200))
        iface = self.config.get("interface", "any")
        if iface == "auto":
            from .config import detect_default_interface
            iface = detect_default_interface()

        fwmark = self.config.get("fwmark", "0x40000000")

        args = strategy.build_nfqws_args(
            qnum=qnum,
            game_filter_mode=self.config.get("game_filter_mode", "disabled"),
            tcp_range=self.config.get("game_filter_tcp", "1024-65535"),
            udp_range=self.config.get("game_filter_udp", "1024-65535"),
            custom_fwmark=fwmark,
        )

        self.firewall.setup(tcp_ports, udp_ports, interface=iface, qnum=qnum, fwmark=fwmark)

        if PID_FILE.exists():
            try:
                PID_FILE.unlink()
            except OSError:
                pass

        cmd = [
            str(self.nfqws_path),
            "--daemon",
            f"--pidfile={PID_FILE}"
        ] + args

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )

        # Wait for nfqws to fork and write PID file
        child_pid = None
        for _ in range(30):
            time.sleep(0.04)
            if PID_FILE.exists():
                try:
                    p = int(PID_FILE.read_text().strip())
                    if p > 0 and is_safe_nfqws_pid(p):
                        child_pid = p
                        break
                except Exception:
                    pass

        if not child_pid:
            ret = proc.poll()
            self.firewall.teardown()
            if PID_FILE.exists():
                try:
                    PID_FILE.unlink()
                except OSError:
                    pass
            raise RuntimeError(f"nfqws failed to start (exit code: {ret if ret is not None else 'unknown'})")

        return child_pid

    def stop_background(self) -> bool:
        """Stop background nfqws process safely and clean up firewall rules."""
        if PID_FILE.exists():
            try:
                pid = int(PID_FILE.read_text().strip())
                if is_safe_nfqws_pid(pid):
                    os.kill(pid, signal.SIGTERM)
                    for _ in range(25):
                        time.sleep(0.08)
                        try:
                            os.kill(pid, 0)
                        except OSError:
                            break
                    else:
                        if is_safe_nfqws_pid(pid):
                            os.kill(pid, signal.SIGKILL)
            except Exception:
                pass
            finally:
                try:
                    PID_FILE.unlink()
                except OSError:
                    pass

        self.firewall.teardown()
        return True

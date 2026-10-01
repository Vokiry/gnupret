import re
import shlex
from pathlib import Path
from typing import Dict, List, Optional
from .config import BASE_DIR, BIN_DIR, LISTS_DIR, ensure_user_lists

STRATEGIES_DIR = BASE_DIR / "strategies"


class Strategy:
    def __init__(
        self,
        strategy_id: str,
        name: str,
        filename: str,
        raw_tcp: str,
        raw_udp: str,
        raw_args: str
    ):
        self.id = strategy_id
        self.name = name
        self.filename = filename
        self.raw_tcp = raw_tcp
        self.raw_udp = raw_udp
        self.raw_args = raw_args

    def get_firewall_ports(self, game_filter_mode: str = "disabled", tcp_range="1024-65535", udp_range="1024-65535"):
        """Extract TCP and UDP ports needed for the firewall."""
        tcp_val = self.raw_tcp
        udp_val = self.raw_udp

        use_tcp = game_filter_mode in ("all", "tcp")
        use_udp = game_filter_mode in ("all", "udp")

        tcp_val = tcp_val.replace("%GameFilterTCP%", tcp_range if use_tcp else "")
        tcp_val = tcp_val.replace("%GameFilter%", tcp_range if use_tcp else "")
        udp_val = udp_val.replace("%GameFilterUDP%", udp_range if use_udp else "")
        udp_val = udp_val.replace("%GameFilter%", udp_range if use_udp else "")

        # Clean up empty commas
        tcp_ports = [p.strip() for p in re.split(r",+", tcp_val) if p.strip() and p.strip() != "12"]
        udp_ports = [p.strip() for p in re.split(r",+", udp_val) if p.strip() and p.strip() != "12"]

        return tcp_ports, udp_ports

    def build_nfqws_args(
        self,
        qnum: int = 200,
        game_filter_mode: str = "disabled",
        tcp_range="1024-65535",
        udp_range="1024-65535",
        custom_fwmark: Optional[str] = None
    ) -> List[str]:
        """Build the complete argument list for nfqws."""
        ensure_user_lists()

        use_tcp = game_filter_mode in ("all", "tcp")
        use_udp = game_filter_mode in ("all", "udp")

        content = self.raw_args
        content = content.replace("%BIN%", str(BIN_DIR) + "/")
        content = content.replace("%LISTS%", str(LISTS_DIR) + "/")

        # Replace GameFilter variables
        content = content.replace("%GameFilterTCP%", tcp_range if use_tcp else "12")
        content = content.replace("%GameFilterUDP%", udp_range if use_udp else "12")
        content = content.replace("%GameFilter%", (tcp_range if use_tcp else "12"))

        # Fix batch escaped exclamation marks for nfqws
        content = content.replace("^!", "!")

        args = shlex.split(content)
        cmd = ["--qnum", str(qnum)]
        if custom_fwmark:
            cmd.extend(["--dpi-desync-fwmark", str(custom_fwmark)])
        cmd.extend(args)
        return cmd


def _natural_sort_key(file_path: Path):
    name = file_path.name.lower()
    if name == "general.bat":
        return (0, 0, "")
    if " (alt).bat" in name:
        return (1, 1, "")
    m = re.search(r"\(alt(\d+)\)\.bat", name)
    if m:
        return (1, int(m.group(1)), "")
    return (2, 0, name)


def parse_bat_file(file_path: Path) -> Optional[Strategy]:
    """Parse a Flowseal .bat strategy file."""
    if not file_path.exists():
        return None

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return None

    # Merge multiline commands separated by ^
    content = re.sub(r"\^\s*[\r\n]+", " ", content)

    # Locate the winws execution line
    winws_match = re.search(r'winws(?:\.exe)?[\"\'\s]+(.*?)(?:\r?\n|$)', content, re.IGNORECASE)
    if not winws_match:
        return None

    raw_args = winws_match.group(1).strip()

    # Extract --wf-tcp and --wf-udp
    tcp_match = re.search(r"--wf-tcp=([^\s]+)", raw_args)
    udp_match = re.search(r"--wf-udp=([^\s]+)", raw_args)

    raw_tcp = tcp_match.group(1) if tcp_match else "80,443,2053,2083,2087,2096,8443"
    raw_udp = udp_match.group(1) if udp_match else "443,19294-19344,50000-50100"

    # Remove wf-tcp and wf-udp from args
    cleaned_args = re.sub(r"--wf-(?:tcp|udp)=[^\s]+", "", raw_args).strip()

    filename = file_path.name
    # Generate friendly name and ID
    if filename.lower() == "general.bat":
        strategy_id = "general"
        name = "Default (general)"
    else:
        # e.g. "general (ALT2).bat" -> "ALT2"
        match = re.search(r"general\s*\((.*?)\)\.bat", filename, re.IGNORECASE)
        if match:
            clean_name = match.group(1).strip()
            name = clean_name
            strategy_id = clean_name.lower().replace(" ", "_")
        else:
            name = file_path.stem
            strategy_id = file_path.stem.lower().replace(" ", "_")

    return Strategy(
        strategy_id=strategy_id,
        name=name,
        filename=filename,
        raw_tcp=raw_tcp,
        raw_udp=raw_udp,
        raw_args=cleaned_args
    )


def list_strategies(base_dir: Path = BASE_DIR) -> Dict[str, Strategy]:
    """Find and parse all available strategies."""
    strategies: Dict[str, Strategy] = {}
    search_dir = STRATEGIES_DIR if STRATEGIES_DIR.exists() and any(STRATEGIES_DIR.glob("*.bat")) else base_dir
    bat_files = sorted(search_dir.glob("general*.bat"), key=_natural_sort_key)

    for p in bat_files:
        strat = parse_bat_file(p)
        if strat:
            strategies[strat.id] = strat

    return strategies


def get_strategy(strategy_query: str, base_dir: Path = BASE_DIR) -> Optional[Strategy]:
    """Find a strategy by ID, filename, or display name."""
    strats = list_strategies(base_dir)
    query_lower = strategy_query.strip().lower()

    # Exact ID match
    if query_lower in strats:
        return strats[query_lower]

    # Filename match
    for s in strats.values():
        if s.filename.lower() == query_lower:
            return s

    # Name match
    for s in strats.values():
        if s.name.lower() == query_lower or query_lower in s.name.lower():
            return s

    return None

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

        for key in ("%GameFilterTCP%", "{GAME_FILTER_TCP}", "%GameFilter%"):
            tcp_val = tcp_val.replace(key, tcp_range if use_tcp else "")
        for key in ("%GameFilterUDP%", "{GAME_FILTER_UDP}", "%GameFilter%"):
            udp_val = udp_val.replace(key, udp_range if use_udp else "")

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
        # Replace paths
        content = content.replace("{BIN}", str(BIN_DIR))
        content = content.replace("{LISTS}", str(LISTS_DIR))
        content = content.replace("%BIN%", str(BIN_DIR) + "/")
        content = content.replace("%LISTS%", str(LISTS_DIR) + "/")

        # Replace GameFilter variables
        for key in ("%GameFilterTCP%", "{GAME_FILTER_TCP}", "%GameFilter%"):
            content = content.replace(key, tcp_range if use_tcp else "12")
        for key in ("%GameFilterUDP%", "{GAME_FILTER_UDP}"):
            content = content.replace(key, udp_range if use_udp else "12")

        # Fix batch escaped exclamation marks for nfqws
        content = content.replace("^!", "!")

        try:
            args = shlex.split(content)
        except ValueError as e:
            raise ValueError(f"Malformed arguments in strategy '{self.name}': {e}")

        cmd = ["--qnum", str(qnum)]
        if custom_fwmark:
            cmd.extend(["--dpi-desync-fwmark", str(custom_fwmark)])
        cmd.extend(args)
        return cmd


def _natural_sort_key(file_path: Path):
    stem = file_path.stem.lower()
    if stem in ("general", "default"):
        return (0, 0, "")
    if stem == "alt":
        return (1, 1, "")
    m = re.match(r"^alt(\d+)$", stem)
    if m:
        return (1, int(m.group(1)), "")
    return (2, 0, stem)


def parse_conf_file(file_path: Path) -> Optional[Strategy]:
    """Parse a native gnupret .conf strategy file."""
    if not file_path.exists():
        return None

    try:
        content = file_path.read_text(encoding="utf-8")
    except Exception:
        return None

    name = file_path.stem.upper()
    raw_tcp = "80,443,2053,2083,2087,2096,8443,{GAME_FILTER_TCP}"
    raw_udp = "443,19294-19344,50000-50100,{GAME_FILTER_UDP}"
    arg_lines = []

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("NAME="):
            name = line.split("=", 1)[1].strip()
        elif line.startswith("TCP_PORTS="):
            raw_tcp = line.split("=", 1)[1].strip()
        elif line.startswith("UDP_PORTS="):
            raw_udp = line.split("=", 1)[1].strip()
        else:
            arg_lines.append(line)

    raw_args = " ".join(arg_lines)
    strategy_id = file_path.stem.lower()

    return Strategy(
        strategy_id=strategy_id,
        name=name,
        filename=file_path.name,
        raw_tcp=raw_tcp,
        raw_udp=raw_udp,
        raw_args=raw_args
    )


def list_strategies(base_dir: Path = BASE_DIR) -> Dict[str, Strategy]:
    """Find and parse all available strategies in strategies/ directory."""
    strategies: Dict[str, Strategy] = {}
    search_dir = STRATEGIES_DIR if STRATEGIES_DIR.exists() else base_dir

    conf_files = sorted(search_dir.glob("*.conf"), key=_natural_sort_key)
    for p in conf_files:
        strat = parse_conf_file(p)
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

    # Common aliases: alt1 -> alt
    if query_lower in ("alt1", "alt-1", "alt_1") and "alt" in strats:
        return strats["alt"]

    # Without extension match
    stem = Path(query_lower).stem
    if stem in strats:
        return strats[stem]
    if stem in ("alt1", "alt-1", "alt_1") and "alt" in strats:
        return strats["alt"]

    # Filename match
    for s in strats.values():
        if s.filename.lower() == query_lower:
            return s

    # Exact Name match (case-insensitive)
    for s in strats.values():
        if s.name.lower() == query_lower:
            return s

    # Word boundary match (e.g. "ALT" won't match "ALT10")
    for s in strats.values():
        pattern = rf"\b{re.escape(query_lower)}\b"
        if re.search(pattern, s.name, re.IGNORECASE):
            return s

    # Fallback substring match
    for s in strats.values():
        if query_lower in s.name.lower():
            return s

    return None

import shutil
import subprocess
from typing import List


def format_and_chunk_ports(ports: List[str], max_weight: int = 15) -> List[str]:
    """
    Format port ranges ('-' to ':') for iptables multiport and chunk them
    taking weight into account: single port = 1, port range = 2, max weight <= 15.
    """
    chunks = []
    current_chunk = []
    current_weight = 0

    for p in ports:
        formatted = p.replace("-", ":")
        weight = 2 if ":" in formatted else 1
        if current_weight + weight > max_weight:
            if current_chunk:
                chunks.append(",".join(current_chunk))
            current_chunk = [formatted]
            current_weight = weight
        else:
            current_chunk.append(formatted)
            current_weight += weight

    if current_chunk:
        chunks.append(",".join(current_chunk))
    return chunks


class FirewallManager:
    TABLE_NAME = "gnupret"
    IPTABLES_CHAIN_POST = "GNUPRET_POST"
    IPTABLES_CHAIN_PRE = "GNUPRET_PRE"

    def __init__(self, backend: str = "auto"):
        self.backend = self._detect_backend(backend)

    def _detect_backend(self, backend: str) -> str:
        if backend in ("nftables", "nft") and shutil.which("nft"):
            return "nftables"
        if backend == "iptables" and shutil.which("iptables"):
            return "iptables"
        # Auto detect: prefer nftables
        if shutil.which("nft"):
            return "nftables"
        if shutil.which("iptables"):
            return "iptables"
        raise RuntimeError("Neither nftables nor iptables was found on this system.")

    def setup(
        self,
        tcp_ports: List[str],
        udp_ports: List[str],
        interface: str = "any",
        qnum: int = 200,
        fwmark: str = "0x40000000",
    ) -> bool:
        """Apply firewall rules directing traffic to NFQUEUE."""
        # Ensure nf_conntrack module is loaded
        try:
            subprocess.run(
                ["modprobe", "nf_conntrack"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False
            )
        except Exception:
            pass

        # Enable liberal conntrack for DPI RST desync handling
        try:
            subprocess.run(
                ["sysctl", "-w", "net.netfilter.nf_conntrack_tcp_be_liberal=1"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False
            )
        except Exception:
            pass

        # Ensure clean slate first
        self.teardown()

        try:
            if self.backend == "nftables":
                return self._setup_nftables(tcp_ports, udp_ports, interface, qnum, fwmark)
            else:
                return self._setup_iptables(tcp_ports, udp_ports, interface, qnum, fwmark)
        except Exception:
            # Self-healing: if setup fails halfway, rollback to avoid dangling rules
            self.teardown()
            raise

    def teardown(self) -> bool:
        """Remove all gnupret firewall rules."""
        if self.backend == "nftables":
            return self._teardown_nftables()
        else:
            return self._teardown_iptables()

    def is_active(self) -> bool:
        """Check if gnupret firewall rules are currently loaded."""
        if self.backend == "nftables":
            try:
                res = subprocess.run(
                    ["nft", "list", "table", "inet", self.TABLE_NAME],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                return res.returncode == 0
            except Exception:
                return False
        else:
            try:
                res = subprocess.run(
                    ["iptables", "-t", "mangle", "-L", self.IPTABLES_CHAIN_POST],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                return res.returncode == 0
            except Exception:
                return False

    def _setup_nftables(
        self,
        tcp_ports: List[str],
        udp_ports: List[str],
        interface: str,
        qnum: int,
        fwmark: str,
    ) -> bool:
        if interface and interface not in ("any", "*"):
            out_iface = f'oifname "{interface}" '
            in_iface = f'iifname "{interface}" '
        else:
            out_iface = 'oifname != "lo" '
            in_iface = 'iifname != "lo" '

        tcp_str = ", ".join(tcp_ports) if tcp_ports else ""
        udp_str = ", ".join(udp_ports) if udp_ports else ""

        rules = [
            f"table inet {self.TABLE_NAME} {{",
            "    chain post {",
            "        type filter hook postrouting priority mangle; policy accept;",
        ]

        if tcp_str:
            rules.append(
                f"        {out_iface}meta mark & {fwmark} == 0x00000000 tcp dport {{ {tcp_str} }} ct original packets 1-12 queue flags bypass to {qnum}"
            )
        if udp_str:
            rules.append(
                f"        {out_iface}meta mark & {fwmark} == 0x00000000 udp dport {{ {udp_str} }} queue flags bypass to {qnum}"
            )

        rules.extend([
            "    }",
            "    chain pre {",
            "        type filter hook prerouting priority filter; policy accept;",
        ])

        if tcp_str:
            rules.append(
                f"        {in_iface}tcp sport {{ {tcp_str} }} ct reply packets 1-3 queue flags bypass to {qnum}"
            )

        rules.extend([
            "    }",
            "}",
        ])

        nft_script = "\n".join(rules) + "\n"

        proc = subprocess.run(
            ["nft", "-f", "-"],
            input=nft_script,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        if proc.returncode != 0:
            raise RuntimeError(f"Failed to apply nftables rules: {proc.stderr.strip()}")
        return True

    def _teardown_nftables(self) -> bool:
        subprocess.run(
            ["nft", "delete", "table", "inet", self.TABLE_NAME],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return True

    def _setup_iptables(
        self,
        tcp_ports: List[str],
        udp_ports: List[str],
        interface: str,
        qnum: int,
        fwmark: str,
    ) -> bool:
        iface_out_opt = ["-o", interface] if interface and interface not in ("any", "*") else ["!", "-o", "lo"]
        iface_in_opt = ["-i", interface] if interface and interface not in ("any", "*") else ["!", "-i", "lo"]

        binaries = ["iptables"]
        if shutil.which("ip6tables"):
            binaries.append("ip6tables")

        tcp_chunks = format_and_chunk_ports(tcp_ports)
        udp_chunks = format_and_chunk_ports(udp_ports)

        for ipt in binaries:
            # Create chains
            subprocess.run([ipt, "-t", "mangle", "-N", self.IPTABLES_CHAIN_POST], stderr=subprocess.DEVNULL)
            subprocess.run([ipt, "-t", "mangle", "-N", self.IPTABLES_CHAIN_PRE], stderr=subprocess.DEVNULL)

            # Hook chains at head of mangle POSTROUTING and PREROUTING
            subprocess.run([ipt, "-t", "mangle", "-I", "POSTROUTING", "1", "-j", self.IPTABLES_CHAIN_POST], check=True)
            subprocess.run([ipt, "-t", "mangle", "-I", "PREROUTING", "1", "-j", self.IPTABLES_CHAIN_PRE], check=True)

            # Add rules to POST chain (matches come before target -j NFQUEUE)
            for chunk in tcp_chunks:
                cmd = (
                    [ipt, "-t", "mangle", "-A", self.IPTABLES_CHAIN_POST, "-p", "tcp"]
                    + iface_out_opt
                    + [
                        "-m", "multiport", "--dports", chunk,
                        "-m", "mark", "!", "--mark", f"{fwmark}/{fwmark}",
                        "-m", "connbytes", "--connbytes-dir", "original", "--connbytes-mode", "packets", "--connbytes", "1:12",
                        "-j", "NFQUEUE", "--queue-num", str(qnum), "--queue-bypass"
                    ]
                )
                subprocess.run(cmd, check=True)

            for chunk in udp_chunks:
                cmd = (
                    [ipt, "-t", "mangle", "-A", self.IPTABLES_CHAIN_POST, "-p", "udp"]
                    + iface_out_opt
                    + [
                        "-m", "multiport", "--dports", chunk,
                        "-m", "mark", "!", "--mark", f"{fwmark}/{fwmark}",
                        "-j", "NFQUEUE", "--queue-num", str(qnum), "--queue-bypass"
                    ]
                )
                subprocess.run(cmd, check=True)

            # Add rules to PRE chain
            for chunk in tcp_chunks:
                cmd = (
                    [ipt, "-t", "mangle", "-A", self.IPTABLES_CHAIN_PRE, "-p", "tcp"]
                    + iface_in_opt
                    + [
                        "-m", "multiport", "--sports", chunk,
                        "-m", "connbytes", "--connbytes-dir", "reply", "--connbytes-mode", "packets", "--connbytes", "1:3",
                        "-j", "NFQUEUE", "--queue-num", str(qnum), "--queue-bypass"
                    ]
                )
                subprocess.run(cmd, check=True)

        return True

    def _teardown_iptables(self) -> bool:
        binaries = ["iptables"]
        if shutil.which("ip6tables"):
            binaries.append("ip6tables")

        for ipt in binaries:
            # Repeatedly remove jump rules until none remain (handles duplicate hooks)
            while True:
                res = subprocess.run(
                    [ipt, "-t", "mangle", "-D", "POSTROUTING", "-j", self.IPTABLES_CHAIN_POST],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                if res.returncode != 0:
                    break

            while True:
                res = subprocess.run(
                    [ipt, "-t", "mangle", "-D", "PREROUTING", "-j", self.IPTABLES_CHAIN_PRE],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                if res.returncode != 0:
                    break

            # Flush and delete chains
            subprocess.run([ipt, "-t", "mangle", "-F", self.IPTABLES_CHAIN_POST], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run([ipt, "-t", "mangle", "-X", self.IPTABLES_CHAIN_POST], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run([ipt, "-t", "mangle", "-F", self.IPTABLES_CHAIN_PRE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run([ipt, "-t", "mangle", "-X", self.IPTABLES_CHAIN_PRE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        return True

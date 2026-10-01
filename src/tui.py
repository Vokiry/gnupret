import os
import sys
import time
import shutil
import urllib.request
from typing import Dict, List

from .config import (
    BASE_DIR,
    LISTS_DIR,
    load_config,
    save_config,
    get_ipset_status,
    set_ipset_mode,
    detect_default_interface,
    update_upstream_lists
)
from .strategy import Strategy, list_strategies, get_strategy
from .firewall import FirewallManager
from .runner import Runner, get_running_status, check_conflicts, get_nfqws_path
from .systemd import (
    is_systemd_available,
    get_service_status,
    install_service,
    remove_service,
    start_service,
    stop_service,
    restart_service
)
from .hosts import get_hosts_status, update_hosts, remove_hosts
from .tester import run_target_tests, parse_targets


# ANSI Colors
CLR_RESET = "\033[0m"
CLR_BOLD = "\033[1m"
CLR_RED = "\033[91m"
CLR_GREEN = "\033[92m"
CLR_YELLOW = "\033[93m"
CLR_BLUE = "\033[94m"
CLR_CYAN = "\033[96m"


def clear_screen():
    os.system("clear" if os.name == "posix" else "cls")


def print_banner(cfg: dict, active_strategy: Strategy):
    is_running, pid, _ = get_running_status()
    srv_status = get_service_status()

    status_str = f"{CLR_GREEN}RUNNING (PID: {pid}){CLR_RESET}" if is_running else f"{CLR_RED}STOPPED{CLR_RESET}"

    if srv_status.get("installed"):
        if srv_status.get("active"):
            srv_str = f"{CLR_GREEN}Active & {'Enabled' if srv_status.get('enabled') else 'Disabled'}{CLR_RESET}"
        else:
            srv_str = f"{CLR_YELLOW}Inactive ({'Enabled' if srv_status.get('enabled') else 'Disabled'}){CLR_RESET}"
    else:
        srv_str = f"{CLR_RESET}Not installed{CLR_RESET}"

    game_mode = cfg.get("game_filter_mode", "disabled")
    ipset_mode = get_ipset_status()
    iface = cfg.get("interface", "auto")

    print(f"{CLR_CYAN}{CLR_BOLD}============================================================{CLR_RESET}")
    print(f"             {CLR_BOLD}GNUPRET SERVICE MANAGER (Linux){CLR_RESET}")
    print(f"   Strategy:    {CLR_YELLOW}{active_strategy.name}{CLR_RESET} ({active_strategy.filename})")
    print(f"   Process:     {status_str}")
    print(f"   Systemd:     {srv_str}")
    print(f"   Game Filter: {game_mode.upper()} [TCP/UDP 1024-65535]")
    print(f"   IPSet Mode:  {ipset_mode.upper()} (lists/ipset-all.txt)")
    print(f"   Interface:   {iface}")
    print(f"{CLR_CYAN}{CLR_BOLD}============================================================{CLR_RESET}")


def menu_select_strategy(cfg: dict) -> Strategy:
    clear_screen()
    strategies = list_strategies()
    print(f"\n{CLR_BOLD}Choose a Strategy:{CLR_RESET}\n")

    strat_list = list(strategies.values())
    for idx, strat in enumerate(strat_list, start=1):
        is_cur = " (current)" if strat.filename == cfg.get("strategy") else ""
        print(f"  {idx:2d}. {strat.name:<25} {CLR_CYAN}[{strat.filename}]{CLR_RESET}{is_cur}")

    print("\n   0. Cancel\n")
    try:
        choice = input("  Select strategy number: ").strip()
        if choice in ("0", ""):
            return get_strategy(cfg.get("strategy", "general.bat")) or strat_list[0]
        c_int = int(choice)
        if 1 <= c_int <= len(strat_list):
            selected = strat_list[c_int - 1]
            cfg["strategy"] = selected.filename
            save_config(cfg)
            print(f"\n{CLR_GREEN}Switched strategy to: {selected.name}{CLR_RESET}")
            time.sleep(1)
            return selected
    except Exception:
        pass
    return get_strategy(cfg.get("strategy", "general.bat")) or strat_list[0]


def menu_toggle_game_filter(cfg: dict):
    modes = ["disabled", "all", "tcp", "udp"]
    cur = cfg.get("game_filter_mode", "disabled")
    try:
        idx = modes.index(cur)
        next_mode = modes[(idx + 1) % len(modes)]
    except ValueError:
        next_mode = "disabled"
    cfg["game_filter_mode"] = next_mode
    save_config(cfg)
    print(f"\n{CLR_GREEN}Game Filter set to: {next_mode.upper()}{CLR_RESET}")
    time.sleep(0.8)


def menu_toggle_ipset(cfg: dict):
    cur = get_ipset_status()
    # Cycle: loaded -> none -> any -> loaded
    order = ["loaded", "none", "any"]
    try:
        next_mode = order[(order.index(cur) + 1) % len(order)]
    except ValueError:
        next_mode = "loaded"
    set_ipset_mode(next_mode)
    print(f"\n{CLR_GREEN}IPSet mode changed to: {next_mode.upper()}{CLR_RESET}")
    time.sleep(0.8)


def menu_run_tests():
    clear_screen()
    print(f"\n{CLR_BOLD}Running target connectivity tests...{CLR_RESET}\n")
    results = run_target_tests()
    print(f"{'Target':<24} | {'Status':<10} | {'Latency':<10} | {'Details'}")
    print("-" * 65)
    for name, ok, lat, detail in results:
        status_disp = f"{CLR_GREEN}OK{CLR_RESET}" if ok else f"{CLR_RED}FAIL{CLR_RESET}"
        lat_disp = f"{lat:6.1f}ms" if lat > 0 else "   -- "
        print(f"{name:<24} | {status_disp:<19} | {lat_disp:<10} | {detail}")
    print("\nPress Enter to continue...")
    input()


def menu_benchmark_all_strategies(cfg: dict):
    clear_screen()
    print(f"\n{CLR_BOLD}Auto-Benchmarking Strategies against YouTube & Discord...{CLR_RESET}")
    print("Testing each strategy for ~3 seconds. Please wait...\n")

    runner = Runner(cfg)
    strategies = list_strategies()
    # Filter core targets to check
    all_targets = parse_targets()
    test_targets = {
        k: all_targets[k]
        for k in ["YouTubeWeb", "DiscordMain", "DiscordGateway"]
        if k in all_targets
    }

    results_table = []

    for s_name, strat in strategies.items():
        print(f"Testing {strat.name:<24} ... ", end="", flush=True)
        try:
            # Stop any existing
            runner.stop_background()
            runner.start_background(strat)
            time.sleep(0.8)

            t_res = run_target_tests(test_targets, max_workers=3)
            yt_ok = any(r[1] for r in t_res if "YouTube" in r[0])
            dc_ok = any(r[1] for r in t_res if "Discord" in r[0])
            avg_lat = sum(r[2] for r in t_res if r[1]) / (sum(1 for r in t_res if r[1]) or 1)

            res_str = []
            if yt_ok:
                res_str.append("YT: OK")
            if dc_ok:
                res_str.append("DC: OK")

            summary = ", ".join(res_str) if res_str else "BLOCKED"
            print(f"{summary} ({avg_lat:.0f}ms)")
            results_table.append((strat.name, strat.filename, yt_ok, dc_ok, avg_lat))
        except Exception as e:
            print(f"ERR: {e}")
        finally:
            runner.stop_background()

    clear_screen()
    print(f"\n{CLR_BOLD}=== Benchmark Results ==={CLR_RESET}\n")
    print(f"{'Strategy':<25} | {'YouTube':<10} | {'Discord':<10} | {'Avg Latency'}")
    print("-" * 65)
    for s_name, s_file, yt, dc, lat in results_table:
        yt_disp = f"{CLR_GREEN}OK{CLR_RESET}" if yt else f"{CLR_RED}FAIL{CLR_RESET}"
        dc_disp = f"{CLR_GREEN}OK{CLR_RESET}" if dc else f"{CLR_RED}FAIL{CLR_RESET}"
        lat_disp = f"{lat:6.1f}ms" if (yt or dc) else "   -- "
        print(f"{s_name:<25} | {yt_disp:<19} | {dc_disp:<19} | {lat_disp}")

    print("\nPress Enter to return to menu...")
    input()


def menu_update_hosts():
    clear_screen()
    print(f"\n{CLR_BOLD}Updating /etc/hosts for Discord Voice & Telegram...{CLR_RESET}\n")
    try:
        update_hosts()
        st = get_hosts_status()
        print(f"{CLR_GREEN}Successfully updated /etc/hosts ({st.get('lines_count')} records loaded){CLR_RESET}")
    except Exception as e:
        print(f"{CLR_RED}Error: {e}{CLR_RESET}")
    print("\nPress Enter to continue...")
    input()


def menu_diagnostics(cfg: dict):
    clear_screen()
    print(f"\n{CLR_BOLD}=== gnupret Diagnostics ==={CLR_RESET}\n")

    # 1. Root check
    is_root = os.geteuid() == 0
    print(f"Root privileges:       {CLR_GREEN}YES{CLR_RESET}" if is_root else f"Root privileges:       {CLR_RED}NO (Run with sudo!){CLR_RESET}")

    # 2. nfqws binary
    nfqws = get_nfqws_path()
    nfqws_ok = nfqws.exists() and os.access(nfqws, os.X_OK)
    print(f"nfqws binary:          {CLR_GREEN}Found ({nfqws}){CLR_RESET}" if nfqws_ok else f"nfqws binary:          {CLR_RED}Missing{CLR_RESET}")

    # 3. Firewall backend
    fw = FirewallManager()
    print(f"Firewall backend:      {CLR_GREEN}{fw.backend}{CLR_RESET}")
    print(f"Firewall active table: {CLR_GREEN}YES{CLR_RESET}" if fw.is_active() else f"Firewall active table: {CLR_YELLOW}NO (idle){CLR_RESET}")

    # 4. Conflicts check
    conflicts = check_conflicts()
    if conflicts:
        print(f"\n{CLR_YELLOW}Warning: Potential conflicts detected:{CLR_RESET}")
        for c in conflicts:
            print(f"  - {c}")
    else:
        print(f"Process conflicts:     {CLR_GREEN}None detected{CLR_RESET}")

    # 5. Hosts status
    hst = get_hosts_status()
    print(f"Custom /etc/hosts:     {CLR_GREEN}Active ({hst['lines_count']} records){CLR_RESET}" if hst["installed"] else "Custom /etc/hosts:     Not installed")

    # 6. Default route
    iface = detect_default_interface()
    print(f"Default route dev:     {CLR_GREEN}{iface}{CLR_RESET}")

    print("\nPress Enter to continue...")
    input()


def interactive_menu():
    """Main interactive TUI loop."""
    if os.geteuid() != 0:
        print(f"{CLR_RED}Error: gnupret requires root privileges for Netfilter manipulation.{CLR_RESET}")
        print("Please run with sudo: sudo gnupret")
        sys.exit(1)

    while True:
        cfg = load_config()
        strat = get_strategy(cfg.get("strategy", "general.bat")) or list_strategies().get("general")
        clear_screen()
        print_banner(cfg, strat)

        is_running, _, _ = get_running_status()
        srv_status = get_service_status()

        print("  :: CONTROLS")
        print("     1. Run in Console (Foreground test mode with live logs)")
        if is_running:
            print(f"     2. {CLR_RED}Stop Background Process{CLR_RESET}")
        else:
            print(f"     2. {CLR_GREEN}Start Background Process{CLR_RESET}")
        print("     3. Select Strategy")
        print()
        print("  :: SERVICE (systemd)")
        if srv_status.get("installed"):
            print("     4. Reinstall / Enable Service")
            print("     5. Remove / Disable Service")
            print("     6. Restart Service")
        else:
            print("     4. Install Systemd Service")
            print("     5. Remove Service")
            print("     6. Service not installed")
        print()
        print("  :: SETTINGS")
        print(f"     7. Game Filter Toggle   [{cfg.get('game_filter_mode', 'disabled').upper()}]")
        print(f"     8. IPSet Filter Toggle  [{get_ipset_status().upper()}]")
        print()
        print("  :: TOOLS & UPDATES")
        print("     9. Run Target Tests (YouTube, Discord, etc.)")
        print("     10. Auto-Benchmark All Strategies (Find best)")
        print("     11. Update /etc/hosts (Discord Voice & Telegram)")
        print("     12. Update IPSet & Hostlists from GitHub")
        print("     13. Run Diagnostics")
        print()
        print("  ----------------------------------------------------------")
        print("     0. Exit")
        print()

        try:
            choice = input("  Select option (0-13): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting...")
            break

        runner = Runner(cfg)

        if choice == "0":
            break
        elif choice == "1":
            clear_screen()
            runner.run_foreground(strat)
            print("\nPress Enter to return to menu...")
            input()
        elif choice == "2":
            if is_running:
                runner.stop_background()
                print(f"{CLR_GREEN}Background process stopped.{CLR_RESET}")
            else:
                try:
                    pid = runner.start_background(strat)
                    print(f"{CLR_GREEN}Started background process with PID {pid}.{CLR_RESET}")
                except Exception as e:
                    print(f"{CLR_RED}Failed to start: {e}{CLR_RESET}")
            time.sleep(1)
        elif choice == "3":
            menu_select_strategy(cfg)
        elif choice == "4":
            try:
                install_service()
                enable_service()
                start_service()
                print(f"\n{CLR_GREEN}Service installed, enabled, and started!{CLR_RESET}")
            except Exception as e:
                print(f"\n{CLR_RED}Error: {e}{CLR_RESET}")
            time.sleep(1.5)
        elif choice == "5":
            try:
                remove_service()
                print(f"\n{CLR_GREEN}Service stopped and removed.{CLR_RESET}")
            except Exception as e:
                print(f"\n{CLR_RED}Error: {e}{CLR_RESET}")
            time.sleep(1.5)
        elif choice == "6":
            if srv_status.get("installed"):
                restart_service()
                print(f"\n{CLR_GREEN}Service restarted.{CLR_RESET}")
            time.sleep(1)
        elif choice == "7":
            menu_toggle_game_filter(cfg)
        elif choice == "8":
            menu_toggle_ipset(cfg)
        elif choice == "9":
            menu_run_tests()
        elif choice == "10":
            menu_benchmark_all_strategies(cfg)
        elif choice == "11":
            menu_update_hosts()
        elif choice == "12":
            clear_screen()
            print(f"\n{CLR_BOLD}Updating IPSet and domain lists from Flowseal repository...{CLR_RESET}\n")
            try:
                update_upstream_lists()
                print(f"{CLR_GREEN}Lists successfully updated!{CLR_RESET}")
            except Exception as e:
                print(f"{CLR_RED}Update failed: {e}{CLR_RESET}")
            print("\nPress Enter to continue...")
            input()
        elif choice == "13":
            menu_diagnostics(cfg)

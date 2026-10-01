import os
import sys
import argparse
from pathlib import Path

from .config import (
    BASE_DIR,
    load_config,
    save_config,
    get_ipset_status,
    set_ipset_mode,
)
from .strategy import list_strategies, get_strategy
from .firewall import FirewallManager
from .runner import Runner, get_running_status, check_conflicts, get_nfqws_path
from .systemd import (
    get_service_status,
    install_service,
    remove_service,
    start_service,
    stop_service,
    restart_service,
    enable_service,
    disable_service,
)
from .hosts import update_hosts, remove_hosts, get_hosts_status
from .tester import run_target_tests
from .tui import interactive_menu


def check_root():
    if os.geteuid() != 0:
        print("Error: This operation requires root privileges.")
        print("Please run with sudo: sudo gnupret <command>")
        sys.exit(1)


def cmd_list(args):
    strategies = list_strategies()
    cfg = load_config()
    cur = cfg.get("strategy")
    print("\nAvailable strategies:\n")
    for s in strategies.values():
        is_cur = " * (active)" if s.filename == cur else ""
        print(f"  {s.id:<20} {s.name:<25} [{s.filename}]{is_cur}")
    print()


def cmd_select(args):
    strat = get_strategy(args.strategy)
    if not strat:
        print(f"Error: Strategy '{args.strategy}' not found.")
        print("Use 'gnupret list' to see available strategies.")
        sys.exit(1)
    cfg = load_config()
    cfg["strategy"] = strat.filename
    save_config(cfg)
    print(f"Selected strategy: {strat.name} ({strat.filename})")


def cmd_run(args):
    check_root()
    cfg = load_config()
    strat_query = args.strategy or cfg.get("strategy", "general.bat")
    strat = get_strategy(strat_query)
    if not strat:
        print(f"Error: Strategy '{strat_query}' not found.")
        sys.exit(1)
    runner = Runner(cfg)
    runner.run_foreground(strat)


def cmd_start(args):
    check_root()
    cfg = load_config()
    strat_query = args.strategy or cfg.get("strategy", "general.bat")
    strat = get_strategy(strat_query)
    if not strat:
        print(f"Error: Strategy '{strat_query}' not found.")
        sys.exit(1)
    runner = Runner(cfg)
    try:
        pid = runner.start_background(strat)
        print(f"Started gnupret with strategy '{strat.name}' (PID: {pid})")
    except Exception as e:
        print(f"Failed to start: {e}")
        sys.exit(1)


def cmd_stop(args):
    check_root()
    runner = Runner()
    runner.stop_background()
    print("gnupret background process and firewall rules stopped.")


def cmd_status(args):
    is_running, pid, strat_name = get_running_status()
    cfg = load_config()
    fw = FirewallManager()
    srv = get_service_status()

    print("\n=== gnupret Status ===")
    print(f"  Process:        {'RUNNING (PID: ' + str(pid) + ')' if is_running else 'STOPPED'}")
    print(f"  Active Config:  {strat_name or cfg.get('strategy')}")
    print(f"  Firewall Table: {'ACTIVE' if fw.is_active() else 'INACTIVE'}")
    print(f"  Game Filter:    {cfg.get('game_filter_mode', 'disabled').upper()}")
    print(f"  IPSet Mode:     {get_ipset_status().upper()}")
    if srv.get("installed"):
        print(f"  Systemd Unit:   {'ACTIVE' if srv.get('active') else 'INACTIVE'} ({'ENABLED' if srv.get('enabled') else 'DISABLED'})")
    else:
        print("  Systemd Unit:   Not installed")

    conflicts = check_conflicts()
    if conflicts:
        print("\n  Warnings / Potential conflicts:")
        for c in conflicts:
            print(f"    - {c}")
    print()


def cmd_test(args):
    print("Testing targets availability...\n")
    results = run_target_tests()
    for name, ok, lat, detail in results:
        status_str = "OK" if ok else "FAIL"
        print(f"  {name:<22} : {status_str:<4} ({lat:5.1f}ms) - {detail}")
    print()


def cmd_service(args):
    check_root()
    action = args.action
    if action == "install":
        install_service()
        enable_service()
        print("Installed and enabled gnupret.service")
    elif action == "remove":
        remove_service()
        print("Stopped, disabled and removed gnupret.service")
    elif action == "start":
        start_service()
        print("Started gnupret.service")
    elif action == "stop":
        stop_service()
        print("Stopped gnupret.service")
    elif action == "restart":
        restart_service()
        print("Restarted gnupret.service")
    elif action == "status":
        st = get_service_status()
        print(st.get("output", "Service not installed"))


def cmd_game_filter(args):
    mode = args.mode.lower()
    if mode not in ("disabled", "all", "tcp", "udp"):
        print("Invalid mode. Options: disabled, all, tcp, udp")
        sys.exit(1)
    cfg = load_config()
    cfg["game_filter_mode"] = mode
    save_config(cfg)
    print(f"Game filter set to: {mode.upper()}")


def cmd_ipset(args):
    mode = args.mode.lower()
    if mode not in ("loaded", "none", "any"):
        print("Invalid mode. Options: loaded, none, any")
        sys.exit(1)
    if set_ipset_mode(mode):
        print(f"IPSet filter set to: {mode.upper()}")
    else:
        print("Failed to change IPSet mode.")


def cmd_hosts(args):
    check_root()
    if args.action == "update":
        update_hosts()
        st = get_hosts_status()
        print(f"Updated /etc/hosts ({st.get('lines_count')} records)")
    elif args.action == "remove":
        remove_hosts()
        print("Removed custom hosts from /etc/hosts")


def cmd_daemon(args):
    """Entry point for systemd service ExecStart."""
    check_root()
    cfg = load_config()
    strat = get_strategy(cfg.get("strategy", "general.bat"))
    if not strat:
        print("Strategy not found, cannot run daemon.")
        sys.exit(1)
    runner = Runner(cfg)
    runner.run_foreground(strat)


def cmd_firewall_cleanup(args):
    """Entry point for systemd ExecStopPost or emergency cleanup."""
    check_root()
    fw = FirewallManager()
    fw.teardown()


def main():
    parser = argparse.ArgumentParser(
        prog="gnupret",
        description="gnupret - Linux adapter for zapret Discord & YouTube bypass",
    )
    subparsers = parser.add_subparsers(dest="command")

    # run
    p_run = subparsers.add_parser("run", help="Run strategy in foreground (console test mode)")
    p_run.add_argument("strategy", nargs="?", help="Strategy name or ID (optional)")
    p_run.set_defaults(func=cmd_run)

    # start
    p_start = subparsers.add_parser("start", help="Start strategy in background")
    p_start.add_argument("strategy", nargs="?", help="Strategy name or ID (optional)")
    p_start.set_defaults(func=cmd_start)

    # stop
    p_stop = subparsers.add_parser("stop", help="Stop background running strategy and firewall")
    p_stop.set_defaults(func=cmd_stop)

    # status
    p_status = subparsers.add_parser("status", help="Show current status")
    p_status.set_defaults(func=cmd_status)

    # list
    p_list = subparsers.add_parser("list", help="List available strategies")
    p_list.set_defaults(func=cmd_list)

    # select
    p_select = subparsers.add_parser("select", help="Select default strategy")
    p_select.add_argument("strategy", help="Strategy name or ID")
    p_select.set_defaults(func=cmd_select)

    # test
    p_test = subparsers.add_parser("test", help="Test connectivity to Discord, YouTube, Google")
    p_test.set_defaults(func=cmd_test)

    # service
    p_service = subparsers.add_parser("service", help="Manage systemd service")
    p_service.add_argument("action", choices=["install", "remove", "start", "stop", "restart", "status"])
    p_service.set_defaults(func=cmd_service)

    # game-filter
    p_gf = subparsers.add_parser("game-filter", help="Configure Game Filter")
    p_gf.add_argument("mode", choices=["disabled", "all", "tcp", "udp"])
    p_gf.set_defaults(func=cmd_game_filter)

    # ipset
    p_ipset = subparsers.add_parser("ipset", help="Configure IPSet mode")
    p_ipset.add_argument("mode", choices=["loaded", "none", "any"])
    p_ipset.set_defaults(func=cmd_ipset)

    # hosts
    p_hosts = subparsers.add_parser("hosts", help="Manage /etc/hosts updates")
    p_hosts.add_argument("action", choices=["update", "remove"])
    p_hosts.set_defaults(func=cmd_hosts)

    # daemon / internal
    p_daemon = subparsers.add_parser("daemon", help=argparse.SUPPRESS)
    p_daemon.set_defaults(func=cmd_daemon)

    p_clean = subparsers.add_parser("firewall-cleanup", help=argparse.SUPPRESS)
    p_clean.set_defaults(func=cmd_firewall_cleanup)

    args = parser.parse_args()

    if not args.command:
        # Launch interactive TUI menu
        interactive_menu()
    else:
        args.func(args)


if __name__ == "__main__":
    main()

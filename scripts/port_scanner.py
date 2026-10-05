#!/usr/bin/env python3
"""Safe, local-only TCP port scanner for a home lab.

ETHICS / AUTHORIZATION
----------------------
Scanning hosts you do not own or are not explicitly authorized to test is illegal
in many jurisdictions. This script therefore *refuses* to scan anything that is not
loopback or RFC1918 private space, unless you pass --i-am-authorized AND the target
is still private. There is no flag to scan the public internet. Use it only on your
own lab machines.
"""
from __future__ import annotations

import argparse
import ipaddress
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

# A few common service ports, with friendly names for the report.
COMMON_SERVICES = {
    22: "ssh", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    143: "imap", 443: "https", 445: "smb", 3306: "mysql",
    5432: "postgres", 6379: "redis", 8080: "http-alt",
}


def is_private(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
    except (ValueError, socket.gaierror):
        return False
    return any(ip in net for net in PRIVATE_NETS)


def parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


def scan_port(host: str, port: int, timeout: float) -> tuple[int, bool]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return port, sock.connect_ex((host, port)) == 0


def scan(host: str, ports: list[int], timeout: float, workers: int) -> list[int]:
    open_ports: list[int] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(scan_port, host, p, timeout) for p in ports]
        for fut in as_completed(futures):
            port, is_open = fut.result()
            if is_open:
                open_ports.append(port)
    return sorted(open_ports)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local-only TCP port scanner (lab use).")
    parser.add_argument("host", help="Target host (must resolve to loopback/private IP).")
    parser.add_argument("-p", "--ports", default="1-1024", help="Ports, e.g. '22,80,443' or '1-1024'.")
    parser.add_argument("-t", "--timeout", type=float, default=0.3, help="Per-port timeout seconds.")
    parser.add_argument("-w", "--workers", type=int, default=100, help="Concurrent connections.")
    parser.add_argument("--i-am-authorized", action="store_true",
                        help="Affirm you own/are authorized to scan this private host.")
    args = parser.parse_args(argv)

    if not is_private(args.host):
        print(f"REFUSED: '{args.host}' is not loopback/private. This tool only scans lab hosts.",
              file=sys.stderr)
        return 2
    if not args.i_am_authorized:
        print("REFUSED: pass --i-am-authorized to confirm this is your own lab host.",
              file=sys.stderr)
        return 2

    ports = parse_ports(args.ports)
    print(f"Scanning {args.host} ({len(ports)} ports)...")
    open_ports = scan(args.host, ports, args.timeout, args.workers)
    if not open_ports:
        print("No open ports found.")
    for port in open_ports:
        print(f"  {port:>5}/tcp  open   {COMMON_SERVICES.get(port, 'unknown')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

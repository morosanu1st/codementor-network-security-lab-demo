#!/usr/bin/env python3
"""IPv4 CIDR / subnet calculator and splitter.

Examples:
  python subnet_calc.py 192.168.1.0/24
  python subnet_calc.py 10.0.0.0/16 --split 4
  python subnet_calc.py 172.16.5.37/22 --contains 172.16.4.10
"""
from __future__ import annotations

import argparse
import ipaddress


def host_range(net: ipaddress.IPv4Network) -> tuple[int, str, str]:
    """Usable host count and first/last host without materializing the list."""
    if net.prefixlen == 32:
        return 1, str(net.network_address), str(net.network_address)
    if net.prefixlen == 31:  # RFC 3021 point-to-point links: both addresses usable
        return 2, str(net.network_address), str(net.broadcast_address)
    return net.num_addresses - 2, str(net.network_address + 1), str(net.broadcast_address - 1)


def describe(net: ipaddress.IPv4Network) -> str:
    count, first, last = host_range(net)
    return "\n".join([
        f"Network:        {net.network_address}",
        f"Prefix:         /{net.prefixlen}",
        f"Netmask:        {net.netmask}",
        f"Wildcard:       {net.hostmask}",
        f"Broadcast:      {net.broadcast_address}",
        f"Total addrs:    {net.num_addresses}",
        f"Usable hosts:   {count}  ({first} - {last})",
        f"Private range:  {'yes' if net.is_private else 'no'}",
    ])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CIDR/subnet calculator.")
    parser.add_argument("cidr", help="Network in CIDR, e.g. 192.168.1.0/24")
    parser.add_argument("--split", type=int, metavar="N",
                        help="Split into N equal-ish subnets (next power of two).")
    parser.add_argument("--contains", metavar="IP", help="Check if an IP is inside the network.")
    args = parser.parse_args(argv)

    net = ipaddress.IPv4Network(args.cidr, strict=False)
    print(describe(net))

    if args.contains:
        ip = ipaddress.IPv4Address(args.contains)
        print(f"\n{ip} in {net}? {'yes' if ip in net else 'no'}")

    if args.split:
        bits = max(0, (args.split - 1)).bit_length()
        new_prefix = net.prefixlen + bits
        print(f"\nSplit into {2 ** bits} subnets (/{new_prefix}):")
        for sub in net.subnets(new_prefix=new_prefix):
            print(f"  {sub}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Summarize network flows from a CSV export (e.g. a firewall/NetFlow log).

Expected columns: timestamp,src_ip,src_port,dst_ip,dst_port,protocol,bytes,packets
Produces: top talkers, top destination ports, protocol breakdown, and a crude
"beaconing" heuristic (many small connections at a *regular interval* to the same
destination ip:port, the classic C2 call-home pattern) and a
port-scan heuristic (one source touching many distinct ports on one host).
"""
from __future__ import annotations

import argparse
import csv
import statistics
from collections import Counter, defaultdict
from datetime import datetime


def load_flows(path: str) -> list[dict]:
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))


def summarize(flows: list[dict]) -> dict:
    bytes_by_src: Counter[str] = Counter()
    conns_by_src: Counter[str] = Counter()
    ports: Counter[str] = Counter()
    protos: Counter[str] = Counter()
    pair_counts: Counter[tuple[str, str]] = Counter()
    pair_bytes: defaultdict[tuple[str, str], int] = defaultdict(int)
    pair_ports: defaultdict[tuple[str, str], set[str]] = defaultdict(set)
    service_times: defaultdict[tuple[str, str, str], list[datetime]] = defaultdict(list)
    service_bytes: defaultdict[tuple[str, str, str], int] = defaultdict(int)

    for row in flows:
        src = row["src_ip"]
        dst = row["dst_ip"]
        nbytes = int(row.get("bytes", 0) or 0)
        bytes_by_src[src] += nbytes
        conns_by_src[src] += 1
        ports[row["dst_port"]] += 1
        protos[row["protocol"].upper()] += 1
        pair = (src, dst)
        pair_counts[pair] += 1
        pair_bytes[pair] += nbytes
        pair_ports[pair].add(row["dst_port"])
        svc = (src, dst, row["dst_port"])
        service_times[svc].append(datetime.fromisoformat(row["timestamp"]))
        service_bytes[svc] += nbytes

    # Beaconing heuristic: >= 5 small connections to the same ip:port whose
    # inter-arrival times are very regular (coefficient of variation < 0.25).
    beaconing = []
    for (s, d, port), times in service_times.items():
        if len(times) < 5:
            continue
        avg_bytes = service_bytes[(s, d, port)] // len(times)
        times.sort()
        gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
        mean_gap = statistics.mean(gaps)
        if mean_gap <= 0 or avg_bytes >= 500:
            continue
        cv = statistics.pstdev(gaps) / mean_gap
        if cv < 0.25:
            beaconing.append({"src": s, "dst": f"{d}:{port}", "count": len(times),
                              "avg_bytes": avg_bytes, "interval_s": round(mean_gap, 1)})
    beaconing.sort(key=lambda x: x["count"], reverse=True)

    # Port-scan heuristic: one source hitting >= 10 distinct ports on one host.
    scans = [
        {"src": s, "dst": d, "distinct_ports": len(p)}
        for (s, d), p in pair_ports.items()
        if len(p) >= 10
    ]

    return {
        "total_flows": len(flows),
        "top_talkers": bytes_by_src.most_common(5),
        "top_ports": ports.most_common(5),
        "protocols": dict(protos),
        "beaconing_suspects": beaconing,
        "scan_suspects": scans,
    }


def render(summary: dict) -> str:
    lines = [f"Total flows: {summary['total_flows']}", "", "Top talkers (by bytes):"]
    for ip, nbytes in summary["top_talkers"]:
        lines.append(f"  {ip:<16} {nbytes:>10} bytes")
    lines += ["", "Top destination ports:"]
    for port, count in summary["top_ports"]:
        lines.append(f"  port {port:<6} {count} flows")
    lines += ["", "Protocol breakdown:"]
    for proto, count in sorted(summary["protocols"].items()):
        lines.append(f"  {proto:<6} {count}")
    lines += ["", "Possible beaconing (small, regular-interval connections):"]
    if summary["beaconing_suspects"]:
        for b in summary["beaconing_suspects"]:
            lines.append(f"  {b['src']} -> {b['dst']}  {b['count']} conns every ~{b['interval_s']}s, avg {b['avg_bytes']} bytes")
    else:
        lines.append("  none detected")
    lines += ["", "Possible port scans (many distinct ports on one host):"]
    if summary["scan_suspects"]:
        for sc in summary["scan_suspects"]:
            lines.append(f"  {sc['src']} -> {sc['dst']}  {sc['distinct_ports']} distinct ports")
    else:
        lines.append("  none detected")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize flows from a CSV log.")
    parser.add_argument("csv_path", help="Path to the flow CSV.")
    args = parser.parse_args(argv)
    print(render(summarize(load_flows(args.csv_path))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

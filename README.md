# Network Security Lab Demo (Defensive / Ethical)

A small, **local-only** network security lab for learning how networks are
discovered, monitored and defended: Python tools you can read end-to-end, a
segmented Docker lab with a firewall router, and a lab-report template.

> Built by **Mihai Chindriș** (software engineer and Codementor tutor) as a
> reference for 1:1 network-security tutoring sessions.

## ⚠️ Ethics and authorization

- Only scan, capture or test systems **you own or have written permission to test**.
  Unauthorized scanning can be illegal (e.g. the Computer Fraud and Abuse Act in the US,
  Computer Misuse Act in the UK, Directive 2013/40/EU in the EU) and against your ISP's
  or university's terms.
- The port scanner in this repo **refuses** non-private targets (anything outside
  loopback / RFC 1918) and requires an explicit `--i-am-authorized` flag even then.
- The Docker lab networks are `internal: true`: containers cannot reach the internet or
  your home LAN.
- The goal is understanding and defense: detecting scans, writing firewall rules,
  documenting findings. It is not about attacking real systems.

## What's inside

| Path | Purpose |
|------|---------|
| `scripts/port_scanner.py` | Threaded TCP-connect scanner, restricted to loopback/private IPs, with an authorization gate. |
| `scripts/flow_parser.py` | Summarizes a flow CSV: top talkers, top ports, protocol mix, **beaconing** (regular-interval small connections) and **port-scan** detection. |
| `scripts/subnet_calc.py` | IPv4 CIDR calculator: netmask, wildcard, broadcast, usable range, `--contains`, `--split N`. |
| `data/sample_flows.csv` | 82 synthetic flows containing normal web/DNS/SSH traffic, a 60-second C2-style beacon and a 14-port sweep. |
| `lab/docker-compose.yml` | Segmented lab: `attacker` ⇄ `router` ⇄ `victim` on two isolated networks. |
| `lab/configs/router-firewall.sh` | Default-deny iptables FORWARD policy with stateful allow rules and drop logging. |
| `templates/lab-report-template.md` | Objectives, topology, method, findings, mitigations. |
| `tests/test_lab_tools.py` | 11 unit tests (stdlib `unittest`). |

## Quick start (Python 3.9+, no dependencies)

```bash
python3 -m unittest discover -s tests -v

python3 scripts/subnet_calc.py 172.16.5.37/22 --contains 172.16.4.10 --split 4
python3 scripts/flow_parser.py data/sample_flows.csv

# start something to find, then scan your own machine
python3 -m http.server 8765 --bind 127.0.0.1 &
python3 scripts/port_scanner.py 127.0.0.1 -p 8700-8800 --i-am-authorized
```

Sample `flow_parser.py` output (excerpt):

```
Possible beaconing (small, regular-interval connections):
  10.10.20.10 -> 10.10.10.66:4444  12 conns every ~60.0s, avg 150 bytes

Possible port scans (many distinct ports on one host):
  10.10.10.5 -> 10.10.20.10  14 distinct ports
```

## The Docker lab

```
attacker 10.10.10.5 ── attacker_net 10.10.10.0/24 ── router (.254 | .254) ── victim_net 10.10.20.0/24 ── victim 10.10.20.10 (nginx)
```

```bash
cd lab
docker compose up -d --build
docker compose exec router sh            # iptables -L FORWARD -n -v ; tcpdump -i any -nn
docker compose exec attacker sh          # nmap -sT -p 1-1024 10.10.20.10 ; curl -I http://10.10.20.10
docker compose down -v
```

The router starts with **default-deny forwarding** and only allows new TCP/80
connections from the attacker segment to the victim (plus rate-limited ping).
Exercises: open SSH only from one host, add logging, then confirm the change with a
re-scan and a capture.

## Concepts covered

**Wireshark / tcpdump**
- Capture on the router: `tcpdump -i any -nn -w /tmp/lab.pcap`, then open the pcap in Wireshark.
- Useful display filters: `tcp.flags.syn==1 && tcp.flags.ack==0` (connection attempts),
  `tcp.flags.reset==1`, `ip.addr==10.10.20.10`, `http.request`, `dns`.
- Statistics → Conversations / Endpoints / Protocol Hierarchy: the GUI version of `flow_parser.py`.
- Follow TCP Stream to see what actually went over the wire.

**nmap (in the lab only)**
- `-sT` connect scan vs `-sS` SYN scan; `-sV` service detection; `-p-` all ports; `-Pn`.
- Reading results: *open* (SYN/ACK), *closed* (RST), *filtered* (no reply / ICMP unreachable),
  and how each looks in the capture.

**Firewall rules (iptables / nftables concepts)**
- Default-deny, stateful `ESTABLISHED,RELATED` accept, explicit allow lists, rule order,
  logging before drop, rate limits.
- INPUT vs FORWARD vs OUTPUT chains; why the lab rules live in FORWARD.

**Detection basics**
- Port sweeps (many ports, one source, short time) and beaconing (regular small
  call-homes) — both implemented in `flow_parser.py` so the logic is visible.

## How I'd help you in 1:1 sessions

**Session 1: Foundations and lab setup (60 min)**
- OSI/TCP-IP refresher with real packets: the TCP handshake, DNS, HTTP.
- Subnetting drills with `subnet_calc.py`; design the lab addressing plan together.
- Get the Docker lab running on your machine (or a VM if you prefer VirtualBox/GNS3).

**Session 2: Seeing traffic (60 min)**
- Capture on the router, analyze in Wireshark, build filters, follow streams.
- Compare Wireshark Conversations with `flow_parser.py` output.

**Session 3: Discovery and defense (60 min)**
- Scan the victim from the attacker segment, interpret open/closed/filtered.
- Write and test firewall rules; prove each change with a re-scan + capture.

**Session 4: Detection and reporting (60 min)**
- Extend the detectors (e.g. DNS tunneling heuristics, failed-login bursts).
- Write a short lab report with the template: findings, evidence, mitigations.

Throughout: I explain the "why", you drive the keyboard, and every exercise stays
inside the isolated lab. Coursework is used as a learning guide; I help you
understand it rather than do graded work for you.

## License

MIT, see [LICENSE](LICENSE).

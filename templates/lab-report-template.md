# Lab Report: <exercise title>

| Field | Value |
|-------|-------|
| Date | YYYY-MM-DD |
| Author | <your name> |
| Lab environment | `lab/docker-compose.yml` (isolated, no internet) |
| Authorization | Self-owned lab only. No third-party systems were touched. |

## 1. Objectives
- What question does this exercise answer? (e.g. "Which services on the victim are reachable from the attacker segment, and does the router policy match the intended design?")
- Success criteria:

## 2. Topology
```
attacker 10.10.10.5 --- [attacker_net 10.10.10.0/24] --- router (.254/.254) --- [victim_net 10.10.20.0/24] --- victim 10.10.20.10
```
- Addressing plan (`python scripts/subnet_calc.py 10.10.0.0/16 --split 4`):
- Firewall policy in place (paste `iptables -L FORWARD -n -v`):

## 3. Method
| Step | Command / tool | Purpose |
|------|----------------|---------|
| 1 | `tcpdump -i any -w /tmp/cap.pcap` on router | Capture evidence |
| 2 | `nmap -sT -p 1-1024 10.10.20.10` from attacker | Service discovery |
| 3 | `curl -I http://10.10.20.10` | Verify allowed service |
| 4 | Open pcap in Wireshark, filter `tcp.flags.syn==1 && tcp.flags.ack==0` | Inspect handshake attempts |

## 4. Findings
| # | Finding | Evidence (command output / pcap frame / screenshot) | Severity |
|---|---------|------------------------------------------------------|----------|
| F1 | | | Low / Med / High |
| F2 | | | |

## 5. Analysis
- What does the traffic show? (SYN → SYN/ACK = open, SYN → RST = closed, SYN → nothing = filtered)
- Does the observed exposure match the intended policy? Where does it differ and why?

## 6. Mitigations / Recommendations
| Finding | Mitigation | Verified? (how) |
|---------|------------|-----------------|
| F1 | e.g. restrict FORWARD rule to tcp/80 only | re-scan shows only 80 open |

## 7. Lessons learned
-

## 8. Appendix
- Raw outputs, pcap filenames, rule diffs.

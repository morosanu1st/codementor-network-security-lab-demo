#!/bin/sh
# Router firewall for the lab. Default-deny forwarding, then allow only what the
# exercise needs. Edit and re-run inside the router container:
#   docker compose exec router sh /router-firewall.sh
set -e

ATTACKER_NET=10.10.10.0/24
VICTIM=10.10.20.10

iptables -F FORWARD
iptables -P FORWARD DROP

# Allow replies for connections that were already permitted.
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Exercise 1: only HTTP from the attacker segment to the victim web server.
iptables -A FORWARD -s "$ATTACKER_NET" -d "$VICTIM" -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT

# Allow ping for connectivity tests (rate limited).
iptables -A FORWARD -p icmp --icmp-type echo-request -m limit --limit 5/second -j ACCEPT

# Log everything else that gets dropped (view with: dmesg or tcpdump on the router).
iptables -A FORWARD -m limit --limit 10/min -j LOG --log-prefix "LAB-DROP: "

echo "Firewall loaded:"
iptables -L FORWARD -n -v --line-numbers

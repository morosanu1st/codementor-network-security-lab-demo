FROM alpine:3.20
RUN apk add --no-cache nmap nmap-scripts tcpdump curl iproute2 bind-tools
CMD ["sh", "-c", "ip route replace 10.10.20.0/24 via 10.10.10.254 && tail -f /dev/null"]

FROM alpine:3.20
RUN apk add --no-cache iptables tcpdump iproute2
CMD ["sh", "-c", "sh /router-firewall.sh && tail -f /dev/null"]

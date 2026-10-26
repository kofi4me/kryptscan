#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="${KRYPTSCAN_SCANNER_CONTAINER:-kryptnet-scanner}"
CHAIN="KRYPTSCAN-EGRESS"
CHAIN6="KRYPTSCAN-EGRESS6"

for _ in $(seq 1 30); do
  if docker inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

network_name="$(
  docker inspect \
    --format '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}' \
    "$CONTAINER_NAME" | head -n 1
)"

if [[ -z "$network_name" ]]; then
  echo "ERROR: unable to identify the Docker network for $CONTAINER_NAME" >&2
  exit 1
fi

network_subnets="$(
  docker network inspect \
    --format '{{range .IPAM.Config}}{{println .Subnet}}{{end}}' \
    "$network_name"
)"
ipv4_subnet="$(printf '%s\n' "$network_subnets" | awk '/\./ {print; exit}')"
ipv6_subnet="$(printf '%s\n' "$network_subnets" | awk '/:/ {print; exit}')"

if [[ -z "$ipv4_subnet" ]]; then
  echo "ERROR: unable to identify the IPv4 subnet for Docker network $network_name" >&2
  exit 1
fi

iptables -w -N "$CHAIN" 2>/dev/null || true
iptables -w -F "$CHAIN"
iptables -w -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

for destination in \
  0.0.0.0/8 \
  10.0.0.0/8 \
  100.64.0.0/10 \
  127.0.0.0/8 \
  169.254.0.0/16 \
  172.16.0.0/12 \
  192.0.0.0/24 \
  192.0.2.0/24 \
  192.168.0.0/16 \
  198.18.0.0/15 \
  198.51.100.0/24 \
  203.0.113.0/24 \
  224.0.0.0/4 \
  240.0.0.0/4; do
  iptables -w -A "$CHAIN" -d "$destination" -j REJECT
done
iptables -w -A "$CHAIN" -j RETURN

while rule_number="$(iptables -w -L DOCKER-USER --line-numbers -n | awk -v chain="$CHAIN" '$2 == chain {print $1; exit}')" \
  && [[ -n "$rule_number" ]]; do
  iptables -w -D DOCKER-USER "$rule_number"
done
iptables -w -I DOCKER-USER 1 -s "$ipv4_subnet" -j "$CHAIN"

if [[ -n "$ipv6_subnet" ]] && command -v ip6tables >/dev/null 2>&1; then
  ip6tables -w -N "$CHAIN6" 2>/dev/null || true
  ip6tables -w -F "$CHAIN6"
  ip6tables -w -A "$CHAIN6" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  for destination in \
    ::/128 \
    ::1/128 \
    fc00::/7 \
    fe80::/10 \
    ff00::/8 \
    2001:db8::/32; do
    ip6tables -w -A "$CHAIN6" -d "$destination" -j REJECT
  done
  ip6tables -w -A "$CHAIN6" -j RETURN
  while rule_number="$(ip6tables -w -L DOCKER-USER --line-numbers -n | awk -v chain="$CHAIN6" '$2 == chain {print $1; exit}')" \
    && [[ -n "$rule_number" ]]; do
    ip6tables -w -D DOCKER-USER "$rule_number"
  done
  ip6tables -w -I DOCKER-USER 1 -s "$ipv6_subnet" -j "$CHAIN6"
fi

logger -t kryptscan-egress \
  "restricted scanner container=$CONTAINER_NAME network=$network_name subnet=$ipv4_subnet"
echo "KryptScan scanner egress isolation active for $ipv4_subnet."

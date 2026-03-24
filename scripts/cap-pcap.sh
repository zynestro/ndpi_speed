#!/usr/bin/env bash
set -euo pipefail

# Fast synthetic capture for nDPI:
# - finishes in a few minutes (bounded by CAPTURE_SEC)
# - keeps protocol mix (Easy/Mid/Hard)
# - avoids long hangs on network failures
#
# Example:
#   CAPTURE_SEC=120 MAX_PKTS=12000 PROFILE=encrypted_heavy ./scripts/cap-pcap.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Output PCAP path (can override via env)
OUTPUT="${OUTPUT:-$ROOT_DIR/input/cap_traffic_fast.pcap}"
# Interface to capture on, default any for convenience
IFACE="${IFACE:-any}"
# Hard stop by wall-clock seconds
CAPTURE_SEC="${CAPTURE_SEC:-180}"
# Hard stop by packet count
MAX_PKTS="${MAX_PKTS:-30000}"
# Snapshot length (smaller = smaller file, but less payload)
SNAPLEN="${SNAPLEN:-128}"

# Traffic volume knobs.
# Default to encrypted-heavy profile so TLS/SSH占比更高。
# PROFILE choices:
#   - encrypted_heavy (default): prioritize TLS/SSH/CONNECT traffic
#   - balanced: more even Easy/Mid/Hard mix
PROFILE="${PROFILE:-encrypted_heavy}"
if [[ "${PROFILE}" == "balanced" ]]; then
  EASY_ROUNDS_DEFAULT=40
  MID_ROUNDS_DEFAULT=35
  HARD_HTTPS_ROUNDS_DEFAULT=60
  HARD_SSH_ROUNDS_DEFAULT=20
  VPN_ROUNDS_DEFAULT=40
  TLS_HANDSHAKE_ROUNDS_DEFAULT=20
else
  EASY_ROUNDS_DEFAULT=15
  MID_ROUNDS_DEFAULT=15
  HARD_HTTPS_ROUNDS_DEFAULT=140
  HARD_SSH_ROUNDS_DEFAULT=50
  VPN_ROUNDS_DEFAULT=120
  TLS_HANDSHAKE_ROUNDS_DEFAULT=80
fi

EASY_ROUNDS="${EASY_ROUNDS:-$EASY_ROUNDS_DEFAULT}"
MID_ROUNDS="${MID_ROUNDS:-$MID_ROUNDS_DEFAULT}"
HARD_HTTPS_ROUNDS="${HARD_HTTPS_ROUNDS:-$HARD_HTTPS_ROUNDS_DEFAULT}"
HARD_SSH_ROUNDS="${HARD_SSH_ROUNDS:-$HARD_SSH_ROUNDS_DEFAULT}"
VPN_ROUNDS="${VPN_ROUNDS:-$VPN_ROUNDS_DEFAULT}"
TLS_HANDSHAKE_ROUNDS="${TLS_HANDSHAKE_ROUNDS:-$TLS_HANDSHAKE_ROUNDS_DEFAULT}"

TCPDUMP_PID=""

cleanup() {
  # Try graceful stop first to flush pcap header/footer.
  if [[ -n "${TCPDUMP_PID}" ]] && kill -0 "${TCPDUMP_PID}" 2>/dev/null; then
    sudo kill -INT "${TCPDUMP_PID}" 2>/dev/null || true
    wait "${TCPDUMP_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "[*] Output: ${OUTPUT}"
echo "[*] Capture iface=${IFACE}, cap_sec=${CAPTURE_SEC}, max_pkts=${MAX_PKTS}, snaplen=${SNAPLEN}"
echo "[*] Profile=${PROFILE}"
echo "[*] Rounds easy=${EASY_ROUNDS}, mid=${MID_ROUNDS}, hard_https=${HARD_HTTPS_ROUNDS}, hard_ssh=${HARD_SSH_ROUNDS}, vpn=${VPN_ROUNDS}, tls_hs=${TLS_HANDSHAKE_ROUNDS}"

mkdir -p "$(dirname "${OUTPUT}")"
rm -f "${OUTPUT}"

# Refresh sudo credential early to avoid mid-run prompt blocking.
sudo -v

echo "[*] Start tcpdump..."
# timeout + -c double-protect runtime and file size.
sudo timeout "${CAPTURE_SEC}s" tcpdump \
  -i "${IFACE}" \
  -s "${SNAPLEN}" \
  -nn \
  -B 4096 \
  -c "${MAX_PKTS}" \
  -w "${OUTPUT}" \
  '(tcp or udp)' >/dev/null 2>&1 &
TCPDUMP_PID=$!

sleep 1

# EASY: mostly control-plane style traffic (DNS).
echo "[*] Generating EASY traffic (DNS)..."
for ((i=1; i<=EASY_ROUNDS; i++)); do
  timeout 2s dig +tries=1 +time=1 www.baidu.com >/dev/null 2>&1 || true
  timeout 2s dig +tries=1 +time=1 www.qq.com >/dev/null 2>&1 || true
done

# MID: plaintext HTTP requests.
echo "[*] Generating MID traffic (HTTP)..."
for ((i=1; i<=MID_ROUNDS; i++)); do
  timeout 3s curl -sS --connect-timeout 1 --max-time 2 -I http://example.com >/dev/null 2>&1 || true
  timeout 3s curl -sS --connect-timeout 1 --max-time 2 -I http://neverssl.com >/dev/null 2>&1 || true
done

# HARD: encrypted web traffic (HTTPS -> usually recognized as TLS).
echo "[*] Generating HARD traffic (HTTPS/TLS)..."
for ((i=1; i<=HARD_HTTPS_ROUNDS; i++)); do
  timeout 4s curl -sS --connect-timeout 1 --max-time 3 -I https://www.google.com >/dev/null 2>&1 || true
  timeout 4s curl -sS --connect-timeout 1 --max-time 3 -I https://www.youtube.com >/dev/null 2>&1 || true
  timeout 4s curl -sS --connect-timeout 1 --max-time 3 -I https://www.cloudflare.com >/dev/null 2>&1 || true
  timeout 4s curl -sS --connect-timeout 1 --max-time 3 -I https://www.github.com >/dev/null 2>&1 || true
done

# Additional pure TLS handshake generation to boost TLS flows.
echo "[*] Generating extra TLS handshakes (openssl s_client)..."
for ((i=1; i<=TLS_HANDSHAKE_ROUNDS; i++)); do
  timeout 3s bash -c "echo | openssl s_client -servername www.google.com -connect www.google.com:443 >/dev/null 2>&1" || true
  timeout 3s bash -c "echo | openssl s_client -servername www.cloudflare.com -connect www.cloudflare.com:443 >/dev/null 2>&1" || true
done

# HARD: SSH handshake attempts.
echo "[*] Generating HARD traffic (SSH handshake)..."
for ((i=1; i<=HARD_SSH_ROUNDS; i++)); do
  timeout 2s ssh -o BatchMode=yes -o ConnectionAttempts=1 -o ConnectTimeout=1 localhost "exit" >/dev/null 2>&1 || true
done

# VPN-like encrypted HTTPS traffic.
echo "[*] Generating VPN-like HTTPS traffic..."
for ((i=1; i<=VPN_ROUNDS; i++)); do
  timeout 4s curl -sS --connect-timeout 1 --max-time 3 -I https://cloudflare.com >/dev/null 2>&1 || true
done

echo "[*] Waiting capture process to flush and exit..."
wait "${TCPDUMP_PID}" 2>/dev/null || true
TCPDUMP_PID=""

if [[ -f "${OUTPUT}" ]]; then
  echo "[*] Done. Saved to ${OUTPUT}"
  ls -lh "${OUTPUT}"
  # capinfos is optional; print quick stats if available.
  command -v capinfos >/dev/null 2>&1 && capinfos "${OUTPUT}" | sed -n '1,20p' || true
else
  echo "[!] tcpdump did not produce output file"
  exit 1
fi

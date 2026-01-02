#!/bin/bash
set -e

echo "╔════════════════════════════════════════════╗"
echo "║  Naval IPsec Build & Deploy System        ║"
echo "╚════════════════════════════════════════════╝"

if [ "$EUID" -ne 0 ]; then
  echo "[✗] Run as root: sudo ./build_deploy.sh"
  exit 1
fi

echo "[*] Installing dependencies..."
apt-get update -qq
apt-get install -y strongswan strongswan-pki tcpdump build-essential libssl-dev > /dev/null

echo "[*] Compiling controller..."
gcc -o esp_ah_controller ../code/esp_ah_controller.c -O2 -Wall -Wextra

chmod 755 esp_ah_controller
mv esp_ah_controller ../build/

touch /var/log/naval-ipsec.log
chmod 640 /var/log/naval-ipsec.log

echo "[✓] Build & deploy complete"
echo "Run: sudo ./build/esp_ah_controller"

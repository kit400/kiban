#!/usr/bin/env bash
# =============================================================================
# install_and_test.sh — Installer & verifier for kiban
# Repository: https://github.com/kit400/kiban
# =============================================================================
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_SRC="${PROJECT_DIR}/target/release/kiban"
BIN_DST="/usr/local/bin/kiban"
CONF_DIR="/etc/kiban"
CONF_DST="${CONF_DIR}/kiban.conf"
SERVICE_SRC="${PROJECT_DIR}/kiban.service"
SERVICE_DST="/etc/systemd/system/kiban.service"

echo "=== [1/5] Installing kiban binary and systemd service ==="
sudo install -m 0755 "${BIN_SRC}" "${BIN_DST}"
sudo mkdir -p "${CONF_DIR}"

if [[ ! -f "${CONF_DST}" ]]; then
    sudo install -m 0600 "${PROJECT_DIR}/kiban.conf.example" "${CONF_DST}"
fi

sudo install -m 0644 "${SERVICE_SRC}" "${SERVICE_DST}"

echo "=== [2/5] Running dry-run parser benchmark on server logs ==="
if [[ -f /var/log/auth.log ]]; then
    echo "--- Testing /var/log/auth.log ---"
    sudo "${BIN_DST}" test -c "${CONF_DST}" /var/log/auth.log | tail -n 15
fi

if [[ -f /var/log/nginx/access.log ]]; then
    echo "--- Testing /var/log/nginx/access.log ---"
    sudo "${BIN_DST}" test -c "${CONF_DST}" /var/log/nginx/access.log | tail -n 15
fi

if [[ -f /var/log/nginx/error.log ]]; then
    echo "--- Testing /var/log/nginx/error.log ---"
    sudo "${BIN_DST}" test -c "${CONF_DST}" /var/log/nginx/error.log | tail -n 15
fi

echo "=== [3/5] Starting and enabling kiban.service ==="
sudo systemctl daemon-reload
sudo systemctl restart kiban.service
sudo systemctl enable kiban.service
sleep 0.5
sudo systemctl status kiban.service --no-pager

echo "=== [4/5] Verifying nftables kernel table status ==="
sudo "${BIN_DST}" status -c "${CONF_DST}"

echo "=== [5/5] Checking kiban process resource footprint ==="
ps -o pid,rss,vsz,pcpu,etime,comm,args -C kiban || true

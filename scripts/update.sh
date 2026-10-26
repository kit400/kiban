#!/usr/bin/env bash
# =============================================================================
# update.sh — One-line installer & updater for kiban
#
# Public one-liner:
#   curl -sSL https://raw.githubusercontent.com/kit400/kiban/main/scripts/update.sh | bash
# =============================================================================
set -euo pipefail

REPO_URL="https://github.com/kit400/kiban.git"
BIN_DST="/usr/local/bin/kiban"
CONF_DIR="/etc/kiban"
CONF_DST="${CONF_DIR}/kiban.conf"
SERVICE_DST="/etc/systemd/system/kiban.service"

SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then
    SUDO="sudo"
fi

SCRIPT_DIR=""
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi

if [[ -n "${SCRIPT_DIR}" && -f "${SCRIPT_DIR}/Cargo.toml" ]]; then
    SRC_DIR="${SCRIPT_DIR}"
elif [[ -d "/opt/kiban/.git" ]]; then
    SRC_DIR="/opt/kiban"
else
    SRC_DIR="/opt/kiban"
    if ! command -v git >/dev/null 2>&1; then
        ${SUDO} apt-get update -qq && ${SUDO} apt-get install -y -qq git
    fi
    echo "[kiban] Cloning ${REPO_URL} into ${SRC_DIR}..."
    ${SUDO} mkdir -p "${SRC_DIR}"
    ${SUDO} chown "$(id -u):$(id -g)" "${SRC_DIR}"
    git clone "${REPO_URL}" "${SRC_DIR}"
fi

cd "${SRC_DIR}"
if git status --porcelain 2>/dev/null | grep -q .; then
    echo "[kiban] Building from current working tree in ${SRC_DIR}..."
else
    echo "[kiban] Pulling latest changes from origin/main in ${SRC_DIR}..."
    git fetch origin main
    git reset --hard origin/main
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "[kiban] Installing Rust/Cargo toolchain..."
    ${SUDO} apt-get update -qq && ${SUDO} apt-get install -y -qq build-essential cargo
fi

echo "[kiban] Building release binary..."
cargo build --release

echo "[kiban] Installing ${BIN_DST} on local host ($(hostname))..."
${SUDO} install -m 0755 target/release/kiban "${BIN_DST}"

${SUDO} mkdir -p "${CONF_DIR}"
if [[ ! -f "${CONF_DST}" ]]; then
    echo "[kiban] Creating initial config ${CONF_DST}..."
    ${SUDO} install -m 0600 kiban.conf.example "${CONF_DST}"
fi

if [[ ! -f "${SERVICE_DST}" ]]; then
    echo "[kiban] Installing systemd unit ${SERVICE_DST}..."
    ${SUDO} install -m 0644 kiban.service "${SERVICE_DST}"
fi

echo "[kiban] Restarting kiban.service on local host ($(hostname))..."
${SUDO} systemctl daemon-reload
${SUDO} systemctl enable --now kiban.service
${SUDO} systemctl restart kiban.service

# Optional remote deployment targets configured in gitignored .deploy.env
if [[ -f "${SRC_DIR}/.deploy.env" ]]; then
    # shellcheck disable=SC1091
    source "${SRC_DIR}/.deploy.env"
fi

if [[ -n "${DEPLOY_TARGETS:-}" ]]; then
    for target in ${DEPLOY_TARGETS}; do
        host="${target%:*}"
        port="${target##*:}"
        if [[ "${host}" == "${port}" ]]; then
            port="22"
        fi
        if ssh -p "${port}" -o BatchMode=yes -o ConnectTimeout=5 "${host}" "true" 2>/dev/null; then
            echo "[kiban] Deploying updated binary to ${host}:${port}..."
            scp -P "${port}" -q target/release/kiban "${host}:${BIN_DST}.new"
            ssh -p "${port}" "${host}" \
                "chmod 0755 ${BIN_DST}.new && mv -f ${BIN_DST}.new ${BIN_DST} && systemctl restart kiban.service && systemctl is-active kiban.service"
            echo "[kiban] Remote host ${host} updated and kiban.service restarted."
        fi
    done
fi

echo "[kiban] Update complete!"

#!/usr/bin/env bash
set -euo pipefail

APP_USER="awocc"
APP_NAME="awocc"
APP_DIR="/opt/awocc"
BIN_PATH="/usr/local/bin/awocc"
SERVICE_PATH="/etc/systemd/system/awocc.service"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root (e.g., sudo ./install_awocc.sh)."
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! id -u "${APP_USER}" >/dev/null 2>&1; then
  useradd \
    --system \
    --create-home \
    --home-dir "/var/lib/${APP_NAME}" \
    --shell /usr/sbin/nologin \
    "${APP_USER}"
fi

mkdir -p "${APP_DIR}"
if command -v rsync >/dev/null 2>&1; then
  rsync -a --delete \
    --exclude ".git" \
    --exclude "cert-cache" \
    "${SCRIPT_DIR}/" "${APP_DIR}/"
else
  rm -rf "${APP_DIR:?}/"*
  cp -a "${SCRIPT_DIR}/." "${APP_DIR}/"
fi

chown -R "${APP_USER}:${APP_USER}" "${APP_DIR}"

if command -v go >/dev/null 2>&1; then
  (cd "${APP_DIR}" && go build -o "${BIN_PATH}" .)
else
  echo "Go is required to build the binary."
  exit 1
fi

chown "${APP_USER}:${APP_USER}" "${BIN_PATH}"

if command -v setcap >/dev/null 2>&1; then
  setcap "cap_net_bind_service=+ep" "${BIN_PATH}"
else
  echo "setcap not found; ${APP_NAME} may not bind to ports 80/443 as ${APP_USER}."
fi

if command -v ufw >/dev/null 2>&1; then
  ufw allow 80/tcp
  ufw allow 443/tcp
elif command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --permanent --add-service=http
  firewall-cmd --permanent --add-service=https
  firewall-cmd --reload
else
  echo "No supported firewall tool found (ufw or firewalld). Open ports 80/443 manually."
fi

cat > "${SERVICE_PATH}" <<EOF
[Unit]
Description=AWOCC web app
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_DIR}
Environment=HTTP_ADDR=:80
Restart=always
RestartSec=3
ExecStart=${BIN_PATH}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "${APP_NAME}.service"

echo "Installed and started ${APP_NAME}."

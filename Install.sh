#!/usr/bin/env bash
# FaiLive2 Cloud — Web VPS Panel installer (single-file app)
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

echo "==> FaiLive2 Cloud Web Panel installer"
echo "    Install dir: $APP_DIR"

if [[ $EUID -ne 0 ]]; then
  echo "!! Must run as root (needs to drive lxc)."
  exit 1
fi

if [[ ! -f web.py ]]; then
  echo "!! web.py not found in $APP_DIR — put install.sh and web.py in the same folder."
  exit 1
fi

# --- 1. System packages ---
echo "==> Installing system packages"
apt-get update -y
apt-get install -y python3 python3-venv python3-pip curl ca-certificates \
    lxc lxc-templates bridge-utils dnsmasq-base iptables \
    openssh-client rsync git uidmap

# --- 2. Require lxc/lxd ---
if ! command -v lxc >/dev/null 2>&1; then
  echo "!! 'lxc' command not found."
  echo "    If you use LXD:  snap install lxd && lxd init --auto"
  exit 1
fi

# --- 3. Python venv + deps ---
echo "==> Python venv + deps"
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip wheel
pip install \
  "fastapi==0.115.0" \
  "uvicorn[standard]==0.32.0" \
  "jinja2==3.1.4" \
  "python-multipart==0.0.12" \
  "passlib[bcrypt]==1.7.4" \
  "python-jose[cryptography]==3.3.0" \
  "pydantic-settings==2.5.2"

# --- 4. Generate .env ---
if [[ ! -f .env ]]; then
  echo "==> Generating .env"
  SECRET_KEY="$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')"
  ADMIN_PASSWORD="$(python3 -c 'import secrets,string;print("".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(20)))')"
  PUBLIC_IP="$(curl -s --max-time 5 https://ifconfig.me/ip || echo 127.0.0.1)"
  cat > .env <<EOF
SECRET_KEY=$SECRET_KEY
ADMIN_EMAIL=admin@localhost
ADMIN_PASSWORD=$ADMIN_PASSWORD
PUBLIC_IP=$PUBLIC_IP
LXC_STORAGE_POOL=default
MAX_VPS_PER_USER=3
EOF
  echo "==========================================================="
  echo "  Admin credentials (save these):"
  echo "    Email:    admin@localhost"
  echo "    Password: $ADMIN_PASSWORD"
  echo "==========================================================="
else
  echo "==> .env already exists, keeping it"
fi

# --- 5. systemd service ---
echo "==> Installing systemd service"
cat > /etc/systemd/system/failive2-web.service <<EOF
[Unit]
Description=FaiLive2 Cloud Web VPS Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
EnvironmentFile=$APP_DIR/.env
ExecStart=$APP_DIR/.venv/bin/uvicorn web:app --host 0.0.0.0 --port 3000
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now failive2-web.service

echo ""
echo "==> Done!"
echo "    Panel:   http://localhost:3000"
echo "    Logs:    journalctl -u failive2-web -f"
echo "    Stop:    systemctl stop failive2-web"
echo "    Restart: systemctl restart failive2-web"
echo ""
echo "    Login with the admin credentials printed above (also in .env)."

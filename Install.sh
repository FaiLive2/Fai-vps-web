#!/usr/bin/env bash
# FaiLive2 Cloud v2 — Interactive installer
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

BOLD=$'\e[1m'; DIM=$'\e[2m'; CYAN=$'\e[36m'; GREEN=$'\e[32m'; YEL=$'\e[33m'; RED=$'\e[31m'; RESET=$'\e[0m'
say()  { printf "%s==>%s %s\n" "$CYAN" "$RESET" "$*"; }
ok()   { printf "%s ✓%s %s\n"  "$GREEN" "$RESET" "$*"; }
warn() { printf "%s !%s %s\n"  "$YEL" "$RESET" "$*"; }
die()  { printf "%s ✗%s %s\n"  "$RED" "$RESET" "$*" >&2; exit 1; }

clear
printf "%s╔══════════════════════════════════════════════╗\n" "$BOLD"
printf "║        FaiLive2 Cloud  ·  Web Panel          ║\n"
printf "║              interactive installer           ║\n"
printf "╚══════════════════════════════════════════════╝%s\n\n" "$RESET"

if [[ $EUID -ne 0 ]]; then die "Run as root:  sudo bash install.sh"; fi
[[ -f web.py ]] || die "web.py not found in $APP_DIR (put it next to install.sh)"

# ---------- 1. System packages ----------
say "Installing system packages (this may take a minute)"
apt-get update -y >/dev/null
apt-get install -y python3 python3-venv python3-pip curl ca-certificates \
    lxc lxc-templates bridge-utils dnsmasq-base iptables \
    openssh-client rsync git uidmap >/dev/null
ok "System packages installed"

command -v lxc >/dev/null 2>&1 || die "lxc not found. Install LXD first: snap install lxd && lxd init --auto"
ok "lxc present: $(command -v lxc)"

# ---------- 2. Prompt for admin credentials ----------
echo
printf "%s── Admin account ──────────────────────────────%s\n" "$BOLD" "$RESET"

read -rp "Admin email    [admin@localhost]: " ADMIN_EMAIL
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@localhost}"

while :; do
  read -rsp "Admin password (min 8, max 72 chars): " ADMIN_PASSWORD; echo
  [[ ${#ADMIN_PASSWORD} -ge 8 && ${#ADMIN_PASSWORD} -le 72 ]] && break
  warn "Password must be 8–72 characters."
done
read -rsp "Repeat password: " ADMIN_PASSWORD2; echo
[[ "$ADMIN_PASSWORD" == "$ADMIN_PASSWORD2" ]] || die "Passwords do not match"
ok "Admin: $ADMIN_EMAIL"

# ---------- 3. Prompt for panel domain ----------
echo
printf "%s── Panel domain ───────────────────────────────%s\n" "$BOLD" "$RESET"
printf "%sExamples: panel.example.com  |  vps.example.com  |  cloud.example.com%s\n" "$DIM" "$RESET"
printf "%sPoint an A record of this domain at your server IP in Cloudflare (DNS only, no proxy).%s\n\n" "$DIM" "$RESET"

while :; do
  read -rp "Panel domain: " PANEL_DOMAIN
  if [[ "$PANEL_DOMAIN" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then break; fi
  warn "Invalid domain. Use something like panel.example.com"
done
ok "Panel domain: $PANEL_DOMAIN"

read -rp "Panel port    [3000]: " PANEL_PORT
PANEL_PORT="${PANEL_PORT:-3000}"

PUBLIC_IP="$(curl -s --max-time 5 https://ifconfig.me/ip || echo 127.0.0.1)"
ok "Public IP detected: $PUBLIC_IP"
echo

# ---------- 4. Python venv ----------
say "Creating Python venv + installing dependencies"
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip wheel >/dev/null
pip install \
  "fastapi==0.115.0" \
  "uvicorn[standard]==0.32.0" \
  "jinja2==3.1.4" \
  "python-multipart==0.0.12" \
  "passlib[bcrypt]==1.7.4" \
  "bcrypt==4.0.1" \
  "python-jose[cryptography]==3.3.0" \
  "pydantic-settings==2.5.2" >/dev/null
ok "Python deps installed (bcrypt 4.0.1 pinned)"

# ---------- 5. Write .env ----------
say "Writing .env"
SECRET_KEY="$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')"
cat > .env <<EOF
SECRET_KEY=$SECRET_KEY
ADMIN_EMAIL=$ADMIN_EMAIL
ADMIN_PASSWORD=$ADMIN_PASSWORD
PUBLIC_IP=$PUBLIC_IP
PANEL_DOMAIN=$PANEL_DOMAIN
PANEL_PORT=$PANEL_PORT
LXC_STORAGE_POOL=default
MAX_VPS_PER_USER=3
EOF
chmod 600 .env
ok ".env written"

# ---------- 6. systemd service ----------
say "Installing systemd service"
cat > /etc/systemd/system/failive2-web.service <<EOF
[Unit]
Description=FaiLive2 Cloud Web VPS Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
EnvironmentFile=$APP_DIR/.env
ExecStart=$APP_DIR/.venv/bin/uvicorn web:app --host 0.0.0.0 --port $PANEL_PORT
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable failive2-web >/dev/null
systemctl restart failive2-web
sleep 3

# ---------- 7. Helper commands ----------
say "Installing helper commands (failive2-status / failive2-logs)"
cat > /usr/local/bin/failive2-status <<'EOF'
#!/usr/bin/env bash
echo "── failive2-web ──"
systemctl is-active failive2-web
ss -tlnp 2>/dev/null | grep ':3000' || true
echo
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:3000/healthz || true
EOF
cat > /usr/local/bin/failive2-logs <<'EOF'
#!/usr/bin/env bash
journalctl -u failive2-web -n "${1:-60}" --no-pager
EOF
chmod +x /usr/local/bin/failive2-status /usr/local/bin/failive2-logs
ok "Helpers: failive2-status , failive2-logs"

# ---------- 8. Verify ----------
echo
say "Verifying panel"
if curl -sf -o /dev/null "http://localhost:$PANEL_PORT/healthz"; then
  ok "Panel is running on http://localhost:$PANEL_PORT"
else
  warn "Panel did not respond yet — run:  failive2-logs 30"
fi

cat <<EOF

${BOLD}╔══════════════════════════════════════════════╗${RESET}
${BOLD}║              INSTALL COMPLETE                ║${RESET}
${BOLD}╚══════════════════════════════════════════════╝${RESET}

  Panel URL:   http://$PANEL_DOMAIN:$PANEL_PORT
  Also local:  http://$PUBLIC_IP:$PANEL_PORT
  Admin email: $ADMIN_EMAIL
  Password:    (the one you entered)

  ${DIM}Next steps:${RESET}
    1. In Cloudflare, add an A record:
         $PANEL_DOMAIN  →  $PUBLIC_IP   (DNS only, no proxy)
    2. Open firewall on port $PANEL_PORT if you plan to use it directly:
         ufw allow $PANEL_PORT/tcp
    3. Log in and create users on the Admin page.
    4. For HTTPS, point Cloudflare proxy on OR add Caddy/nginx in front.

  ${DIM}Helpers:${RESET}
    failive2-status       # quick check
    failive2-logs 80      # tail logs

EOF

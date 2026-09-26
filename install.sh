#!/usr/bin/env bash
# MT Server Monitor - one-command bootstrap on a fresh VPS.
#   curl -sO <bundle> && bash install.sh
# Idempotent: safe to re-run; existing .env and TLS certs are preserved.
set -euo pipefail

DIR="/root/mt-monitor"
echo "== MT Server Monitor bootstrap =="

if [ -d "$DIR/server" ]; then
    echo "existing install found at $DIR -> upgrading in place (config + data kept)"
    cp -r server mt-agent deploy "$DIR/"
else
    mkdir -p "$DIR"
    cp -r server mt-agent deploy "$DIR/"
fi

cd "$DIR"

# --- dependencies (system python; no venv needed) ---
if ! python3 -c "import flask" 2>/dev/null; then
    echo "installing python deps..."
    python3 -m pip install -q -r requirements.txt
fi

# --- persistent config: keep secrets from a previous install ---
if [ ! -f "$DIR/.env" ]; then
    echo "generating fresh secrets..."
    SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    ADMIN=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")
    AGENT=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    PUBLIC_IP=$(curl -s -m 5 ifconfig.me || echo "localhost")

    cat > "$DIR/.env" <<EOF
MTMON_SECRET_KEY=$SECRET
MTMON_ADMIN_TOKEN=$ADMIN
MTMON_AGENT_REGISTRATION=on
MTMON_AGENT_KEYS=rdp-01:$AGENT
MTMON_TLS=on
MTMON_TLS_NAMES=$PUBLIC_IP,127.0.0.1,localhost
MTMON_HOST=0.0.0.0
MTMON_PORT=8080
MTMON_DB_PATH=$DIR/data/monitor.db
MTMON_SCREEN_DIR=$DIR/data/screens
MTMON_TLS_CERT=$DIR/data/certs/cert.pem
MTMON_TLS_KEY=$DIR/data/certs/key.pem
EOF
    chmod 600 "$DIR/.env"
    echo ""
    echo "============================================================"
    echo " FRESH INSTALL - SAVE THESE NOW"
    echo "   dashboard login : \$ADMIN_TOKEN below"
    echo "   agent key (rdp-01): \$AGENT_KEY below"
    echo "============================================================"
    echo "ADMIN_TOKEN=$ADMIN"
    echo "AGENT_KEY=$AGENT"
    echo "============================================================"
else
    echo "existing .env kept (secrets unchanged)"
fi

# --- systemd service ---
mkdir -p data
cp deploy/mtmon.service /etc/systemd/system/mtmon.service
systemctl daemon-reload
systemctl enable mtmon 2>/dev/null || true
systemctl restart mtmon

sleep 5
echo ""
echo "== status =="
systemctl is-active mtmon
echo ""
echo "Dashboard: https://$(curl -s -m 5 ifconfig.me || echo '<vps-ip>'):8080"
echo "Health:    systemctl status mtmon"
echo "Logs:      journalctl -u mtmon -f"
echo ""
echo "Next: deploy the agent (mt-agent/) on your Windows RDP box."

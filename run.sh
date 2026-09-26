#!/usr/bin/env bash
# mtmon — bare-metal / systemd / RDP-box fallback when Docker is unavailable.
# Usage: ./run.sh            (foreground)
#        ./run.sh -d         (background, logs → data/mtmon.log)
#        MTMON_SECRET_KEY=... MTMON_OPERATOR_PASSWORD=... ./run.sh
set -euo pipefail
cd "$(dirname "$0")/server"

mkdir -p data
python3 -c "import flask" 2>/dev/null || pip install --quiet flask psutil pillow

if [[ "${1:-}" == "-d" ]]; then
  mkdir -p ../data
  nohup python3 app.py >> ../data/mtmon.log 2>&1 &
  echo "started pid $!  (log: data/mtmon.log)  http://127.0.0.1:${MTMON_PORT:-8080}"
else
  exec python3 app.py
fi

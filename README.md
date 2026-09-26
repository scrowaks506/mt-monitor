# MT Server Monitor

Production-grade web monitoring for **Windows RDP boxes running MetaTrader terminals**, with live screen view and real remote mouse/keyboard control. Built for traders who need to keep eyes on their trading box from anywhere.

## What it does

- **Live screen** — JPEG frames of the RDP desktop, refreshed every few seconds
- **Real remote control** — mouse (move / left / right / middle / drag / scroll) and keyboard, via Windows `SendInput`
- **Metrics** — CPU / RAM / disk, MT4/MT5 terminal detection, uptime
- **Command queue** — whitelist-only actions (`restart_mt5`, `kill_process`, `run_command`, `reboot`) with **double confirmation**
- **Alerting** — threshold-based, deduplicated, 30-minute cooldown. Sends to Telegram
- **Audit log** — every control session and command is recorded
- **Auth** — token login, per-IP brute-force lockout (5 wrong attempts -> 15 minutes)
- **TLS** — self-signed cert auto-generated, or bring your own
- **Portable** — one env file, one `install.sh`, Docker compose included

## Architecture

```
┌────────────────┐        HMAC-signed HTTPS        ┌─────────────────┐
│  RDP box       │ ───────────────────────────────▶ │  Monitor server │
│  (mt-agent)    │   heartbeat + JPEG screenshots  │  (Flask + TLS)  │
│  PowerShell    │ ◀─────────────────────────────── │                 │
└────────────────┘   input events + commands        └────────┬────────┘
                                                                │
                                                     ┌──────────┴──────────┐
                                                     │  Your browser        │
                                                     │  dashboard + control │
                                                     └─────────────────────┘
```

The agent runs as **two pieces** on the RDP box, because Windows isolates session 0 (services) from interactive sessions:

- `MTAgentBoot` — scheduled task at system startup, running as SYSTEM. Heartbeat + metrics + commands. **Survives RDP logoff.**
- `MTAgentLogon` — scheduled task at logon. Live screen capture + remote input. Runs in your session, dies on logoff.

The dashboard merges both, so the terminal list never flips between the two.

## Deploy the server

```bash
tar xzf mt-monitor-full.tar.gz
bash install.sh
```

The installer generates fresh secrets on first run and prints them — **save them**. It installs a systemd service that auto-starts on boot and auto-restarts on crash.

Bare metal or Docker:

```bash
./run.sh            # foreground
./run.sh -d         # background

cp .env.example .env   # edit secrets
docker compose up -d
```

Environment (all `MTMON_*`, see `.env.example`):

| Var | Default | Meaning |
|---|---|---|
| `MTMON_ADMIN_TOKEN` | generated | Dashboard login token |
| `MTMON_AGENT_KEYS` | generated | `agent_id:key,...` — must match `config.json` on the RDP box |
| `MTMON_AGENT_REGISTRATION` | `on` | `on` = agents can self-register with a valid key |
| `MTMON_TLS` | `off` | `on` = HTTPS with auto self-signed cert |
| `MTMON_TLS_NAMES` | localhost | IP / domain put in the cert |
| `MTMON_TLS_CERT` / `MTMON_TLS_KEY` | auto | Bring your own cert (Let's Encrypt, Caddy) |
| `MTMON_PORT` | `8080` | Listen port |
| `MTMON_ALERT_CPU` / `MEM` / `DISK` | 90 / 92 / 95 | Alert thresholds (%) |
| `MTMON_ALERT_OFFLINE_SEC` | `90` | Seconds without heartbeat -> offline |
| `MTMON_ALERT_COOLDOWN_MIN` | `30` | Alert dedup cooldown |
| `MTMON_TELEGRAM_BOT_TOKEN` | — | Telegram alert bot |
| `MTMON_TELEGRAM_CHAT_ID` | — | Alert destination |

## Deploy the agent (Windows RDP)

1. Copy `mt-agent/` to `C:\mt-agent\`
2. Edit `config.json`:
   ```json
   {
     "agent_id": "rdp-01",
     "server_url": "https://YOUR-VPS-IP:8080",
     "key": "same-value-as-MTMON_AGENT_KEYS"
   }
   ```
3. Run as Administrator:
   ```powershell
   cd C:\mt-agent
   .\install-service.ps1
   ```
4. Open `https://YOUR-VPS-IP:8080` and log in.

The browser will warn about the self-signed cert — accept it once, or put a real domain in front.

## Security

- **HMAC-SHA256** on every agent request (`hmac.compare_digest`, timing-safe). Bad signature -> 401.
- Server stores only `sha256(key)`. The raw key never leaves the RDP box.
- Dashboard requires login. Cookie is httponly + SameSite=Lax (secure under TLS).
- Brute-force lockout per IP.
- Commands are whitelist-only and need double confirmation.
- The agent **pins the TLS certificate** on first connect and rejects any different cert afterwards, so a MITM cannot swap in their own self-signed cert later.

### Honest limits

- **Self-signed TLS does not stop a first-contact MITM.** An attacker who controls the network on the very first connection can pin their own cert. For full protection use a real domain + Let's Encrypt.
- **Remote control is polling-based**, not a real-time protocol. Input round-trip is roughly 300ms-1s depending on config — fine for clicking around MT5, not for fast typing.
- **Ctrl+Alt+Del and UAC prompts cannot be controlled.** Windows blocks `SendInput` at the secure attention sequence.
- **A leaked admin token is full control of the RDP box.** `run_command` executes arbitrary `cmd /c`. Treat the token like a house key.
- **Session 0 cannot see the RDP desktop.** That is why the agent splits into boot + logon tasks.

## MetaTrader notes

- Terminal detection scans `%LOCALAPPDATA%\MetaQuotes\Terminal\*\terminal(64).exe` — MT4 (`terminal.exe`) and MT5 (`terminal64.exe`), plus running status and RAM.
- MT5 account state (`mt5_accounts`) is optional and usually empty: it needs the terminal's local API at `127.0.0.1:443` enabled. When empty, the margin-level alert never fires — only CPU / RAM / disk / terminal / offline alerts work.

## API reference

| Endpoint | Method | Auth | Notes |
|---|---|---|---|
| `/health` | GET | — | Liveness probe (docker healthcheck) |
| `/login` | GET | — | Login page |
| `/api/login` | POST | — | `{token}` -> cookie |
| `/api/agents` | GET | admin | State of all agents |
| `/api/agents/<id>/history` | GET | admin | Heartbeat time series |
| `/api/events` | GET | admin | Activity feed (audit) |
| `/api/commands` | GET | admin | Recent commands |
| `/api/ingest` | POST | HMAC | Agent heartbeat |
| `/api/screenshots/<id>` | POST | HMAC | Upload screenshot |
| `/api/screenshots/<id>/latest.jpg` | GET | admin | Fetch latest frame |
| `/api/control/queue` | POST | admin | Queue command (step 1) |
| `/api/control/confirm` | POST | admin | Double confirmation (step 2) |
| `/api/control/take/<id>` | POST | admin | Acquire exclusive input control |
| `/api/control/release/<id>` | POST | admin | Release input control |
| `/api/input/<id>` | POST | admin | Send input events |
| `/api/input/<id>/poll` | POST | HMAC | Agent drains input queue |
| `/api/commands/poll` | POST | HMAC | Agent fetches next command |
| `/api/commands/done` | POST | HMAC | Agent reports result |

## Project layout

```
mt-monitor/
├── install.sh              one-command bootstrap
├── server/                 Flask app (config, db, auth, alerts, app, dashboard)
├── mt-agent/               Windows agent (agent.ps1, install-service.ps1, uninstall.ps1, config.json)
├── deploy/                 systemd units
├── docker-compose.yml + Dockerfile
├── run.sh                  bare-metal launcher
├── requirements.txt
└── .env.example            template - the real .env is gitignored
```

## Requirements

- Server: Linux, Python 3.8+ (flask, psutil, Pillow). `openssl` for the self-signed cert.
- Agent: Windows Server 2012 R2+ / Windows 8.1+, PowerShell 4+. No extra .NET install needed.

## License

MIT — provided as-is. This is a remote administration tool; only deploy it on machines you own or have written permission to manage.

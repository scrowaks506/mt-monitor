import os, time, hashlib, hmac, mimetypes

import db
from config import settings
from auth import auth_required, login, logout
from flask import (Flask, request, jsonify, send_from_directory,
                   make_response, g, Response)

BASE = os.path.dirname(os.path.abspath(__file__))
TEMPLATES = os.path.join(BASE, "templates")

app = Flask(__name__, template_folder=TEMPLATES)
app.config["SECRET_KEY"] = settings.SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = settings.MAX_BODY_BYTES

# in-memory rate limit for ingest (per agent)
_ratelimit = {}
_ratelimit_window = 60.0


def _check_rate(agent_id):
    now = time.time()
    arr = _ratelimit.setdefault(agent_id, [])
    arr[:] = [t for t in arr if now - t < _ratelimit_window]
    if len(arr) >= settings.RATE_LIMIT_PER_MIN:
        return False
    arr.append(now)
    return True


# ---------------- live input channel (remote mouse/keyboard) ----------------
# In-memory ring per agent. Input is a high-frequency stream (hundreds of
# events/min), not something we audit row-by-row; control *sessions* are the
# audited thing (control.take / control.release in the audit table).
from collections import deque as _deque

_INPUT_QUEUES = {}
_INPUT_CAP = 500            # events buffered per agent (older dropped)
_INPUT_BURST = 64           # max events returned per poll
_CONTROL_SESSION = {}       # agent_id -> {"actor":..., "since":ts}


def _input_q(agent_id):
    q = _INPUT_QUEUES.get(agent_id)
    if q is None:
        q = _deque(maxlen=_INPUT_CAP)
        _INPUT_QUEUES[agent_id] = q
    return q


def _agent_env_key(agent_id):
    """The raw key for an agent, from MTMON_AGENT_KEY_<ID> (any case), the
    canonical MTMON_AGENT_KEYS list, or the single MTMON_AGENT_KEY.
    Returns '' when not configured. Never stored anywhere."""
    return settings.agent_keys().get(agent_id, "")


def _verify_agent(body, agent_id, sig, register_ok=False):
    """HMAC-SHA256 check over the raw body. Key = sha256(raw_key).

    On first contact with registration enabled, the agent auto-registers.
    Returns (ok: bool, error_json_or_None, status_code)."""
    if not agent_id or not sig:
        return False, jsonify(error="missing auth headers"), 401
    env_key = _agent_env_key(agent_id)
    if not env_key:
        return False, jsonify(error="agent not registered"), 404
    expected = hmac.new(hashlib.sha256(env_key.encode()).hexdigest().encode(),
                        body, hashlib.sha256).hexdigest()
    stored = db.agent_key_hash(agent_id)
    if stored is None:
        if not (register_ok and settings.AGENT_REGISTRATION):
            return False, jsonify(error="agent not registered"), 404
        db.register_agent(agent_id, agent_id, expected)
    elif not hmac.compare_digest(stored, expected):
        # key changed in .env after the agent was first registered
        db.register_agent(agent_id, agent_id, expected)
    if not hmac.compare_digest(expected, sig):
        return False, jsonify(error="bad signature"), 401
    return True, None, 200


# ---------------- dashboard ----------------
@app.route("/")
@auth_required
def dashboard():
    return make_response(open(os.path.join(TEMPLATES, "dashboard.html"), encoding="utf-8").read())


@app.route("/login")
def login_page():
    return login()


@app.route("/api/login", methods=["POST"])
def login_api():
    return login()


@app.route("/api/logout", methods=["POST"])
def logout_api():
    return logout()


# ---------------- read API ----------------
@app.route("/api/agents")
@auth_required
def agents_json():
    return jsonify(db.latest_all())


@app.route("/api/agents/<agent_id>/history")
@auth_required
def history_json(agent_id):
    limit = min(request.args.get("limit", 300, type=int), 2000)
    return jsonify(db.series(agent_id, limit))


@app.route("/api/events")
@auth_required
def events_json():
    return jsonify(db.recent_events(request.args.get("limit", 60, type=int)))


@app.route("/api/audit")
@auth_required
def audit_json():
    return jsonify(db.recent_audit(request.args.get("limit", 100, type=int)))


@app.route("/api/commands")
@auth_required
def commands_json():
    """Recent commands for the control panel."""
    with db.get_db() as c:
        rows = c.execute(
            "SELECT * FROM commands ORDER BY id DESC LIMIT ?", (50,)).fetchall()
    return jsonify([dict(r) for r in rows])


# ---------------- ingest (agent -> server) ----------------
@app.route("/api/ingest", methods=["POST"])
def ingest():
    body = request.get_data()
    agent_id = (request.headers.get("X-Agent-ID") or "").strip()
    sig = request.headers.get("X-Signature", "")

    if not agent_id or not sig:
        return jsonify(error="missing auth headers"), 401

    ok, err, code = _verify_agent(body, agent_id, sig, register_ok=True)
    if not ok:
        return err, code
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify(error="payload must be an object"), 400

    payload["received_ts"] = time.time()

    # Multi-session RDP: the session-0 copy (service) can't see the trader's
    # %LOCALAPPDATA%, so it reports empty terminals. The interactive copy can.
    # If both send heartbeats for the same agent, keep the richer terminal list
    # and the freshest metrics so the dashboard never flips between the two.
    role = payload.get("role")
    if role == "service":
        prev = db.latest_payload(agent_id)
        if prev and prev.get("role") == "session" and prev.get("mt_terminals"):
            payload["mt_terminals"] = prev["mt_terminals"]

    db.record(agent_id, payload)
    return jsonify(ok=True), 201


# ---------------- screenshot upload ----------------
@app.route("/api/screenshots/<agent_id>", methods=["POST"])
def upload_screenshot(agent_id):
    body = request.get_data()
    agent_id = agent_id.strip()
    ok, err, code = _verify_agent(body, agent_id, request.headers.get("X-Signature", ""),
                                  register_ok=True)
    if not ok:
        return err, code
    if len(body) > settings.MAX_BODY_BYTES:
        return jsonify(error="too large"), 413

    os.makedirs(settings.SCREEN_DIR, exist_ok=True)
    ts = int(time.time())
    # keep only the latest frame per agent (old ones are unlinked)
    latest = os.path.join(settings.SCREEN_DIR, f"{agent_id}_latest.jpg")
    tmp = os.path.join(settings.SCREEN_DIR, f".{agent_id}_{ts}.jpg.tmp")
    with open(tmp, "wb") as f:
        f.write(body)
    os.replace(tmp, latest)
    # timestamp sidecar so the dashboard can show frame age
    with open(os.path.join(settings.SCREEN_DIR, f"{agent_id}_ts"), "w") as f:
        f.write(str(ts))
    return jsonify(ok=True, ts=ts), 201


@app.route("/api/screenshots/<agent_id>/latest.jpg")
@auth_required
def get_screenshot(agent_id):
    p = os.path.join(settings.SCREEN_DIR, f"{agent_id}_latest.jpg")
    if not os.path.isfile(p):
        return make_response("no frame yet", 404)
    resp = make_response(open(p, "rb").read())
    resp.headers["Content-Type"] = "image/jpeg"
    resp.headers["Cache-Control"] = "no-store, max-age=0"
    # always send fresh; some browsers/proxies cache images aggressively
    resp.headers["Last-Modified"] = time.strftime(
        "%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    return resp


# ---------------- registration ----------------
@app.route("/api/register", methods=["POST"])
@auth_required
def register():
    """Register an agent with its shared key. Keep the key on the agent only."""
    d = request.get_json(silent=True) or {}
    agent_id = (d.get("agent_id") or "").strip()
    name = (d.get("name") or "").strip()
    key = (d.get("key") or "").strip()
    if not agent_id or not name or not key:
        return jsonify(error="agent_id, name, key required"), 400
    db.register_agent(agent_id, name, hashlib.sha256(key.encode()).hexdigest())
    return jsonify(ok=True, agent_id=agent_id), 201


# ---------------- control (double-confirm) ----------------
# Actions are whitelisted server-side. The agent only ever executes a known
# action id — it cannot be told to run arbitrary commands through this channel.
ACTIONS = {
    "restart_mt5":   {"label": "Restart terminal MT5", "severity": "warn"},
    "kill_process":  {"label": "Kill proses",          "severity": "crit"},
    "screenshot":    {"label": "Screenshot",           "severity": "info"},
    "run_command":   {"label": "Run command…",         "severity": "crit"},
    "reboot":        {"label": "Reboot Windows",       "severity": "crit"},
    "agent_update":  {"label": "Update agent",         "severity": "warn"},
}


@app.route("/api/control/queue", methods=["POST"])
@auth_required
def control_queue():
    d = request.get_json(silent=True) or {}
    agent_id = (d.get("agent_id") or "").strip()
    action = (d.get("action") or "").strip()
    args = d.get("args") or {}
    if action not in ACTIONS:
        return jsonify(error="unknown action"), 400
    if not db.get_agent(agent_id):
        return jsonify(error="unknown agent"), 404
    if action == "run_command" and not (isinstance(args, dict) and (args.get("cmd") or "").strip()):
        return jsonify(error="run_command requires args.cmd"), 400
    if action == "kill_process" and not (isinstance(args, dict) and (args.get("name") or "").strip()):
        return jsonify(error="kill_process requires args.name"), 400

    cid = db.queue_command(agent_id, action, args, g.actor)
    return jsonify(ok=True, id=cid, state="queued",
                   severity=ACTIONS[action]["severity"]), 201


@app.route("/api/control/confirm", methods=["POST"])
@auth_required
def control_confirm():
    """Second confirmation. Agent will not run a command until this is called."""
    d = request.get_json(silent=True) or {}
    cid = d.get("id")
    if not cid:
        return jsonify(error="id required"), 400
    state = db.confirm_command(int(cid), g.actor)
    if state != "confirmed":
        return jsonify(error="command not in queued state", state=state), 409
    return jsonify(ok=True, id=cid, state="confirmed")


# ---- live mouse/keyboard ----
@app.route("/api/control/take/<agent_id>", methods=["POST"])
@auth_required
def control_take(agent_id):
    """Acquire exclusive input control. Only one operator at a time."""
    if not db.get_agent(agent_id):
        return jsonify(error="unknown agent"), 404
    sess = _CONTROL_SESSION.get(agent_id)
    if sess and time.time() - sess["since"] < 600:
        return jsonify(error="agent already controlled", actor=sess["actor"]), 409
    _CONTROL_SESSION[agent_id] = {"actor": g.actor, "since": time.time()}
    db.log_audit(g.actor, "control.take", agent_id, "exclusive input session started")
    return jsonify(ok=True, mode="control")


@app.route("/api/control/release/<agent_id>", methods=["POST"])
@auth_required
def control_release(agent_id):
    _CONTROL_SESSION.pop(agent_id, None)
    _INPUT_QUEUES.pop(agent_id, None)
    db.log_audit(g.actor, "control.release", agent_id, "input session ended")
    return jsonify(ok=True, mode="view")


@app.route("/api/input/<agent_id>", methods=["POST"])
@auth_required
def input_stream(agent_id):
    """Push mouse/keyboard events. Events are {t, ...type-specific} dicts.

    Validated here so a hostile/careless client cannot enqueue junk that the
    agent then has to deal with.
    """
    if not db.get_agent(agent_id):
        return jsonify(error="unknown agent"), 404
    d = request.get_json(silent=True) or {}
    if not isinstance(d, dict):
        return jsonify(error="body must be an object"), 400
    events = d.get("events") or d.get("evs")
    if not isinstance(events, list):
        return jsonify(error="events[] required"), 400

    q = _input_q(agent_id)
    n = 0
    for ev in events:
        if not isinstance(ev, dict):
            continue
        t = ev.get("t")
        if t not in ("move", "down", "up", "scroll", "key"):
            continue  # unknown event type — dropped
        out = {"t": t}
        if t == "scroll":
            # scroll delta is signed (negative = scroll up), unlike screen coords
            dy = ev.get("y", ev.get("deltaY"))
            if not isinstance(dy, int):
                continue
            if not (-10000 <= dy <= 10000):
                continue
            out["x"], out["y"] = 0, dy
        elif t == "move":
            x, y = ev.get("x"), ev.get("y")
            if not isinstance(x, int) or not isinstance(y, int):
                continue
            if not (0 <= x <= 100000) or not (0 <= y <= 100000):
                continue
            out["x"], out["y"] = x, y
        else:
            b = ev.get("b")
            if b not in ("left", "right", "middle"):
                if t == "key":
                    k = ev.get("k")
                    if not isinstance(k, str) or len(k) > 25:
                        continue
                    out["k"] = k
                    if "down" in ev:
                        out["down"] = bool(ev["down"])
                    q.append(out); n += 1
                    continue
                continue
            out["b"] = b
        q.append(out)
        n += 1
    return jsonify(ok=True, queued=n)


@app.route("/api/input/<agent_id>/poll", methods=["POST"])
def input_poll(agent_id):
    """Agent drains its input queue. Signed like ingest."""
    body = request.get_data()
    agent_id = (request.headers.get("X-Agent-ID") or "").strip()
    ok, err, code = _verify_agent(body, agent_id, request.headers.get("X-Signature", ""))
    if not ok:
        return err, code
    q = _input_q(agent_id)
    out = []
    while len(out) < _INPUT_BURST and q:
        out.append(q.popleft())
    # tell the agent whether an operator is holding control, so it can raise
    # frame quality and keep polling tightly instead of backing off
    ctrl = agent_id in _CONTROL_SESSION
    return jsonify(ok=True, events=out, remaining=len(q), control=ctrl)


# ---------------- agent poll (agent -> server) ----------------
@app.route("/api/commands/poll", methods=["POST"])
def commands_poll():
    """Agent fetches its next confirmed command. Signed like ingest."""
    body = request.get_data()
    agent_id = (request.headers.get("X-Agent-ID") or "").strip()
    ok, err, code = _verify_agent(body, agent_id, request.headers.get("X-Signature", ""))
    if not ok:
        return err, code

    cmd = db.claim_command(agent_id)
    if not cmd:
        return jsonify(pending=False)
    return jsonify(pending=True, id=cmd["id"], action=cmd["action"],
                   args=json.loads(cmd["args"] or "{}"))


@app.route("/api/commands/done", methods=["POST"])
def commands_done():
    body = request.get_data()
    agent_id = (request.headers.get("X-Agent-ID") or "").strip()
    ok, err, code = _verify_agent(body, agent_id, request.headers.get("X-Signature", ""))
    if not ok:
        return err, code
    d = json.loads(body) if body else {}
    cid = d.get("id")
    result = d.get("result") or {}
    if not cid:
        return jsonify(error="id required"), 400
    db.finish_command(int(cid), result)
    return jsonify(ok=True)


import json  # noqa: E402  (used above)


@app.route("/health")
def health():
    """Lightweight liveness probe — no auth, no DB hits (docker healthcheck)."""
    return jsonify(ok=True, service="mtmon", version="1.0.0")


if __name__ == "__main__":
    settings.ensure_secrets()
    db.init()
    if settings.USE_TLS:
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(settings.TLS_CERT, settings.TLS_KEY)
        # TLS also upgrades the login cookie to `secure`
        app.run(host=settings.HOST, port=settings.PORT, threaded=True, ssl_context=ctx)
        print(f"[mtmon] HTTPS on :{settings.PORT} (self-signed)")
    else:
        app.run(host=settings.HOST, port=settings.PORT, threaded=True)
        print(f"[mtmon] PLAIN HTTP on :{settings.PORT} — admin token is NOT encrypted in transit")

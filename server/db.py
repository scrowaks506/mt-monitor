import sqlite3, json, time, os, hashlib
from threading import Lock

from config import settings

_lock = Lock()


def get_db():
    conn = sqlite3.connect(settings.DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init():
    os.makedirs(settings.DATA_DIR, exist_ok=True)
    os.makedirs(settings.SCREEN_DIR, exist_ok=True)
    with _lock, get_db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS agents(
            agent_id TEXT PRIMARY KEY, name TEXT, key_hash TEXT NOT NULL,
            last_ts REAL DEFAULT 0, created_ts REAL);
        CREATE TABLE IF NOT EXISTS heartbeats(
            id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT NOT NULL,
            ts REAL NOT NULL, cpu REAL, mem REAL, disk REAL, payload TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS hb_agent_ts ON heartbeats(agent_id, ts DESC);
        CREATE TABLE IF NOT EXISTS commands(
            id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT NOT NULL,
            action TEXT NOT NULL, args TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'queued',
            created_ts REAL NOT NULL, claimed_ts REAL, done_ts REAL, result TEXT);
        CREATE INDEX IF NOT EXISTS cmd_agent_state ON commands(agent_id, state, id);
        CREATE TABLE IF NOT EXISTS audit(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
            actor TEXT NOT NULL, agent_id TEXT, action TEXT NOT NULL, detail TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS alert_state(
            key TEXT PRIMARY KEY, state TEXT NOT NULL, last_ts REAL NOT NULL);
        """)
    # Seed agents from env: MTMON_AGENT_KEY_<ID> = shared key, and the
    # MTMON_AGENT_KEY_<ID> variants are the documented per-agent keys. Only the
    # sha256 of each key is stored, so this file never holds secrets.
    for k, v in os.environ.items():
        if not k.startswith("MTMON_AGENT_KEY_"):
            continue
        aid = k[len("MTMON_AGENT_KEY_"):].lower()
        if not aid or not v:
            continue
        register_agent(aid, aid, hashlib.sha256(v.encode()).hexdigest())
    if settings.AGENT_KEY and settings.AGENT_ID_DEFAULT:
        register_agent(settings.AGENT_ID_DEFAULT, settings.AGENT_ID_DEFAULT,
                       hashlib.sha256(settings.AGENT_KEY.encode()).hexdigest())


def register_agent(agent_id, name, key_hash):
    with _lock, get_db() as c:
        c.execute(
            "INSERT INTO agents(agent_id,name,key_hash,created_ts) VALUES(?,?,?,?) "
            "ON CONFLICT(agent_id) DO UPDATE SET name=excluded.name,key_hash=excluded.key_hash",
            (agent_id, name, key_hash, time.time()))


def agent_key_hash(agent_id):
    with get_db() as c:
        r = c.execute("SELECT key_hash FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
        return r["key_hash"] if r else None


def get_agent(agent_id):
    with get_db() as c:
        return dict(c.execute("SELECT * FROM agents WHERE agent_id=?", (agent_id,)).fetchone() or {})


def latest_payload(agent_id):
    """Most recent heartbeat payload (dict), or None."""
    with _lock, get_db() as c:
        h = c.execute(
            "SELECT payload FROM heartbeats WHERE agent_id=? ORDER BY ts DESC LIMIT 1",
            (agent_id,)).fetchone()
        return json.loads(h["payload"]) if h else None


def record(agent_id, payload):
    ts = float(payload.get("ts") or time.time())
    with _lock, get_db() as c:
        c.execute(
            "INSERT INTO heartbeats(agent_id,ts,cpu,mem,disk,payload) VALUES(?,?,?,?,?,?)",
            (agent_id, ts, payload.get("cpu"), payload.get("mem"),
             payload.get("disk"), json.dumps(payload)))
        c.execute("UPDATE agents SET last_ts=? WHERE agent_id=?", (ts, agent_id))


def latest_all():
    with get_db() as c:
        rows = c.execute("SELECT agent_id,name,last_ts FROM agents ORDER BY name").fetchall()
        out = []
        for r in rows:
            h = c.execute(
                "SELECT payload FROM heartbeats WHERE agent_id=? ORDER BY ts DESC LIMIT 1",
                (r["agent_id"],)).fetchone()
            out.append({"agent_id": r["agent_id"], "name": r["name"],
                        "last_ts": r["last_ts"],
                        "payload": json.loads(h["payload"]) if h else None})
        return out


def series(agent_id, limit=300):
    with get_db() as c:
        rows = c.execute(
            "SELECT ts,payload FROM heartbeats WHERE agent_id=? ORDER BY ts DESC LIMIT ?",
            (agent_id, limit)).fetchall()
        return [{"ts": r["ts"], **json.loads(r["payload"])} for r in reversed(rows)]


def log_audit(actor, action, agent_id, detail=""):
    with _lock, get_db() as c:
        c.execute(
            "INSERT INTO audit(ts,actor,agent_id,action,detail) VALUES(?,?,?,?,?)",
            (time.time(), actor, agent_id, action, detail))


def recent_audit(limit=100):
    with get_db() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM audit ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()]


def recent_events(limit=60):
    """Unified activity feed: audit rows are the source of truth."""
    with get_db() as c:
        return [dict(r) for r in c.execute(
            "SELECT ts, actor, agent_id, action, detail FROM audit ORDER BY ts DESC LIMIT ?",
            (limit,)).fetchall()]


# ---------------- command queue (control channel) ----------------
# Double-confirm flow:
#   dashboard queues  -> state=queued
#   dashboard confirms -> state=confirmed  (the second click)
#   agent polls        -> claims it, state=running
#   agent posts result -> state=done
def queue_command(agent_id, action, args, actor):
    with _lock, get_db() as c:
        cur = c.execute(
            "INSERT INTO commands(agent_id,action,args,state,created_ts) VALUES(?,?,?,'queued',?)",
            (agent_id, action, json.dumps(args), time.time()))
        cid = cur.lastrowid
    log_audit(actor, "command.queue", agent_id, json.dumps({"id": cid, "action": action, "args": args}))
    return cid


def command(cid):
    with get_db() as c:
        return dict(c.execute("SELECT * FROM commands WHERE id=?", (cid,)).fetchone() or {})


def confirm_command(cid, actor):
    with _lock, get_db() as c:
        c.execute("UPDATE commands SET state='confirmed' WHERE id=? AND state='queued'", (cid,))
    cmd = command(cid)
    if cmd.get("state") == "confirmed":
        log_audit(actor, "command.confirm", cmd["agent_id"], str(cid))
    return cmd.get("state")


def claim_command(agent_id):
    """Agent claims the oldest CONFIRMED command. Atomic."""
    with _lock, get_db() as c:
        r = c.execute(
            "SELECT * FROM commands WHERE agent_id=? AND state='confirmed' "
            "ORDER BY id ASC LIMIT 1", (agent_id,)).fetchone()
        if not r:
            return None
        c.execute("UPDATE commands SET state='running',claimed_ts=? WHERE id=?",
                  (time.time(), r["id"]))
        return dict(r)


def finish_command(cid, result):
    with _lock, get_db() as c:
        c.execute(
            "UPDATE commands SET state='done',done_ts=?,result=? WHERE id=?",
            (time.time(), json.dumps(result)[:8000], cid))
        r = c.execute("SELECT agent_id FROM commands WHERE id=?", (cid,)).fetchone()
    if r:
        log_audit("agent", "command.done", r["agent_id"], json.dumps(result)[:2000])


# ---------------- alerts ----------------
def alert_state(key):
    with get_db() as c:
        r = c.execute("SELECT state,last_ts FROM alert_state WHERE key=?", (key,)).fetchone()
        return (r["state"], r["last_ts"]) if r else (None, 0.0)


def set_alert_state(key, state):
    with _lock, get_db() as c:
        c.execute(
            "INSERT INTO alert_state(key,state,last_ts) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET state=excluded.state,last_ts=excluded.last_ts",
            (key, state, time.time()))

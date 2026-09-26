"""Environment-driven configuration. No secrets in files by default.

All of this can be overridden with env vars, which is what makes the server
portable: the same image runs on a laptop, a VPS, or a NAS, configured purely
through environment.
"""
import os
import secrets


def _bool(v, default=False):
    return (str(v).strip().lower() in ("1", "true", "yes", "on")) if v is not None else default


class Settings:
    # --- server ---
    PORT = int(os.environ.get("MTMON_PORT", os.environ.get("PORT", "8080")))
    HOST = os.environ.get("MTMON_HOST", "0.0.0.0")
    # where sqlite + screenshots live. In docker this is a mounted volume.
    DATA_DIR = os.environ.get("MTMON_DATA_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data"))
    DB_PATH = os.environ.get("MTMON_DB_PATH", os.path.join(DATA_DIR, "monitor.db"))
    SCREEN_DIR = os.environ.get("MTMON_SCREEN_DIR", os.path.join(DATA_DIR, "screens"))

    # --- security ---
    # Dashboard login + command authorization. If empty, a random token is
    # generated at first boot and written to <DATA_DIR>/.admin_token.
    AUTH_TOKEN = (os.environ.get("MTMON_ADMIN_TOKEN") or os.environ.get("MTMON_AUTH_TOKEN") or "").strip()
    SECRET_KEY = (os.environ.get("MTMON_SECRET_KEY") or os.environ.get("SECRET_KEY") or "").strip()

    # --- agent keys ---
    # MTMON_AGENT_KEYS is the canonical form: "agent-id:key,agent-id:key".
    # Per-agent MTMON_AGENT_KEY_<ID> (any case) is also accepted for convenience.
    # Only sha256(key) is stored in the DB; the raw key lives on the agent only.
    AGENT_REGISTRATION = _bool(os.environ.get("MTMON_AGENT_REGISTRATION"), True)

    @classmethod
    def agent_keys(cls):
        """dict agent_id -> raw key. One place to resolve agent auth keys."""
        out = {}
        for part in (os.environ.get("MTMON_AGENT_KEYS") or "").split(","):
            part = part.strip()
            if ":" not in part:
                continue
            aid, _, key = part.partition(":")
            if aid.strip() and key.strip():
                out[aid.strip()] = key.strip()
        pre = "MTMON_AGENT_KEY_"
        for k, v in os.environ.items():
            if k.startswith(pre) and v:
                out[k[len(pre):].lower()] = v.strip()
        if cls.AGENT_ID_DEFAULT and cls.AGENT_KEY:
            out[cls.AGENT_ID_DEFAULT] = cls.AGENT_KEY
        return out

    AGENT_KEY = os.environ.get("MTMON_AGENT_KEY", "").strip()
    AGENT_ID_DEFAULT = os.environ.get("MTMON_AGENT_ID", "").strip()

    # --- alert thresholds ---
    OFFLINE_AFTER_SEC = int(os.environ.get("MTMON_ALERT_OFFLINE_SEC", "90"))
    CPU_PCT = float(os.environ.get("MTMON_ALERT_CPU", "90"))
    MEM_PCT = float(os.environ.get("MTMON_ALERT_MEM", "92"))
    DISK_PCT = float(os.environ.get("MTMON_ALERT_DISK", "95"))
    NO_TERMINAL_ALERT = _bool(os.environ.get("MTMON_ALERT_NO_TERMINAL"), True)
    MARGIN_LEVEL = float(os.environ.get("MTMON_ALERT_MARGIN_LEVEL", "120"))
    ALERT_COOLDOWN_MIN = float(os.environ.get("MTMON_ALERT_COOLDOWN_MIN", "30"))
    RETENTION_DAYS = int(os.environ.get("MTMON_RETENTION_DAYS", "30"))

    # --- telegram (optional) ---
    TG_TOKEN = os.environ.get("MTMON_TELEGRAM_BOT_TOKEN", "").strip()
    TG_CHAT = os.environ.get("MTMON_TELEGRAM_CHAT_ID", "").strip()

    # --- ingest safety ---
    MAX_BODY_BYTES = int(os.environ.get("MTMON_MAX_BODY_BYTES", "6291456"))  # 6 MiB (screenshots)
    RATE_LIMIT_PER_MIN = int(os.environ.get("MTMON_RATE_LIMIT", "240"))

    # --- TLS ---
    # TLS is strongly recommended whenever the server is reachable from the
    # internet: the admin token and every screenshot travel over HTTP otherwise.
    # Without a domain name, use self-signed certs (browser warns once).
    USE_TLS = _bool(os.environ.get("MTMON_TLS"))
    TLS_CERT = (os.environ.get("MTMON_TLS_CERT") or os.path.join(DATA_DIR, "certs", "cert.pem")).strip()
    TLS_KEY = (os.environ.get("MTMON_TLS_KEY") or os.path.join(DATA_DIR, "certs", "key.pem")).strip()
    # IPs/domains baked into the self-signed cert
    TLS_NAMES = [s.strip() for s in (os.environ.get("MTMON_TLS_NAMES") or "").split(",") if s.strip()]

    @classmethod
    def ensure_secrets(cls):
        """Generate anything missing. Safe-by-default, still one-command deploys."""
        os.makedirs(cls.DATA_DIR, exist_ok=True)
        os.makedirs(cls.SCREEN_DIR, exist_ok=True)
        if cls.USE_TLS:
            cls.ensure_tls()
        if not cls.AUTH_TOKEN:
            # MTMON_OPERATOR_PASSWORD is the documented dashboard token; if it is
            # absent we generate one and persist it so redeploy does not lock you out.
            if os.environ.get("MTMON_OPERATOR_PASSWORD"):
                cls.AUTH_TOKEN = os.environ["MTMON_OPERATOR_PASSWORD"].strip()
            else:
                p = os.path.join(cls.DATA_DIR, ".admin_token")
                if os.path.exists(p):
                    with open(p) as f:
                        cls.AUTH_TOKEN = f.read().strip()
                else:
                    cls.AUTH_TOKEN = secrets.token_urlsafe(24)
                    with open(p, "w") as f:
                        f.write(cls.AUTH_TOKEN)
                    os.chmod(p, 0o600)
                    print(f"[mtmon] no MTMON_ADMIN_TOKEN set - generated admin token at {p}")
        if not cls.SECRET_KEY:
            cls.SECRET_KEY = secrets.token_urlsafe(32)
        return cls.AUTH_TOKEN

    @classmethod
    def ensure_tls(cls):
        """Generate a self-signed cert if none exists. Callers then use TLS."""
        import subprocess
        d = os.path.dirname(cls.TLS_CERT)
        os.makedirs(d, exist_ok=True)
        if os.path.isfile(cls.TLS_CERT) and os.path.isfile(cls.TLS_KEY):
            return
        names = cls.TLS_NAMES or ["localhost", "127.0.0.1"]
        subj = "/CN=" + names[0]
        alts = ",".join(f"DNS:{n}" if not n.replace(".", "").isdigit() else f"IP:{n}"
                        for n in names)
        cmd = ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", cls.TLS_KEY,
               "-out", cls.TLS_CERT, "-days", "825", "-nodes", "-subj", subj,
               "-addext", f"subjectAltName={alts}"]
        subprocess.run(cmd, check=True, capture_output=True)
        os.chmod(cls.TLS_KEY, 0o600)
        print(f"[mtmon] TLS: generated self-signed cert for {names} at {cls.TLS_CERT}")
        print("[mtmon] TLS: browsers will warn once — accept it, or put a real domain + Caddy in front")


settings = Settings()

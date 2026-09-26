"""Threshold evaluation + Telegram alerts + audit-backed event feed.

All thresholds come from config.Settings (env-driven). Every state transition is
written to the audit table, which is the activity feed the dashboard renders.
"""
import time, os, urllib.request, urllib.parse

from config import settings


def send_telegram(text):
    token, chat = settings.TG_TOKEN, settings.TG_CHAT
    if not token or not chat:
        print(f"[alert] telegram not configured — would send:\n{text}", flush=True)
        return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = urllib.parse.urlencode(
        {"chat_id": chat, "text": text,
         "parse_mode": "HTML", "disable_web_page_preview": "true"}).encode()
    try:
        req = urllib.request.Request(url, data=data)
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status == 200
    except Exception as e:
        print(f"[alert] telegram send failed: {e}", flush=True)
        return False


def _f(v, nd=1):
    try:
        return round(float(v), nd)
    except (TypeError, ValueError):
        return None


def evaluate():
    import db
    s = settings
    cooldown = s.ALERT_COOLDOWN_MIN * 60
    now = time.time()

    def fire(key, msg):
        state, last = db.alert_state(key)
        if state == "active" and (now - last) < cooldown:
            return
        if state != "active":
            db.set_alert_state(key, "active")
            db.log_audit("alert", "alert.fire", key.split(":")[0], msg.replace("\n", " "))
            send_telegram(msg)
            print(f"[alert] FIRED {key}", flush=True)

    def clear(key, msg):
        state, _ = db.alert_state(key)
        if state == "active":
            db.set_alert_state(key, "cleared")
            db.log_audit("alert", "alert.clear", key.split(":")[0], msg.replace("\n", " "))
            send_telegram(msg)
            print(f"[alert] CLEARED {key}", flush=True)

    for agent in db.latest_all():
        aid, name, p = agent["agent_id"], agent["name"], agent["payload"]
        if not p:
            continue
        age = now - float(agent["last_ts"] or 0)

        # 1. offline
        k = f"{aid}:offline"
        if age > s.OFFLINE_AFTER_SEC:
            fire(k, f"🔴 <b>{name}</b> offline\nNo heartbeat for {int(age)}s")
        else:
            clear(k, f"🟢 <b>{name}</b> back online")

        # 2. cpu / mem / disk
        for metric, label in (("cpu", "CPU"), ("mem", "RAM"), ("disk", "Disk")):
            v = _f(p.get(metric))
            k = f"{aid}:{metric}"
            if v is not None and v >= getattr(s, f"{metric.upper()}_PCT"):
                fire(k, f"🟠 <b>{name}</b> {label} at {v}% (threshold {getattr(s, f'{metric.upper()}_PCT')}%)")
            else:
                clear(k, f"🟢 <b>{name}</b> {label} back to {v}%")

        # 3. MT terminal present
        terminals = p.get("mt_terminals") or []
        k = f"{aid}:noterminal"
        if s.NO_TERMINAL_ALERT and len(terminals) == 0:
            fire(k, f"🔴 <b>{name}</b>: no MetaTrader terminal running")
        else:
            clear(k, f"🟢 <b>{name}</b>: {len(terminals)} terminal(s) running")

        # 4. margin level per MT account
        for acc in p.get("mt5_accounts") or []:
            login = acc.get("login")
            ml = _f(acc.get("margin_level"))
            k = f"{aid}:margin:{login}"
            if ml is not None and ml != 0 and ml < s.MARGIN_LEVEL:
                fire(k, f"🟣 <b>{name}</b> / MT5 {login}: margin level {ml}% "
                        f"(threshold {s.MARGIN_LEVEL}%) — margin call risk")
            else:
                clear(k, f"🟢 <b>{name}</b> / MT5 {login}: margin level {ml}%")


def loop(interval=30):
    import db
    db.init()
    while True:
        try:
            evaluate()
        except Exception as e:
            print(f"[alert] eval error: {e}", flush=True)
        time.sleep(interval)

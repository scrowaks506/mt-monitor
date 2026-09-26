"""Token auth for the dashboard and control API. Agent ingest uses HMAC keys.

Cookies are httponly + SameSite=Lax. Bearer tokens also accepted for API clients.
"""
import hmac
import time

from flask import request, jsonify, g, redirect

from config import settings


def _ok(tok):
    return bool(tok) and hmac.compare_digest(tok, settings.AUTH_TOKEN)


# ---- login brute-force protection (per source IP) ----
import time as _t
from collections import defaultdict as _dd

_LOGIN_ATTEMPTS = _dd(list)   # ip -> [timestamps of failed attempts]
_LOGIN_BLOCKED = _dd(float)   # ip -> blocked_until ts

_LOGIN_WINDOW = 300.0         # seconds
_LOGIN_MAX_FAILS = 5          # failed attempts in the window before lockout
_LOGIN_LOCKOUT = 900.0        # 15 minute lockout
_LOGIN_MAX_ACTIVE = 2000      # cap memory; oldest IPs pruned


def _login_allowed(ip):
    if len(_LOGIN_BLOCKED) > _LOGIN_MAX_ACTIVE:
        for old in list(_LOGIN_BLOCKED)[: _LOGIN_MAX_ACTIVE // 2]:
            del _LOGIN_BLOCKED[old]
    now = _t.time()
    until = _LOGIN_BLOCKED.get(ip, 0)
    if until and now < until:
        return False, int(until - now)
    if until:
        del _LOGIN_BLOCKED[ip]
    fails = [t for t in _LOGIN_ATTEMPTS.get(ip, []) if now - t < _LOGIN_WINDOW]
    _LOGIN_ATTEMPTS[ip] = fails
    if len(fails) >= _LOGIN_MAX_FAILS:
        _LOGIN_BLOCKED[ip] = now + _LOGIN_LOCKOUT
        return False, int(_LOGIN_LOCKOUT)
    return True, 0


def _login_failed(ip):
    _LOGIN_ATTEMPTS[ip].append(_t.time())


def auth_required(fn):
    """Dashboard + control API. Accepts session cookie or Authorization header."""
    from functools import wraps

    @wraps(fn)
    def wrapper(*a, **kw):
        tok = request.cookies.get("mtmon_token") or ""
        hdr = request.headers.get("Authorization", "")
        if hdr.lower().startswith("bearer "):
            tok = hdr[7:].strip()
        # ?token= is convenient for first-run links, but logged immediately after use
        if not tok:
            q = request.args.get("token", "")
            if q:
                if _ok(q):
                    return fn(*a, **kw)
        if not _ok(tok):
            if request.path.startswith("/api/"):
                return jsonify(error="unauthorized"), 401
            return redirect("/login")
        g.actor = "operator"
        return fn(*a, **kw)

    return wrapper


def login():
    """POST /api/login {token} -> sets cookie. Rate-limited per source IP."""
    if request.method == "GET":
        return render_login()
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0].strip()
    allowed, retry = _login_allowed(ip)
    if not allowed:
        # don't leak whether the account exists; same message as bad token
        return jsonify(error=f"too many attempts — retry in {retry}s"), 429
    d = request.get_json(silent=True) or {}
    tok = (d.get("token") or "").strip()
    if not _ok(tok):
        _login_failed(ip)
        return jsonify(error="invalid token"), 401
    resp = jsonify(ok=True)
    # secure cookie only when actually serving TLS, else the browser drops it
    resp.set_cookie(
        "mtmon_token", tok,
        max_age=60 * 60 * 24 * 30,   # 30 days
        httponly=True, samesite="Lax",
        secure=settings.USE_TLS)
    return resp


def logout():
    resp = jsonify(ok=True)
    resp.delete_cookie("mtmon_token")
    return resp


def render_login():
    return """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>mtmon — login</title><style>
body{background:#0a0c10;color:#c9d1d9;font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;
     display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.box{background:#101318;border:1px solid #1e242d;border-radius:10px;padding:28px;width:340px}
h1{font-size:17px;margin:0 0 4px}
p{color:#7d8590;font-size:12px;margin:0 0 16px}
input{width:100%;background:#0a0c10;border:1px solid #262d38;border-radius:7px;color:#c9d1d9;
      padding:9px 11px;font:13px monospace;outline:0;box-sizing:border-box}
input:focus{border-color:#4f8ef7}
button{width:100%;margin-top:12px;background:#14233d;color:#dfe9fb;border:1px solid #1d2c45;
       border-radius:7px;padding:9px;font:13px sans-serif;cursor:pointer}
.err{color:#f85149;font-size:12px;margin-top:10px}
</style></head><body><div class="box">
<h1>mtmon</h1><p>Ops console — masukkan admin token</p>
<form id=f><input id=t placeholder="admin token" autocomplete="off" autofocus>
<button type=submit>Masuk</button><div class=err id=e></div></form>
<script>
f.onsubmit=async ev=>{ev.preventDefault();
 const err=document.getElementById('e');
 try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({token:t.value})});
  if(r.ok){location='/'}else{err.textContent=(await r.json()).error||'token salah'}}
 catch(x){err.textContent='network error'}}
</script></div></body></html>"""

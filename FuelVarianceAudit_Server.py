"""
FuelVarianceAudit — Auth Server
================================
Handles bcrypt password validation, JWT sessions, and account management.

Install once:  pip install flask flask-cors bcrypt PyJWT
Run:           python FuelVarianceAudit_Server.py
Runs on:       http://localhost:5000
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import bcrypt
import jwt as _jwt
import datetime
import sqlite3
import secrets
import os
import re
import smtplib
import random
import string
import threading
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ── App setup ────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, origins="*", send_wildcard=True,
     allow_headers=["Content-Type", "Authorization", "orgId"])

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DB_PATH    = os.path.join(BASE_DIR, "fva_auth.db")
SECRET_FILE = os.path.join(BASE_DIR, ".fva_secret")

# Persist the JWT signing key across restarts so existing sessions stay valid.
# Override with env var FVA_SECRET_KEY for production deployments.
if os.getenv("FVA_SECRET_KEY"):
    SECRET_KEY = os.getenv("FVA_SECRET_KEY").encode()
elif os.path.exists(SECRET_FILE):
    with open(SECRET_FILE, "rb") as _f:
        SECRET_KEY = _f.read().strip()
else:
    SECRET_KEY = secrets.token_bytes(48)
    with open(SECRET_FILE, "wb") as _f:
        _f.write(SECRET_KEY)
    print(f"[FVA] Generated new signing key → {SECRET_FILE}")

BCRYPT_ROUNDS = 12      # ≈ 250 ms on modern hardware — adjust up for slower servers

# ── Email 2FA / OTP ───────────────────────────────────────────────────────────
# Set these environment variables before starting the server:
#   FVA_SMTP_USER  — your email address  e.g. aolatotse@skybridge.co.bw
#   FVA_SMTP_PASS  — your email password
SMTP_HOST = "mail.skybridge.co.bw"
SMTP_PORT = 587
OTP_TTL   = 600   # seconds (10 minutes)

_otp_store: dict = {}
_otp_lock = threading.Lock()

def _gen_otp() -> str:
    return "".join(random.choices(string.digits, k=6))

def _store_otp(username: str):
    code  = _gen_otp()
    token = secrets.token_urlsafe(32)
    exp   = time.time() + OTP_TTL
    with _otp_lock:
        # Purge expired entries on each write
        for k in [k for k, v in list(_otp_store.items()) if v["exp"] < time.time()]:
            del _otp_store[k]
        _otp_store[token] = {"otp": code, "username": username, "exp": exp, "used": False}
    return token, code

def _consume_otp(mfa_token: str, code: str):
    """Returns username if OTP is valid and unused, None otherwise."""
    with _otp_lock:
        entry = _otp_store.get(mfa_token)
        if not entry:
            return None
        if time.time() > entry["exp"]:
            _otp_store.pop(mfa_token, None)
            return None
        if entry["used"]:
            return None
        if entry["otp"] != code.strip():
            return None
        entry["used"] = True
        _otp_store.pop(mfa_token, None)
        return entry["username"]

def _load_smtp_creds() -> tuple[str, str]:
    user = os.getenv("FVA_SMTP_USER", "")
    pw   = os.getenv("FVA_SMTP_PASS", "")
    if user and pw:
        return user, pw
    cfg = os.path.join(BASE_DIR, ".fva_smtp")
    if os.path.exists(cfg):
        vals: dict = {}
        with open(cfg, encoding="utf-8") as _f:
            for line in _f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    vals[k.strip()] = v.strip()
        user = vals.get("user", "")
        pw   = vals.get("pass", "")
    return user, pw

def _send_otp_email(to_email: str, name: str, code: str) -> None:
    smtp_user, smtp_pass = _load_smtp_creds()
    if not smtp_user or not smtp_pass:
        raise RuntimeError(
            "Email not configured — set FVA_SMTP_USER and FVA_SMTP_PASS, or create .fva_smtp."
        )
    mins = OTP_TTL // 60
    msg            = MIMEMultipart("alternative")
    msg["Subject"] = "Your Fuel Variance Audit sign-in code"
    msg["From"]    = f"Fuel Variance Audit <{smtp_user}>"
    msg["To"]      = to_email

    plain = (
        f"Hello {name},\n\n"
        f"Your sign-in verification code is: {code}\n\n"
        f"This code expires in {mins} minutes. Do not share it with anyone.\n\n"
        f"If you did not request this, contact your administrator immediately.\n\n"
        f"Sky Bridge Logistics — Fuel Variance Audit"
    )
    html = f"""<!DOCTYPE html>
<html><body style="margin:0;padding:0;background:#f5f7fa;font-family:'Segoe UI',Arial,sans-serif">
<div style="max-width:480px;margin:40px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.08)">
  <div style="background:#0f1923;padding:24px 32px;overflow:hidden">
    <span style="font-size:17px;font-weight:700;color:#fff">Fuel Variance Audit</span>
    <span style="font-size:11px;color:#8a9ab5;float:right;line-height:26px">Sky Bridge Logistics</span>
  </div>
  <div style="padding:36px 32px">
    <p style="margin:0 0 8px;font-size:15px;font-weight:600;color:#1a2535">Hello {name},</p>
    <p style="margin:0 0 28px;font-size:14px;color:#4a5568;line-height:1.6">
      Use the code below to complete your sign-in.
      It expires in <strong>{mins} minutes</strong>.
    </p>
    <div style="background:#f0f4f8;border-radius:10px;padding:24px;text-align:center;margin-bottom:28px">
      <div style="font-size:40px;font-weight:800;letter-spacing:14px;color:#0f1923;font-family:Consolas,monospace;padding-left:14px">{code}</div>
    </div>
    <p style="margin:0;font-size:12px;color:#8a9ab5;line-height:1.6">
      If you did not request this code, ignore this email and contact your administrator immediately.
      Never share this code with anyone.
    </p>
  </div>
  <div style="background:#f8fafc;border-top:1px solid #e2e8f0;padding:14px 32px">
    <p style="margin:0;font-size:11px;color:#a0aec0">Sky Bridge Logistics &nbsp;&middot;&nbsp; Automated notification &nbsp;&middot;&nbsp; Do not reply</p>
  </div>
</div>
</body></html>"""
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html,  "html"))
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as srv:
        srv.ehlo()
        srv.starttls()
        srv.login(smtp_user, smtp_pass)
        srv.sendmail(smtp_user, to_email, msg.as_string())

# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id          TEXT PRIMARY KEY,
                username    TEXT UNIQUE NOT NULL,
                email       TEXT NOT NULL,
                name        TEXT,
                pwh         TEXT NOT NULL,
                role        TEXT NOT NULL DEFAULT 'viewer',
                department  TEXT,
                blocked     INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT NOT NULL,
                created_by  TEXT NOT NULL DEFAULT 'system'
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS password_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT NOT NULL,
                changed_at  TEXT NOT NULL,
                changed_by  TEXT NOT NULL
            )
        """)

        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            _seed(db)

def _seed(db):
    """Seed the three default accounts with bcrypt-hashed passwords."""
    default_pw = bcrypt.hashpw(b"FuelAudit@2026!", bcrypt.gensalt(BCRYPT_ROUNDS)).decode()
    now = _now()
    seeds = [
        ("usr001", "a.olatotse",      "aaolatotse1@gmail.com",
         "Aobakwe Olatotse",   default_pw, "admin",    "Management"),
        ("usr002", "p.gaotlhobogwe",  "prince.gaotlhobogwe@skybridgelogistics.co.bw",
         "Prince Gaotlhobogwe", default_pw, "admin",    "Management"),
        ("usr003", "g.mogorosi",       "goitse.mogorosi@skybridgelogistics.co.bw",
         "Goitse Mogorosi",     default_pw, "dispatch", "Dispatch"),
    ]
    db.executemany(
        "INSERT INTO users(id,username,email,name,pwh,role,department,created_at) VALUES(?,?,?,?,?,?,?,?)",
        [(*s, now) for s in seeds],
    )
    print("[FVA] Seeded 3 default accounts  (password: FuelAudit@2026!)")

def _now():
    return f"{datetime.datetime.now(datetime.timezone.utc).isoformat()}Z"

# ── JWT helpers ───────────────────────────────────────────────────────────────
TOKEN_TTL_HOURS = 8

def _make_token(user: sqlite3.Row) -> str:
    payload = {
        "sub":   user["username"],
        "name":  user["name"] or user["username"],
        "email": user["email"],
        "role":  user["role"],
        "iat":   datetime.datetime.now(datetime.timezone.utc),
        "exp":   datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=TOKEN_TTL_HOURS),
    }
    return _jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def _decode_token():
    """Extract and decode the Bearer token from the current request.
    Returns (payload_dict, None) on success or (None, error_str) on failure."""
    auth = request.headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ").strip()
    if not token:
        return None, "No token provided"
    try:
        return _jwt.decode(token, SECRET_KEY, algorithms=["HS256"]), None
    except _jwt.ExpiredSignatureError:
        return None, "Session expired — please log in again"
    except _jwt.InvalidTokenError:
        return None, "Invalid session token"

def _require_auth():
    payload, err = _decode_token()
    if err:
        raise _AuthError(err)
    return payload

def _require_admin():
    payload = _require_auth()
    if payload.get("role") != "admin":
        raise _AuthError("Admin access required", 403)
    return payload

class _AuthError(Exception):
    def __init__(self, msg, status=401):
        self.msg = msg
        self.status = status

@app.errorhandler(_AuthError)
def _handle_auth(e):
    return jsonify({"error": e.msg}), e.status

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return (
        "<h2>FVA Auth Server is running</h2>"
        "<p>API endpoints are at <code>/api/...</code></p>"
        "<ul>"
        "<li><a href='/api/health'>/api/health</a> — status check</li>"
        "<li><code>POST /api/login</code> — authenticate</li>"
        "<li><code>POST /api/change-password</code> — change password (JWT required)</li>"
        "</ul>"
        "<p>Open <strong>FuelVarianceAudit_Login.html</strong> in your browser to use the app.</p>"
    ), 200

@app.route("/api/health")
def health():
    return jsonify({"ok": True, "service": "FVA Auth"})

# ── Login (step 1) — validate credentials, send OTP email ────────
@app.route("/api/login", methods=["POST"])
def login():
    data     = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if not row:
        return jsonify({"error": "Invalid username or password"}), 401
    if row["blocked"]:
        return jsonify({"error": "Account is blocked. Contact your administrator."}), 403

    stored = row["pwh"].encode() if isinstance(row["pwh"], str) else row["pwh"]
    if not bcrypt.checkpw(password.encode("utf-8"), stored):
        return jsonify({"error": "Invalid username or password"}), 401

    # Credentials valid — generate OTP and send to the user's registered email
    mfa_token, otp_code = _store_otp(username)
    name = row["name"] or username
    try:
        _send_otp_email(row["email"], name, otp_code)
    except Exception as ex:
        print(f"[FVA] OTP email error: {ex}")
        return jsonify({"error": f"Could not send verification email. {ex}"}), 500

    # Mask email for the UI hint: show first 2 chars + *** + @domain
    em  = row["email"]
    at  = em.index("@")
    hint = em[:2] + ("*" * max(3, at - 2)) + em[at:]

    return jsonify({"mfa_required": True, "mfa_token": mfa_token, "email_hint": hint})

# ── Login (step 2) — verify email OTP, issue JWT ─────────────────
@app.route("/api/verify-otp", methods=["POST"])
def verify_otp():
    data      = request.get_json(silent=True) or {}
    mfa_token = (data.get("mfa_token") or "").strip()
    code      = (data.get("code")      or "").strip()

    if not mfa_token or not code:
        return jsonify({"error": "Verification code required"}), 400

    username = _consume_otp(mfa_token, code)
    if not username:
        return jsonify({"error": "Invalid or expired code. Please try again."}), 401

    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if not row or row["blocked"]:
        return jsonify({"error": "Account unavailable"}), 403

    return jsonify({
        "token": _make_token(row),
        "user": {
            "username": row["username"],
            "name":     row["name"] or row["username"],
            "email":    row["email"],
            "role":     row["role"],
        },
    })

# ── Verify token ─────────────────────────────────────────────────
@app.route("/api/verify", methods=["POST"])
def verify():
    payload, err = _decode_token()
    if err:
        return jsonify({"valid": False, "error": err}), 401
    return jsonify({"valid": True, "user": {
        "username": payload["sub"],
        "name":     payload["name"],
        "email":    payload["email"],
        "role":     payload["role"],
    }})

# ── Change password ──────────────────────────────────────────────
@app.route("/api/change-password", methods=["POST"])
def change_password():
    payload = _require_auth()
    data    = request.get_json(silent=True) or {}
    old_pw  = (data.get("old_password") or "").encode("utf-8")
    new_pw  = (data.get("new_password") or "").encode("utf-8")

    if len(new_pw) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    with get_db() as db:
        row = db.execute("SELECT pwh FROM users WHERE username = ?", (payload["sub"],)).fetchone()
        if not row:
            return jsonify({"error": "User not found"}), 404

        stored = row["pwh"].encode() if isinstance(row["pwh"], str) else row["pwh"]
        if not bcrypt.checkpw(old_pw, stored):
            return jsonify({"error": "Current password is incorrect"}), 401

        new_hash = bcrypt.hashpw(new_pw, bcrypt.gensalt(BCRYPT_ROUNDS)).decode()
        db.execute("UPDATE users SET pwh = ? WHERE username = ?", (new_hash, payload["sub"]))
        db.execute(
            "INSERT INTO password_log(username, changed_at, changed_by) VALUES(?,?,?)",
            (payload["sub"], _now(), payload["sub"]),
        )

    return jsonify({"success": True})

# ── Admin: list accounts ─────────────────────────────────────────
@app.route("/api/accounts", methods=["GET"])
def list_accounts():
    _require_admin()
    with get_db() as db:
        rows = db.execute(
            "SELECT id,username,email,name,role,department,blocked,created_at,created_by FROM users"
        ).fetchall()
    return jsonify({"accounts": [dict(r) for r in rows]})

# ── Admin: create account ────────────────────────────────────────
@app.route("/api/accounts", methods=["POST"])
def create_account():
    payload = _require_admin()
    data     = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "")
    name     = (data.get("name")     or "").strip()
    email    = (data.get("email")    or "").strip()
    role     = (data.get("role")     or "viewer").strip()
    dept     = (data.get("department") or "").strip()

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if not re.match(r"^[a-z][a-z0-9._-]{1,29}$", username):
        return jsonify({"error": "Username: 2–30 chars, start with a letter, a–z 0–9 . _ -"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if not email or "@" not in email:
        return jsonify({"error": "Valid email required"}), 400
    if role not in ("admin", "dispatch", "exco", "hod", "viewer"):
        return jsonify({"error": "Invalid role"}), 400

    pwh = bcrypt.hashpw(password.encode(), bcrypt.gensalt(BCRYPT_ROUNDS)).decode()
    uid = f"usr{secrets.token_hex(4)}"

    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO users(id,username,email,name,pwh,role,department,created_at,created_by) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (uid, username, email, name, pwh, role, dept, _now(), payload["sub"]),
            )
        return jsonify({"success": True, "id": uid}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409

# ── Admin: block / unblock ───────────────────────────────────────
@app.route("/api/accounts/<account_id>/block", methods=["POST"])
def set_blocked(account_id):
    payload = _require_admin()
    blocked = bool((request.get_json(silent=True) or {}).get("blocked", True))
    with get_db() as db:
        row = db.execute("SELECT username FROM users WHERE id = ?", (account_id,)).fetchone()
        if not row:
            return jsonify({"error": "Account not found"}), 404
        if row["username"] == payload["sub"]:
            return jsonify({"error": "You cannot block your own account"}), 400
        db.execute("UPDATE users SET blocked = ? WHERE id = ?", (int(blocked), account_id))
    return jsonify({"success": True, "blocked": blocked})

# ── Admin: reset another user's password ────────────────────────
@app.route("/api/accounts/<account_id>/reset-password", methods=["POST"])
def reset_password(account_id):
    payload  = _require_admin()
    new_pw   = ((request.get_json(silent=True) or {}).get("new_password") or "").encode()
    if len(new_pw) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    new_hash = bcrypt.hashpw(new_pw, bcrypt.gensalt(BCRYPT_ROUNDS)).decode()
    with get_db() as db:
        db.execute("UPDATE users SET pwh = ? WHERE id = ?", (new_hash, account_id))
        if row := db.execute("SELECT username FROM users WHERE id = ?", (account_id,)).fetchone():
            db.execute(
                "INSERT INTO password_log(username,changed_at,changed_by) VALUES(?,?,?)",
                (row["username"], _now(), payload["sub"]),
            )
    return jsonify({"success": True})

# ══════════════════════════════════════════════════════════════════════════════
# Zoho integration — OAuth, Desk tickets, Forms
# ══════════════════════════════════════════════════════════════════════════════
import urllib.parse
import urllib.request
import json as _json
import time

ZOHO_CFG_FILE = os.path.join(BASE_DIR, ".fva_zoho_config")

def _zoho_cfg():
    if os.path.exists(ZOHO_CFG_FILE):
        with open(ZOHO_CFG_FILE) as _f:
            return _json.load(_f)
    # Create a blank template on first access
    template = {
        "client_id":     "YOUR_ZOHO_CLIENT_ID",
        "client_secret": "YOUR_ZOHO_CLIENT_SECRET",
        "zoho_domain":   "zoho.com",
        "org_id":        "YOUR_ZOHO_DESK_ORG_ID",
        "dept_id":       "",
        "team_id":       "",
        "cc_emails":     ["aaolatotse1@gmail.com"],
        "form_url":      ""
    }
    with open(ZOHO_CFG_FILE, "w") as _f:
        _json.dump(template, _f, indent=2)
    print(f"[FVA] Created Zoho config template → {ZOHO_CFG_FILE}")
    return template

def _zoho_save_cfg(cfg):
    with open(ZOHO_CFG_FILE, "w") as _f:
        _json.dump(cfg, _f, indent=2)

# In-memory token — cleared on server restart (enforces per-session tokens)
_zoho_session = {"access_token": None, "expires_at": 0}

def _zoho_valid():
    return bool(_zoho_session["access_token"]) and time.time() < _zoho_session["expires_at"] - 30

# Redirect URI must match exactly what is registered in Zoho API Console.
# Register: http://localhost:5000/api/zoho/callback
ZOHO_REDIRECT_URI = "http://localhost:5000/api/zoho/callback"

# ── Zoho OAuth ────────────────────────────────────────────────────────────────

@app.route("/api/zoho/auth-url")
def zoho_auth_url():
    _require_admin()
    cfg = _zoho_cfg()
    if cfg.get("client_id", "").startswith("YOUR_"):
        return jsonify({"error": "Zoho client_id not configured in .fva_zoho_config"}), 400
    domain = cfg.get("zoho_domain", "zoho.com")
    # domain is passed via the OAuth 'state' parameter so the callback can read it
    # without embedding it in the redirect_uri (which would break URI matching).
    params = urllib.parse.urlencode({
        "scope":         "Desk.tickets.CREATE,Desk.tickets.READ,Desk.contacts.CREATE,"
                         "Desk.search.READ",
        "client_id":     cfg["client_id"],
        "response_type": "code",
        "redirect_uri":  ZOHO_REDIRECT_URI,
        "access_type":   "online",   # online = no refresh token = truly per-session
        "prompt":        "consent",
        "state":         domain,     # carries domain through the OAuth round-trip
    })
    return jsonify({"url": f"https://accounts.{domain}/oauth/v2/auth?{params}"})

@app.route("/api/zoho/callback")
def zoho_callback():
    code   = request.args.get("code", "")
    error  = request.args.get("error", "")
    domain = request.args.get("state", "zoho.com")  # domain we sent in state param

    _ERR = lambda msg: (
        f'<html><body style="font-family:\'Segoe UI\',sans-serif;background:#15191f;'
        f'color:#e7ebf0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0">'
        f'<div style="text-align:center;background:#1e2530;border:1px solid #2d3748;border-radius:16px;'
        f'padding:40px 36px;max-width:420px">'
        f'<h2 style="color:#fca5a5;margin:0 0 12px">Zoho Auth Failed</h2>'
        f'<p style="color:#8a9ab5;margin:0 0 24px">{msg}</p>'
        f'<button onclick="window.close()" style="background:#2d3748;color:#e7ebf0;border:none;'
        f'border-radius:8px;padding:10px 22px;font-size:14px;cursor:pointer">Close</button>'
        f'</div></body></html>'
    )

    if error:
        return _ERR(error)
    if not code:
        return _ERR("No authorization code received from Zoho.")

    cfg = _zoho_cfg()
    data = urllib.parse.urlencode({
        "code":          code,
        "client_id":     cfg.get("client_id", ""),
        "client_secret": cfg.get("client_secret", ""),
        "redirect_uri":  ZOHO_REDIRECT_URI,
        "grant_type":    "authorization_code",
    }).encode()

    req = urllib.request.Request(
        f"https://accounts.{domain}/oauth/v2/token", data=data, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            tok = _json.loads(resp.read())
    except Exception as ex:
        return _ERR(f"Token exchange failed: {ex}")

    if "access_token" not in tok:
        return _ERR(f"No access_token in Zoho response: {tok.get('error','unknown')}")

    _zoho_session["access_token"] = tok["access_token"]
    _zoho_session["expires_at"]   = time.time() + int(tok.get("expires_in", 3600))

    return (
        '<html><body style="font-family:\'Segoe UI\',sans-serif;background:#15191f;'
        'color:#e7ebf0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0">'
        '<div style="text-align:center;background:#1e2530;border:1px solid #2d3748;border-radius:16px;'
        'padding:40px 36px;max-width:380px">'
        '<div style="width:60px;height:60px;border-radius:50%;background:rgba(34,197,94,.15);'
        'border:2px solid #22c55e;display:inline-flex;align-items:center;justify-content:center;'
        'margin-bottom:18px">'
        '<svg viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2.5" stroke-linecap="round"'
        ' style="width:28px;height:28px"><polyline points="20 6 9 17 4 12"/></svg></div>'
        '<h2 style="margin:0 0 8px;font-size:20px">Zoho Connected</h2>'
        '<p style="color:#8a9ab5;margin:0 0 24px;font-size:13px">'
        'You can now create tickets. This session token expires in 1 hour.<br>'
        'You will need to reconnect next session.</p>'
        '<button onclick="window.close()" style="background:#3b82f6;color:#fff;border:none;'
        'border-radius:10px;padding:11px 28px;font-size:14px;font-weight:600;cursor:pointer">'
        'Close &amp; Return</button>'
        '</div></body></html>'
    )

@app.route("/api/zoho/status")
def zoho_status():
    _require_auth()
    valid = _zoho_valid()
    return jsonify({
        "connected":  valid,
        "expires_at": _zoho_session["expires_at"] if valid else None,
        "expires_in": max(0, int(_zoho_session["expires_at"] - time.time())) if valid else 0,
    })

@app.route("/api/zoho/revoke", methods=["POST"])
def zoho_revoke():
    _require_auth()
    _zoho_session["access_token"] = None
    _zoho_session["expires_at"]   = 0
    return jsonify({"success": True})

# ── Zoho Desk — create ticket ─────────────────────────────────────────────────

@app.route("/api/zoho/ticket", methods=["POST"])
def create_zoho_ticket():
    payload = _require_admin()
    if not _zoho_valid():
        return jsonify({"error": "Zoho session expired — please reconnect."}), 401

    data        = request.get_json(silent=True) or {}
    subject     = (data.get("subject")     or "").strip()
    description = (data.get("description") or "").strip()
    priority    = data.get("priority",  "Medium")
    category    = data.get("category",  "Fuel Variance")

    if not subject:
        return jsonify({"error": "Subject is required"}), 400

    cfg    = _zoho_cfg()
    org_id = cfg.get("org_id", "")
    domain = cfg.get("zoho_domain", "zoho.com")

    if not org_id or org_id.startswith("YOUR_"):
        return jsonify({"error": "Zoho org_id not set in .fva_zoho_config"}), 400

    name_parts = (payload.get("name") or payload["sub"]).split()
    ticket = {
        "subject":     subject,
        "description": description,
        "priority":    priority,
        "channel":     "Web",
        "status":      "Open",
        "cf": {"cf_category": category},
        "contact": {
            "firstName": name_parts[0],
            "lastName":  " ".join(name_parts[1:]) or "-",
            "email":     payload.get("email", ""),
        },
    }

    if cfg.get("dept_id"):
        ticket["departmentId"] = cfg["dept_id"]
    if cfg.get("team_id"):
        ticket["teamId"] = cfg["team_id"]

    headers = {
        "Authorization": f"Zoho-oauthtoken {_zoho_session['access_token']}",
        "orgId":         org_id,
        "Content-Type":  "application/json",
    }
    req = urllib.request.Request(
        f"https://desk.{domain}/api/v1/tickets",
        data=_json.dumps(ticket).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = _json.loads(resp.read())
    except urllib.error.HTTPError as ex:
        body = ex.read().decode()
        return jsonify({"error": f"Zoho Desk: {body}"}), ex.code
    except Exception as ex:
        return jsonify({"error": str(ex)}), 500

    ticket_id = result.get("id", "")
    ticket_no = result.get("ticketNumber", "")

    # Add CC recipients as followers (best-effort — ignore failures)
    cc = cfg.get("cc_emails", [])
    if cc and ticket_id:
        fl_req = urllib.request.Request(
            f"https://desk.{domain}/api/v1/tickets/{ticket_id}/addFollowers",
            data=_json.dumps({"followers": [{"email": e} for e in cc]}).encode(),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(fl_req, timeout=10) as _:
                pass
        except Exception:
            pass   # followers are best-effort; ticket creation already succeeded

    return jsonify({"success": True, "ticket_number": ticket_no, "ticket_id": ticket_id})

# ── Investigation Report — create Zoho Desk ticket with full report ───────────

@app.route("/api/report/submit", methods=["POST"])
def submit_investigation_report():
    payload = _require_auth()
    data = request.get_json(silent=True) or {}

    vehicle   = data.get("vehicleReg", "")
    load_date = data.get("loadDate", "")
    gain_loss = data.get("gainLossL", "")
    gain_pct  = data.get("gainLossPct", "")
    excess    = data.get("excess", "")
    inv_by    = data.get("investigatedBy", "").strip()

    if not inv_by:
        return jsonify({"error": "investigatedBy is required"}), 400

    def row(label, value): return f"  {label:<28}: {value}"

    causes = data.get("rootCauses") or []
    causes_str = ", ".join(causes) if causes else "—"

    lines = [
        "FUEL VARIANCE INVESTIGATION REPORT",
        "Sky Bridge Logistics — Performance Analysis Division",
        "=" * 60,
        "",
        "STATUS: " + (data.get("status") or "FLAGGED FOR INVESTIGATION"),
        "",
        "1. VEHICLE & TRIP DETAILS",
        row("Vehicle Registration",  vehicle),
        row("Driver",                data.get("driverName", "—")),
        row("Contract / Route",      data.get("contractRoute", "—")),
        row("Loading Depot",         data.get("loadingDepot", "—")),
        row("Offloading Depot",      data.get("offloadingDepot", "—")),
        row("Product",               data.get("product", "—")),
        row("Load Date",             load_date),
        "",
        "2. VARIANCE ANALYSIS",
        row("Loaded Volume (L)",     data.get("loadedVolume", "—")),
        row("Offloaded Volume (L)",  data.get("offloadedVolume", "—")),
        row("Gain / Loss (L)",       gain_loss),
        row("Gain / Loss (%)",       gain_pct),
        row("Tolerance Allowed",     data.get("tolerance", "—")),
        row("Excess Beyond Tol.",    excess or "—"),
        "",
        "3. INVESTIGATION DETAILS",
        row("Investigated By",       inv_by),
        row("Date of Investigation", data.get("investigationDate", "—")),
        row("Driver Statement",      data.get("driverStatement", "—")),
        row("Zoho Ticket Ref",       data.get("zohoTicketRef", "—")),
        "",
        "4. FINDINGS",
        (data.get("findings") or "—"),
        "",
        "5. SUSPECTED ROOT CAUSE",
        causes_str,
        "",
        "6. CORRECTIVE ACTION TAKEN",
        (data.get("correctiveAction") or "—"),
        "",
        "7. EVIDENCE NOTES",
        row("Photo 1",  data.get("photo1Desc") or "—"),
        row("Photo 2",  data.get("photo2Desc") or "—"),
        row("Photo 3",  data.get("photo3Desc") or "—"),
        "",
        "8. SIGN-OFF",
        row("Investigator",          f"{data.get('investigatorName','—')} | {data.get('investigatorDept','—')} | {data.get('investigatorDate','—')}"),
        row("Supervisor",            f"{data.get('supervisorName','—')} | {data.get('supervisorDept','—')} | {data.get('supervisorDate','—')}"),
        "",
        "=" * 60,
        "Generated by Fuel Variance Audit System — Sky Bridge Logistics",
    ]
    description = "\n".join(lines)
    subject = f"Fuel Variance Investigation Report — {vehicle} — {load_date}"

    # If Zoho is connected, create a Desk ticket (Desk will email the team)
    if _zoho_valid():
        cfg    = _zoho_cfg()
        org_id = cfg.get("org_id", "")
        domain = cfg.get("zoho_domain", "zoho.com")
        name_parts = (payload.get("name") or payload["sub"]).split()
        ticket = {
            "subject":     subject,
            "description": description,
            "priority":    "High",
            "channel":     "Web",
            "status":      "Open",
            "contact": {
                "firstName": name_parts[0],
                "lastName":  " ".join(name_parts[1:]) or "-",
                "email":     payload.get("email", ""),
            },
        }
        if cfg.get("dept_id"):
            ticket["departmentId"] = cfg["dept_id"]
        headers = {
            "Authorization": f"Zoho-oauthtoken {_zoho_session['access_token']}",
            "orgId":         org_id,
            "Content-Type":  "application/json",
        }
        req = urllib.request.Request(
            f"https://desk.{domain}/api/v1/tickets",
            data=_json.dumps(ticket).encode(),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = _json.loads(resp.read())
            ticket_no = result.get("ticketNumber", "")
            ticket_id = result.get("id", "")
            # CC follow-up
            cc = cfg.get("cc_emails", [])
            if cc and ticket_id:
                try:
                    fl_req = urllib.request.Request(
                        f"https://desk.{domain}/api/v1/tickets/{ticket_id}/addFollowers",
                        data=_json.dumps({"followers": [{"email": e} for e in cc]}).encode(),
                        headers=headers, method="POST",
                    )
                    with urllib.request.urlopen(fl_req, timeout=10) as _: pass
                except Exception: pass
            return jsonify({"success": True, "ticket_number": ticket_no, "ticket_id": ticket_id})
        except urllib.error.HTTPError as ex:
            body = ex.read().decode()
            return jsonify({"error": f"Zoho Desk error: {body}"}), ex.code
        except Exception as ex:
            return jsonify({"error": str(ex)}), 500

    # Zoho not connected — return the report text so the client can handle it
    return jsonify({"error": "Zoho not connected — please connect via the Zoho panel first, then resubmit."}), 401

# ── Zoho Forms — return shareable form URL ────────────────────────────────────

@app.route("/api/zoho/form-url")
def zoho_form_url():
    _require_auth()
    cfg = _zoho_cfg()
    url = cfg.get("form_url", "")
    if not url:
        return jsonify({"error": "form_url not configured in .fva_zoho_config"}), 404
    return jsonify({"url": url})

# ── Zoho config management (admin only) ──────────────────────────────────────

@app.route("/api/zoho/config", methods=["GET"])
def get_zoho_config():
    _require_admin()
    cfg  = _zoho_cfg()
    safe = {k: v for k, v in cfg.items() if k != "client_secret"}
    safe["client_secret"] = "***" if cfg.get("client_secret") else ""
    safe["connected"] = _zoho_valid()
    return jsonify(safe)

@app.route("/api/zoho/config", methods=["POST"])
def save_zoho_config():
    _require_admin()
    data = request.get_json(silent=True) or {}
    cfg  = _zoho_cfg()
    for key in ("client_id", "org_id", "dept_id", "team_id", "zoho_domain", "form_url"):
        if key in data:
            cfg[key] = (data[key] or "").strip()
    if data.get("client_secret") and data["client_secret"] != "***":
        cfg["client_secret"] = data["client_secret"].strip()
    if "cc_emails" in data:
        cfg["cc_emails"] = [e.strip() for e in data["cc_emails"] if e.strip()]
    _zoho_save_cfg(cfg)
    return jsonify({"success": True})

# ── Proxy for React bundle's localhost:3030 calls ────────────────────────────
# The React bundle tries http://localhost:3030 as a ticket-creation proxy.
# Our fetch interceptor in the HTML redirects those calls here instead.

@app.route("/_proxy/ping")
def proxy_ping():
    return jsonify({"ok": True})

@app.route("/_proxy/zoho/v1/tickets", methods=["POST"])
def proxy_zoho_tickets():
    if not _zoho_valid():
        return jsonify({
            "errorCode": "OAUTH_EXPIRED",
            "message": "Zoho session expired — reconnect via the Create Ticket panel first."
        }), 401

    data   = request.get_json(silent=True) or {}
    cfg    = _zoho_cfg()
    org_id = cfg.get("org_id", "")
    domain = cfg.get("zoho_domain", "zoho.com")

    headers = {
        "Authorization": f"Zoho-oauthtoken {_zoho_session['access_token']}",
        "orgId":         org_id,
        "Content-Type":  "application/json",
    }
    req = urllib.request.Request(
        f"https://desk.{domain}/api/v1/tickets",
        data=_json.dumps(data).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = _json.loads(resp.read())
    except urllib.error.HTTPError as ex:
        body = ex.read().decode()
        try:
            err_data = _json.loads(body)
        except Exception:
            err_data = {"message": body}
        return jsonify(err_data), ex.code
    except Exception as ex:
        return jsonify({"message": str(ex)}), 500

    return jsonify(result)

# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("=" * 52)
    print("  FVA Auth Server  —  http://localhost:5000")
    print("  Default password:  FuelAudit@2026!")
    print("  Stop with:         Ctrl+C")
    print("=" * 52)
    app.run(host="0.0.0.0", port=5000, debug=False)

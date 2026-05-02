import os
import sys
import time
import secrets
import logging
import functools
from datetime import timedelta
from collections import defaultdict

from flask import Flask, render_template, jsonify, request, redirect, url_for, session, abort
from flask_socketio import SocketIO, emit
from werkzeug.security import check_password_hash

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config import (
    SECRET_KEY, DASHBOARD_USER, DASHBOARD_PASS_HASH,
    SESSION_LIFETIME_MINUTES, MAX_LOGIN_ATTEMPTS, LOGIN_BLOCK_SECONDS,
)
from database.models import get_recent_attacks, get_stats, get_map_points, get_intel_summary
from intelligence.mitre import get_all_techniques
from intelligence.reputation import rank_threats, detect_campaigns

app     = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = SECRET_KEY
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=SESSION_LIFETIME_MINUTES)
socketio = SocketIO(app, cors_allowed_origins=[], async_mode="threading")

logger = logging.getLogger(__name__)

_login_attempts: dict[str, list[float]] = defaultdict(list)


def _is_rate_limited(ip: str) -> bool:
    now = time.time()
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < LOGIN_BLOCK_SECONDS]
    return len(_login_attempts[ip]) >= MAX_LOGIN_ATTEMPTS


def _record_failed_login(ip: str) -> None:
    _login_attempts[ip].append(time.time())


@app.after_request
def _set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


def _generate_csrf_token() -> str:
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


app.jinja_env.globals["csrf_token"] = _generate_csrf_token

def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        client_ip = request.remote_addr or "unknown"
        if _is_rate_limited(client_ip):
            error = "Too many login attempts. Try again later."
            return render_template("login.html", error=error), 429
        token = session.get("_csrf_token")
        if not token or token != request.form.get("_csrf_token"):
            abort(403)
        if (request.form.get("username") == DASHBOARD_USER and
                check_password_hash(DASHBOARD_PASS_HASH, request.form.get("password", ""))):
            session.permanent = True
            session["logged_in"] = True
            session.pop("_csrf_token", None)
            return redirect(url_for("index"))
        _record_failed_login(client_ip)
        error = "Invalid credentials"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/attacks")
@login_required
def attacks_page():
    return render_template("attacks.html")

@app.route("/intelligence")
@login_required
def intelligence_page():
    return render_template("intelligence.html")

@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify(get_stats())

@app.route("/api/attacks")
@login_required
def api_attacks():
    try:
        limit = min(int(request.args.get("limit", 200)), 1000)
    except (ValueError, TypeError):
        limit = 200
    return jsonify(get_recent_attacks(limit))

@app.route("/api/map")
@login_required
def api_map():
    return jsonify(get_map_points())

@app.route("/api/intel")
@login_required
def api_intel():
    summary = get_intel_summary()
    summary["techniques"] = get_all_techniques()
    return jsonify(summary)

@app.route("/api/health")
def api_health():
    return jsonify({"status": "ok", "version": "2.0"})

@app.route("/api/threats")
@login_required
def api_threats():
    all_attacks = get_recent_attacks(5000)
    top_threats = rank_threats(all_attacks, top_n=20)
    campaigns   = detect_campaigns(all_attacks)
    return jsonify({"top_threats": top_threats, "campaigns": campaigns})

@socketio.on("connect")
def on_connect():
    logger.debug("Dashboard client connected: %s", request.sid)

def broadcast_attack(attack: dict) -> None:
    socketio.emit("new_attack", attack, namespace="/")


def run(host: str = "0.0.0.0", port: int = 5000, debug: bool = False) -> None:
    socketio.run(app, host=host, port=port, debug=debug, use_reloader=False,
                 log_output=False)

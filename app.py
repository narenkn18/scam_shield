"""ScamShield Flask app: routes, validation, rate limiting, security headers."""
import logging
import threading
import time
from collections import defaultdict, deque
from datetime import date
from functools import wraps

from flask import Flask, jsonify, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix

import analyzer
import config
import recovery

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# Locally Flask serves ./public at the site root. On Vercel the CDN serves public/** before Flask is called.
app = Flask(__name__, static_folder="public", static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = config.MAX_IMAGE_BYTES + 256 * 1024  # image + form fields
# Trust one proxy hop (Render, Cloud Run) so rate limiting sees the real client IP.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# ----------------------------------------------------------------- rate limiting
_hits = defaultdict(deque)
_daily = {"day": None, "count": 0}
_lock = threading.Lock()


def limited(fn):
    """Per-IP sliding window (per minute) plus a global daily cap to protect the API quota."""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        now = time.time()
        ip = request.remote_addr or "unknown"
        with _lock:
            today = date.today()
            if _daily["day"] != today:
                _daily["day"], _daily["count"] = today, 0
            if _daily["count"] >= config.DAILY_REQUEST_CAP:
                return jsonify(error="Today's demo limit has been reached. Please try again tomorrow."), 429
            if len(_hits) > 1000:  # drop idle clients so memory cannot grow without bound
                for stale in [k for k, v in _hits.items() if not v or now - v[-1] > 60]:
                    del _hits[stale]
            q = _hits[ip]
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= config.RATE_LIMIT_PER_MIN:
                retry = int(60 - (now - q[0])) + 1
                resp = jsonify(error=f"Too many requests. Please wait {retry} seconds and try again.")
                resp.status_code = 429
                resp.headers["Retry-After"] = str(retry)
                return resp
            q.append(now)
            _daily["count"] += 1
        return fn(*args, **kwargs)

    return wrapper


# ----------------------------------------------------------------- helpers
def _image_mime(data):
    """Detect the real image type from magic bytes instead of trusting the upload's label."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def _bad(message, status=400):
    return jsonify(error=message), status


# ----------------------------------------------------------------- routes
@app.get("/")
def index():
    return render_template("index.html", max_chars=config.MAX_TEXT_CHARS, max_mb=config.MAX_IMAGE_MB)


@app.get("/health")
def health():
    """Deployment check: confirms the prompt files were bundled and a key is configured (never shows the key)."""
    prompts_ok = config.PROMPT_FILE.exists() and config.RECOVERY_PROMPT_FILE.exists()
    return jsonify(status="ok" if prompts_ok else "degraded", prompts_loaded=prompts_ok,
                   api_key_configured=bool(config.GEMINI_API_KEY),
                   safe_browsing_configured=bool(config.SAFE_BROWSING_API_KEY), model=config.MODEL)


@app.post("/api/analyze")
@limited
def api_analyze():
    text = (request.form.get("text") or "").strip()
    language = request.form.get("language", "en")
    mode = request.form.get("mode", "simple")
    upload = request.files.get("image")

    if language not in config.LANGUAGES:
        return _bad("Unsupported language.")
    if mode not in config.MODES:
        return _bad("Unsupported mode.")
    if len(text) > config.MAX_TEXT_CHARS:
        return _bad(f"That message is too long. Please keep it under {config.MAX_TEXT_CHARS} characters.")

    image_bytes = image_mime = None
    if upload and upload.filename:
        image_bytes = upload.read(config.MAX_IMAGE_BYTES + 1)
        if len(image_bytes) > config.MAX_IMAGE_BYTES:
            return _bad(f"That image is too large. Maximum size is {config.MAX_IMAGE_MB:g} MB.", 413)
        image_mime = _image_mime(image_bytes)
        if not image_mime:
            return _bad("Please upload a PNG, JPG or WebP screenshot.")

    if not text and not image_bytes:
        return _bad("Paste a message or link, or upload a screenshot first.")

    try:
        return jsonify(analyzer.analyze(text, language, mode, image_bytes, image_mime))
    except analyzer.AnalyzerError as e:
        return _bad(e.message, e.status)


@app.post("/api/recovery")
@limited
def api_recovery():
    body = request.get_json(silent=True) or {}
    actions = body.get("actions") or []
    language = body.get("language", "en")
    details = str(body.get("details") or "").strip()[:600]
    amount = str(body.get("amount") or "").strip()[:60]

    if not isinstance(actions, list):
        return _bad("Invalid request.")
    actions = [a for a in actions if a in recovery.ACTIONS]
    if not actions:
        return _bad("Tick at least one thing that happened.")
    if language not in config.LANGUAGES:
        return _bad("Unsupported language.")

    try:
        return jsonify(analyzer.recovery_plan(actions, language, details, amount))
    except analyzer.AnalyzerError:
        # Never leave someone in a panic without a plan: fall back to the built-in English steps.
        plan = recovery.build_static_plan(actions, details, amount)
        plan["note"] = "The AI helper is unavailable, so here is the built-in plan in English."
        return jsonify(plan)


# ----------------------------------------------------------------- errors & headers
@app.errorhandler(413)
def too_large(_):
    return _bad(f"That upload is too large. Maximum image size is {config.MAX_IMAGE_MB:g} MB.", 413)


@app.errorhandler(404)
def not_found(_):
    return _bad("Not found.", 404)


@app.errorhandler(500)
def server_error(_):
    return _bad("Something went wrong on our side. Please try again.", 500)


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.is_secure:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data: blob:; "
        "style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
        "script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'"
    )
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


if __name__ == "__main__":
    import os

    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=os.getenv("FLASK_DEBUG") == "1")

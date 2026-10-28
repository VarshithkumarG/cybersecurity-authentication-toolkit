import os
import re
import sqlite3
import secrets
import hmac
from contextlib import contextmanager
from pathlib import Path

from flask import Flask, abort, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

ROOT = Path(__file__).resolve().parent
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("APP_SECRET") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
)

def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_posts():
    if request.method == "POST":
        expected = session.get("csrf", "")
        supplied = request.form.get("csrf_token", "")
        if not expected or not hmac.compare_digest(expected, supplied):
            abort(400, "Invalid request token.")

PAGE = """<!doctype html><title>Authentication Toolkit</title><main><h1>Authentication Toolkit</h1>
<p>Local learning prototype. Use a unique test password.</p>{% if message %}<p role="status">{{ message }}</p>{% endif %}
{% if user %}<p>Signed in as {{ user }}</p><form method="post" action="/logout"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button>Log out</button></form>
{% else %}<form method="post" action="/register"><h2>Create account</h2><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><label>Email <input name="email" type="email" required></label>
<label>Password <input name="password" type="password" minlength="12" required></label><button>Register</button></form>
<form method="post" action="/login"><h2>Sign in</h2><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><label>Email <input name="email" type="email" required></label>
<label>Password <input name="password" type="password" required></label><button>Sign in</button></form>{% endif %}</main>"""


@contextmanager
def connect():
    path = ROOT / "instance" / "users.sqlite3"
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    try:
        with db:
            db.execute("CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, password_hash TEXT NOT NULL)")
            yield db
    finally:
        db.close()


def valid_password(value):
    return isinstance(value, str) and len(value) >= 12 and len(value) <= 256


@app.get("/")
def index():
    return render_template_string(PAGE, user=session.get("email"), message=request.args.get("m"))


@app.post("/register")
def register():
    email, password = request.form.get("email", "").strip().lower(), request.form.get("password", "")
    if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or not valid_password(password):
        abort(400, "Enter a valid email and a password of at least 12 characters.")
    try:
        with connect() as db:
            db.execute("INSERT INTO users VALUES (?, ?)", (email, generate_password_hash(password)))
    except sqlite3.IntegrityError:
        return redirect(url_for("index", m="Account could not be created with those details."))
    session.clear()
    session["email"] = email
    return redirect(url_for("index", m="Account created."))


@app.post("/login")
def login():
    email, password = request.form.get("email", "").strip().lower(), request.form.get("password", "")
    with connect() as db:
        row = db.execute("SELECT password_hash FROM users WHERE email=?", (email,)).fetchone()
    if not row or not check_password_hash(row[0], password):
        return redirect(url_for("index", m="Email or password is incorrect."))
    session.clear()
    session["email"] = email
    return redirect(url_for("index", m="Signed in."))


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("index", m="Signed out."))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)


# Cybersecurity Authentication Toolkit

A local Flask prototype for registration, password strength feedback, secure password storage, login, and session lifecycle controls.

## Problem and objective

Weak password handling and poorly managed sessions make accounts easy to compromise. This project demonstrates a small, reviewable authentication flow with password hashing, signed sessions, and basic input validation.

## Features

- Register and sign in with validated email addresses and a minimum 12-character password.
- PBKDF2-SHA256 salted password hashes using Werkzeug.
- Signed Flask sessions with HttpOnly, SameSite cookies; Secure cookies can be enabled behind HTTPS.
- Session logout, generic authentication errors, and a simple password strength indicator.

## Technology

Python 3.10+, Flask, Flask-Session, Werkzeug, SQLite.

## Setup and run

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. Set `APP_SECRET` to a random secret before use. Set `COOKIE_SECURE=1` when serving through HTTPS. The development server is for local demonstration only.

## How it works

Registration normalizes and validates the email, checks password length, hashes the password through Werkzeug, and stores only the hash in SQLite. Login compares the submitted password with the stored hash and clears the previous session state. The authenticated page checks the signed session; logout clears it. POST requests require a session-bound CSRF token.

## Screenshots and demo

No screenshots or hosted demo are included yet. Run locally and capture the registration, authenticated page, and logout flow for a visual demo.

## Tests

Run `python -m unittest discover -s tests -v` from this repository root.

## Security considerations

This is an educational prototype, not a production identity service. Add email verification, recovery flows, rate limiting, monitoring, database migration/backups, and deployment hardening before production. Signed cookie sessions are not server-side revocable before expiry, so use a dedicated session store in production. Never expose the development server.

## Future improvements

Add MFA, password breach checks, account lockout with abuse-safe recovery, security event audit logs, and integration tests.


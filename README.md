# aiohttp security demo

A simple login/logout backend and frontend built with **aiohttp** and **JWT**.

## Features

- Multiple in-memory users (`alice`, `bob`, `charlie`)
- `POST /api/login` returns a JWT on successful login
- `GET /api/me` is protected and requires a bearer token
- `POST /api/logout` revokes the current token (`jti`) server-side
- Static frontend to test auth flow in browser

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open: http://localhost:8080

## Example users

- `alice / alice123`
- `bob / bob123`
- `charlie / charlie123`

import os
import time
import uuid
import hmac
import sqlite3
from pathlib import Path

import jwt
from aiohttp import web


USERS = {
    "alice": {"password": "alice123", "name": "Alice"},
    "bob": {"password": "bob123", "name": "Bob"},
    "charlie": {"password": "charlie123", "name": "Charlie"},
}

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_SECONDS = 60 * 30
ALLOW_INSECURE_DEMO = os.getenv("ALLOW_INSECURE_DEMO", "false").lower() == "true"
REVOCATION_DB_PATH = os.getenv("REVOCATION_DB_PATH", "revoked_tokens.db")


class RevocationStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._initialize()

    def _initialize(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS revoked_tokens (
                    jti TEXT PRIMARY KEY,
                    revoked_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                )
                """
            )
            conn.commit()

    def revoke(self, jti: str, expires_at: int) -> None:
        revoked_at = int(time.time())
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO revoked_tokens (jti, revoked_at, expires_at)
                VALUES (?, ?, ?)
                """,
                (jti, revoked_at, expires_at),
            )
            conn.commit()

    def is_revoked(self, jti: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,)
            ).fetchone()
        return row is not None

    def purge_expired(self) -> None:
        now = int(time.time())
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM revoked_tokens WHERE expires_at < ?", (now,))
            conn.commit()


REVOCATION_STORE = RevocationStore(REVOCATION_DB_PATH)



def _build_token(username: str) -> str:
    now = int(time.time())
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + JWT_EXPIRE_SECONDS,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)



def _decode_token(token: str) -> dict:
    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    jti = payload.get("jti")
    if not jti or REVOCATION_STORE.is_revoked(jti):
        raise jwt.InvalidTokenError("Token has been revoked")
    return payload


def _security_headers(response: web.StreamResponse) -> None:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'"


@web.middleware
async def auth_middleware(request: web.Request, handler):
    if request.path.startswith("/api") and request.path not in {"/api/login"}:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return web.json_response({"error": "Missing bearer token"}, status=401)

        token = auth_header.split(" ", 1)[1]
        try:
            payload = _decode_token(token)
        except jwt.PyJWTError:
            return web.json_response({"error": "Invalid or expired token"}, status=401)

        request["user"] = payload["sub"]
        request["jti"] = payload["jti"]
        request["exp"] = payload["exp"]

    response = await handler(request)
    _security_headers(response)
    return response


async def login(request: web.Request) -> web.Response:
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"error": "Invalid JSON body"}, status=400)

    if not isinstance(body, dict):
        return web.json_response({"error": "Invalid JSON body"}, status=400)

    username = body.get("username", "").strip().lower()
    password = body.get("password", "")

    if not isinstance(password, str):
        return web.json_response({"error": "Invalid credentials"}, status=401)

    user = USERS.get(username)
    stored_password = user["password"] if user else ""
    if not user or not hmac.compare_digest(stored_password, password):
        return web.json_response({"error": "Invalid credentials"}, status=401)

    token = _build_token(username)
    return web.json_response(
        {
            "token": token,
            "user": {
                "username": username,
                "name": user["name"],
            },
        }
    )


async def logout(request: web.Request) -> web.Response:
    REVOCATION_STORE.revoke(request["jti"], request["exp"])
    return web.json_response({"message": "Logged out successfully"})


async def me(request: web.Request) -> web.Response:
    username = request["user"]
    user = USERS[username]
    return web.json_response({"username": username, "name": user["name"]})


async def index(request: web.Request) -> web.Response:
    html = Path("static/index.html").read_text(encoding="utf-8")
    return web.Response(text=html, content_type="text/html")



def create_app() -> web.Application:
    if JWT_SECRET == "dev-secret-change-me" and not ALLOW_INSECURE_DEMO:
        raise RuntimeError(
            "Refusing to start with insecure default JWT_SECRET. "
            "Set JWT_SECRET to a strong value or set ALLOW_INSECURE_DEMO=true for local demos."
        )

    REVOCATION_STORE.purge_expired()

    app = web.Application(middlewares=[auth_middleware], client_max_size=16 * 1024)
    app.router.add_get("/", index)
    app.router.add_static("/static", path="static", show_index=False)
    app.router.add_post("/api/login", login)
    app.router.add_post("/api/logout", logout)
    app.router.add_get("/api/me", me)
    return app


if __name__ == "__main__":
    web.run_app(create_app(), host="0.0.0.0", port=8080)

import os
import time
import uuid
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

REVOKED_JTIS: set[str] = set()



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
    if not jti or jti in REVOKED_JTIS:
        raise jwt.InvalidTokenError("Token has been revoked")
    return payload


@web.middleware
async def auth_middleware(request: web.Request, handler):
    if request.path.startswith("/api") and request.path not in {"/api/login"}:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return web.json_response({"error": "Missing bearer token"}, status=401)

        token = auth_header.split(" ", 1)[1]
        try:
            payload = _decode_token(token)
        except jwt.PyJWTError as err:
            return web.json_response({"error": str(err)}, status=401)

        request["user"] = payload["sub"]
        request["jti"] = payload["jti"]

    return await handler(request)


async def login(request: web.Request) -> web.Response:
    body = await request.json()
    username = body.get("username", "").strip().lower()
    password = body.get("password", "")

    user = USERS.get(username)
    if not user or user["password"] != password:
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
    REVOKED_JTIS.add(request["jti"])
    return web.json_response({"message": "Logged out successfully"})


async def me(request: web.Request) -> web.Response:
    username = request["user"]
    user = USERS[username]
    return web.json_response({"username": username, "name": user["name"]})


async def index(request: web.Request) -> web.Response:
    html = Path("static/index.html").read_text(encoding="utf-8")
    return web.Response(text=html, content_type="text/html")



def create_app() -> web.Application:
    app = web.Application(middlewares=[auth_middleware])
    app.router.add_get("/", index)
    app.router.add_static("/static", path="static", show_index=False)
    app.router.add_post("/api/login", login)
    app.router.add_post("/api/logout", logout)
    app.router.add_get("/api/me", me)
    return app


if __name__ == "__main__":
    web.run_app(create_app(), host="0.0.0.0", port=8080)

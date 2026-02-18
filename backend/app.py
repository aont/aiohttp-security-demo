import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from aiohttp import web
from aiohttp_security import (
    AbstractAuthorizationPolicy,
    AbstractIdentityPolicy,
    authorized_userid,
    forget,
    remember,
    setup as setup_security,
)


JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_MINUTES = 60
JWT_COOKIE_NAME = "auth_token"


# Demo in-memory users. In production, move this into a database.
USERS = {
    "alice": {"password": "alice123", "roles": {"user"}, "display_name": "Alice"},
    "bob": {"password": "bob123", "roles": {"user", "admin"}, "display_name": "Bob"},
    "carol": {"password": "carol123", "roles": {"user"}, "display_name": "Carol"},
}


class JWTIdentityPolicy(AbstractIdentityPolicy):
    def __init__(self, secret: str, *, cookie_name: str = JWT_COOKIE_NAME):
        self.secret = secret
        self.cookie_name = cookie_name

    async def identify(self, request: web.Request) -> Optional[str]:
        token = request.cookies.get(self.cookie_name)
        if not token:
            return None

        try:
            payload = jwt.decode(token, self.secret, algorithms=[JWT_ALGORITHM])
        except jwt.PyJWTError:
            return None

        return payload.get("sub")

    async def remember(self, request: web.Request, response: web.StreamResponse, identity: str, **kwargs) -> None:
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRY_MINUTES)
        token = jwt.encode(
            {
                "sub": identity,
                "iat": datetime.now(timezone.utc),
                "exp": expires_at,
            },
            self.secret,
            algorithm=JWT_ALGORITHM,
        )

        response.set_cookie(
            self.cookie_name,
            token,
            httponly=True,
            secure=False,  # Set True when served over HTTPS.
            samesite="Lax",
            max_age=JWT_EXPIRY_MINUTES * 60,
            path="/",
        )

    async def forget(self, request: web.Request, response: web.StreamResponse) -> None:
        response.del_cookie(self.cookie_name, path="/")


class DemoAuthorizationPolicy(AbstractAuthorizationPolicy):
    async def authorized_userid(self, identity: str) -> Optional[str]:
        if identity in USERS:
            return identity
        return None

    async def permits(self, identity: Optional[str], permission: str, context=None) -> bool:
        if not identity or identity not in USERS:
            return False

        if permission == "authenticated":
            return True

        return permission in USERS[identity]["roles"]


def _public_user(username: str) -> dict:
    user = USERS[username]
    return {
        "username": username,
        "displayName": user["display_name"],
        "roles": sorted(user["roles"]),
    }


async def login(request: web.Request) -> web.Response:
    data = await request.json()
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not username or not password:
        return web.json_response({"error": "Username and password are required"}, status=400)

    if username not in USERS or USERS[username]["password"] != password:
        return web.json_response({"error": "Invalid credentials"}, status=401)

    response = web.json_response(
        {
            "message": "Login successful",
            "user": _public_user(username),
        }
    )
    await remember(request, response, username)
    return response


async def logout(request: web.Request) -> web.Response:
    response = web.json_response({"message": "Logout successful"})
    await forget(request, response)
    return response


async def me(request: web.Request) -> web.Response:
    user_id = await authorized_userid(request)
    if not user_id:
        return web.json_response({"error": "Unauthorized"}, status=401)

    return web.json_response(_public_user(user_id))


async def users_list(request: web.Request) -> web.Response:
    user_id = await authorized_userid(request)
    if not user_id:
        return web.json_response({"error": "Unauthorized"}, status=401)

    return web.json_response({"users": [_public_user(username) for username in USERS]})


async def demo_users(request: web.Request) -> web.Response:
    return web.json_response({"users": [_public_user(username) for username in USERS]})


async def create_app() -> web.Application:
    app = web.Application()

    setup_security(
        app,
        identity_policy=JWTIdentityPolicy(JWT_SECRET),
        autz_policy=DemoAuthorizationPolicy(),
    )

    app.router.add_post("/api/login", login)
    app.router.add_post("/api/logout", logout)
    app.router.add_get("/api/me", me)
    app.router.add_get("/api/users", users_list)
    app.router.add_get("/api/demo-users", demo_users)

    frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")

    async def index(_: web.Request) -> web.FileResponse:
        return web.FileResponse(os.path.join(frontend_dir, "index.html"))

    app.router.add_get("/", index)
    app.router.add_static("/static/", frontend_dir, show_index=False)

    return app


if __name__ == "__main__":
    web.run_app(create_app(), host="0.0.0.0", port=8080)

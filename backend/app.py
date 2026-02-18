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
    "alice": {"password": "alice123", "roles": {"user"}},
    "bob": {"password": "bob123", "roles": {"user", "admin"}},
    "carol": {"password": "carol123", "roles": {"user"}},
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


async def login(request: web.Request) -> web.Response:
    data = await request.json()
    username = data.get("username", "")
    password = data.get("password", "")

    if username not in USERS or USERS[username]["password"] != password:
        return web.json_response({"error": "Invalid credentials"}, status=401)

    response = web.json_response({"message": "Login successful", "username": username})
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

    user_info = USERS[user_id]
    return web.json_response(
        {
            "username": user_id,
            "roles": sorted(user_info["roles"]),
        }
    )


async def users_list(request: web.Request) -> web.Response:
    user_id = await authorized_userid(request)
    if not user_id:
        return web.json_response({"error": "Unauthorized"}, status=401)

    return web.json_response(
        {
            "users": [
                {"username": username, "roles": sorted(data["roles"])}
                for username, data in USERS.items()
            ]
        }
    )


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

    frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")

    async def index(_: web.Request) -> web.FileResponse:
        return web.FileResponse(os.path.join(frontend_dir, "index.html"))

    app.router.add_get("/", index)
    app.router.add_static("/static/", frontend_dir, show_index=False)

    return app


if __name__ == "__main__":
    web.run_app(create_app(), host="0.0.0.0", port=8080)

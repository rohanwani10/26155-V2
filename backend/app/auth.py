"""Setup, login, and session routes. The FastAPI router is built per-data-dir
so each app instance (and each test) gets an isolated vault."""

import secrets
import time
from pathlib import Path
from typing import Callable, Optional

from fastapi import APIRouter, Cookie, Depends, HTTPException, Response
from pydantic import BaseModel

from .vault import InvalidCredential, Vault, VaultAlreadySetUp, VaultCorrupted, VaultNotSetUp

SESSION_COOKIE = "session_token"
SESSION_TTL_SECONDS = 8 * 60 * 60
MIN_PASSWORD_LENGTH = 8
MAX_LOGIN_FAILURES = 5
LOCKOUT_SECONDS = 30.0


class SessionStore:
    """In-memory only: sessions (and the data keys they hold) never touch disk,
    and don't survive a process restart -- that's the point, this is a
    single-local-admin app, not a durable session system."""

    def __init__(self) -> None:
        self._sessions: dict[str, tuple[bytes, float]] = {}

    def create(self, data_key: bytes) -> str:
        token = secrets.token_urlsafe(32)
        self._sessions[token] = (data_key, time.time() + SESSION_TTL_SECONDS)
        return token

    def get(self, token: Optional[str]) -> Optional[bytes]:
        if not token:
            return None
        # A single dict.get() avoids the separate "in" check + index race:
        # there's no window where another request's destroy() can invalidate
        # the token between a membership check and the lookup.
        entry = self._sessions.get(token)
        if entry is None:
            return None
        data_key, expires_at = entry
        if time.time() > expires_at:
            self._sessions.pop(token, None)
            return None
        return data_key

    def destroy(self, token: Optional[str]) -> None:
        if token:
            self._sessions.pop(token, None)


class LoginLockedOut(Exception):
    pass


class LoginThrottle:
    """Single global gate, not per-IP: there is exactly one admin account for
    this app, so there's nothing to distinguish -- this exists purely to slow
    down repeated guesses against that one account."""

    def __init__(
        self,
        max_failures: int = MAX_LOGIN_FAILURES,
        lockout_seconds: float = LOCKOUT_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._max_failures = max_failures
        self._lockout_seconds = lockout_seconds
        self._clock = clock
        self._failures = 0
        self._locked_until = 0.0

    def check(self) -> None:
        if self._clock() < self._locked_until:
            raise LoginLockedOut()

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self._max_failures:
            self._locked_until = self._clock() + self._lockout_seconds
            self._failures = 0

    def record_success(self) -> None:
        self._failures = 0
        self._locked_until = 0.0


class SetupRequest(BaseModel):
    password: str


class SetupResponse(BaseModel):
    recovery_key: str


class LoginRequest(BaseModel):
    credential: str


def build_auth_router(
    data_dir: Path, clock: Callable[[], float] = time.time
) -> APIRouter:
    router = APIRouter()
    vault = Vault(data_dir / "vault.json")
    sessions = SessionStore()
    throttle = LoginThrottle(clock=clock)

    def require_session(
        session_token: Optional[str] = Cookie(default=None),
    ) -> bytes:
        data_key = sessions.get(session_token)
        if data_key is None:
            raise HTTPException(status_code=401, detail="Not authenticated")
        return data_key

    @router.get("/api/setup/status")
    def setup_status() -> dict[str, bool]:
        return {"setup_complete": vault.is_set_up()}

    @router.post("/api/setup", response_model=SetupResponse)
    def setup(body: SetupRequest) -> SetupResponse:
        if len(body.password.strip()) < MIN_PASSWORD_LENGTH:
            raise HTTPException(
                status_code=400,
                detail=f"Password must be at least {MIN_PASSWORD_LENGTH} characters",
            )
        try:
            recovery_key = vault.setup(body.password)
        except VaultAlreadySetUp:
            raise HTTPException(status_code=409, detail="Already set up")
        return SetupResponse(recovery_key=recovery_key)

    @router.post("/api/login")
    def login(body: LoginRequest, response: Response) -> dict[str, bool]:
        try:
            throttle.check()
        except LoginLockedOut:
            raise HTTPException(
                status_code=429, detail="Too many failed attempts, try again shortly"
            )

        try:
            data_key = vault.unlock(body.credential)
        except VaultNotSetUp:
            raise HTTPException(status_code=409, detail="Not set up yet")
        except VaultCorrupted:
            raise HTTPException(status_code=500, detail="Vault data is corrupted")
        except InvalidCredential:
            throttle.record_failure()
            raise HTTPException(status_code=401, detail="Invalid credential")

        throttle.record_success()
        token = sessions.create(data_key)
        # No `secure=True`: this app is architecturally localhost-only, plain
        # HTTP, with no TLS in scope (see spec). A Secure cookie would only be
        # honored over HTTPS, which would silently break every login here.
        # Revisit if a future ticket adds TLS/non-loopback binding.
        response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax")
        return {"ok": True}

    @router.post("/api/logout")
    def logout(
        response: Response, session_token: Optional[str] = Cookie(default=None)
    ) -> dict[str, bool]:
        sessions.destroy(session_token)
        response.delete_cookie(SESSION_COOKIE)
        return {"ok": True}

    @router.get("/api/me")
    def me(data_key: bytes = Depends(require_session)) -> dict[str, bool]:
        return {"authenticated": True}

    return router

import time
from pathlib import Path
from typing import Callable

from fastapi import FastAPI

from .auth import SessionStore, build_auth_router, make_require_session
from .devices import build_devices_router


def create_app(data_dir: Path, clock: Callable[[], float] = time.time) -> FastAPI:
    data_dir.mkdir(parents=True, exist_ok=True)
    app = FastAPI(title="Network Compliance Engine")

    sessions = SessionStore()
    require_session = make_require_session(sessions)

    app.include_router(build_auth_router(data_dir, sessions, clock=clock))
    app.include_router(build_devices_router(data_dir, require_session))
    return app

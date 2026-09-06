import time
from pathlib import Path
from typing import Callable

from fastapi import FastAPI

from .auth import build_auth_router


def create_app(data_dir: Path, clock: Callable[[], float] = time.time) -> FastAPI:
    data_dir.mkdir(parents=True, exist_ok=True)
    app = FastAPI(title="Network Compliance Engine")
    app.include_router(build_auth_router(data_dir, clock=clock))
    return app

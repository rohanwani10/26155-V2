import time
from pathlib import Path
from typing import Callable, Optional

from fastapi import FastAPI

from .auth import SessionStore, build_auth_router, make_require_session
from .chat import build_chat_router
from .devices import build_devices_router
from .llm import LlmClient, OllamaLlmClient


def create_app(
    data_dir: Path,
    clock: Callable[[], float] = time.time,
    llm_client: Optional[LlmClient] = None,
) -> FastAPI:
    data_dir.mkdir(parents=True, exist_ok=True)
    app = FastAPI(title="Network Compliance Engine")

    sessions = SessionStore()
    require_session = make_require_session(sessions)

    app.include_router(build_auth_router(data_dir, sessions, clock=clock))
    app.include_router(build_devices_router(data_dir, require_session))
    app.include_router(
        build_chat_router(data_dir, require_session, llm_client or OllamaLlmClient())
    )
    return app

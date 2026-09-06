import time
from pathlib import Path
from typing import Callable, Optional

from fastapi import FastAPI

from .auth import SessionStore, build_auth_router, make_require_session
from .chat import build_chat_router
from .devices import build_devices_router
from .llm import LlmClient, OllamaLlmClient
from .training import TrainingQueueStore, TrainingRuleStore, build_training_router
from .training_suggestions import build_training_suggestions_router


def create_app(
    data_dir: Path,
    clock: Callable[[], float] = time.time,
    llm_client: Optional[LlmClient] = None,
) -> FastAPI:
    data_dir.mkdir(parents=True, exist_ok=True)
    app = FastAPI(title="Network Compliance Engine")

    sessions = SessionStore()
    require_session = make_require_session(sessions)

    queue_store = TrainingQueueStore(data_dir / "training_queue.db")
    rule_store = TrainingRuleStore(data_dir / "training_rules.db")
    resolved_llm_client = llm_client or OllamaLlmClient()

    app.include_router(build_auth_router(data_dir, sessions, clock=clock))
    app.include_router(
        build_devices_router(data_dir, require_session, queue_store, rule_store)
    )
    app.include_router(build_training_router(require_session, queue_store, rule_store))
    app.include_router(
        build_training_suggestions_router(require_session, rule_store, resolved_llm_client)
    )
    app.include_router(build_chat_router(data_dir, require_session, resolved_llm_client))
    return app

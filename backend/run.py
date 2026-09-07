"""Local dev entrypoint. Run with: uv run python run.py

Data (encrypted device records, vault, training queue/rules, chat history,
vector store) persists under backend/data/ across restarts.
"""

from pathlib import Path
import uvicorn
from app.main import create_app

app = create_app(Path(__file__).parent / "data")

if __name__ == "__main__":
    uvicorn.run("run:app", host="127.0.0.1", port=8000, reload=True)

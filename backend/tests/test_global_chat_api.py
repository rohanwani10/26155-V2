from fastapi.testclient import TestClient
from app.main import create_app


def test_global_chat_unauthenticated(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app)

    response = client.get("/api/global-chat")
    assert response.status_code == 401

    post_resp = client.post("/api/global-chat", json={"question": "Summarize compliance"})
    assert post_resp.status_code == 401


def test_global_chat_flow(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app)

    # 1. Setup and Login
    client.post("/api/setup", json={"password": "masterpassword123"})
    client.post("/api/login", json={"credential": "masterpassword123"})

    # 2. Get empty history
    history_resp = client.get("/api/global-chat")
    assert history_resp.status_code == 200
    assert history_resp.json()["history"] == []

    # 3. Post a global chat question
    post_resp = client.post(
        "/api/global-chat",
        json={"question": "What is the security compliance status of my fleet?"},
    )
    assert post_resp.status_code == 200
    data = post_resp.json()
    assert "question" in data
    assert "answer" in data
    assert "citations" in data

    # 4. Verify history is saved
    history_after = client.get("/api/global-chat")
    assert history_after.status_code == 200
    assert len(history_after.json()["history"]) == 1

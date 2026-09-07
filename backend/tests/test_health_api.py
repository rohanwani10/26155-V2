from fastapi.testclient import TestClient

from app.main import create_app


def test_health_check_is_unauthenticated_and_ok(tmp_path):
    client = TestClient(create_app(tmp_path))

    resp = client.get("/health")

    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}

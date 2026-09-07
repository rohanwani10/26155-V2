from fastapi.testclient import TestClient
from app.main import create_app


def test_get_network_health_status(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app)

    response = client.get("/api/network-health/status")
    assert response.status_code == 200
    data = response.json()
    assert "links" in data
    assert "alerts" in data
    assert "recommendations" in data
    assert "mode" in data


def test_switch_mode_and_simulate(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app)

    # Switch to demo mode
    response = client.post("/api/network-health/mode", json={"mode": "demo"})
    assert response.status_code == 200
    data = response.json()
    assert data["mode"] == "demo"
    assert len(data["links"]) == 3

    # Trigger spike in demo mode
    response_spike = client.post("/api/network-health/simulate", json={"link_id": "wan-1"})
    assert response_spike.status_code == 200
    spike_data = response_spike.json()
    assert spike_data["simulated_spike"] == "wan-1"
    assert len(spike_data["recommendations"]) > 0

    # Switch back to real mode
    response_real = client.post("/api/network-health/mode", json={"mode": "real"})
    assert response_real.status_code == 200
    assert response_real.json()["mode"] == "real"

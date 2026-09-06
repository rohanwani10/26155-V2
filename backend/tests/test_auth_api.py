import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def client(tmp_path):
    app = create_app(tmp_path)
    return TestClient(app)


class FakeClock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def client_with_clock(tmp_path, clock):
    app = create_app(tmp_path, clock=clock)
    return TestClient(app)


def test_setup_status_is_false_before_setup(client):
    resp = client.get("/api/setup/status")
    assert resp.status_code == 200
    assert resp.json() == {"setup_complete": False}


def test_protected_route_rejects_unauthenticated_requests(client):
    resp = client.get("/api/me")
    assert resp.status_code == 401


def test_login_before_setup_is_rejected(client):
    resp = client.post("/api/login", json={"credential": "whatever"})
    assert resp.status_code == 409


def test_full_setup_then_login_then_logout_flow(client):
    setup_resp = client.post("/api/setup", json={"password": "correct horse battery staple"})
    assert setup_resp.status_code == 200
    recovery_key = setup_resp.json()["recovery_key"]
    assert recovery_key

    status_resp = client.get("/api/setup/status")
    assert status_resp.json() == {"setup_complete": True}

    me_resp = client.get("/api/me")
    assert me_resp.status_code == 401

    wrong_login = client.post("/api/login", json={"credential": "wrong password"})
    assert wrong_login.status_code == 401

    login_resp = client.post("/api/login", json={"credential": "correct horse battery staple"})
    assert login_resp.status_code == 200

    me_resp = client.get("/api/me")
    assert me_resp.status_code == 200
    assert me_resp.json() == {"authenticated": True}

    logout_resp = client.post("/api/logout")
    assert logout_resp.status_code == 200

    me_after_logout = client.get("/api/me")
    assert me_after_logout.status_code == 401


def test_recovery_key_can_log_in(client):
    setup_resp = client.post("/api/setup", json={"password": "correct horse battery staple"})
    recovery_key = setup_resp.json()["recovery_key"]

    login_resp = client.post("/api/login", json={"credential": recovery_key})
    assert login_resp.status_code == 200

    me_resp = client.get("/api/me")
    assert me_resp.status_code == 200


def test_cannot_set_up_twice_via_api(client):
    client.post("/api/setup", json={"password": "first password value"})
    second = client.post("/api/setup", json={"password": "second password value"})
    assert second.status_code == 409


def test_empty_password_is_rejected(client):
    resp = client.post("/api/setup", json={"password": ""})
    assert resp.status_code == 400


def test_whitespace_only_password_is_rejected(client):
    resp = client.post("/api/setup", json={"password": "        "})
    assert resp.status_code == 400


def test_short_password_is_rejected(client):
    resp = client.post("/api/setup", json={"password": "short1"})
    assert resp.status_code == 400


def test_session_cookie_is_httponly_and_not_secure(client):
    # Not Secure: this app is localhost-only, plain HTTP, no TLS in scope.
    # A Secure cookie would never be transmitted at all in that setup.
    client.post("/api/setup", json={"password": "correct horse battery staple"})
    login_resp = client.post(
        "/api/login", json={"credential": "correct horse battery staple"}
    )
    set_cookie_header = login_resp.headers.get("set-cookie", "")
    assert "HttpOnly" in set_cookie_header
    assert "Secure" not in set_cookie_header


def test_repeated_failed_logins_lock_out_further_attempts(client_with_clock, clock):
    client_with_clock.post(
        "/api/setup", json={"password": "correct horse battery staple"}
    )

    for _ in range(5):
        resp = client_with_clock.post(
            "/api/login", json={"credential": "wrong password"}
        )
        assert resp.status_code == 401

    # Even the correct credential is rejected while locked out.
    locked_resp = client_with_clock.post(
        "/api/login", json={"credential": "correct horse battery staple"}
    )
    assert locked_resp.status_code == 429

    # After the lockout window passes, login works again.
    clock.advance(31)
    resp = client_with_clock.post(
        "/api/login", json={"credential": "correct horse battery staple"}
    )
    assert resp.status_code == 200


def test_successful_login_resets_the_failure_counter(client_with_clock):
    client_with_clock.post(
        "/api/setup", json={"password": "correct horse battery staple"}
    )

    for _ in range(4):
        client_with_clock.post("/api/login", json={"credential": "wrong password"})

    ok_resp = client_with_clock.post(
        "/api/login", json={"credential": "correct horse battery staple"}
    )
    assert ok_resp.status_code == 200

    # One more failure shouldn't lock out (counter was reset by the success).
    resp = client_with_clock.post("/api/login", json={"credential": "wrong password"})
    assert resp.status_code == 401

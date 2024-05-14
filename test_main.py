import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

@pytest.fixture
def usr():
    return {"uname": "testuser", "pwd": "testpassword", "sal": 1000.0, "raise_date": "2024-05-20"}

def test_reg_and_tok(usr):
    resp = client.post("/token", auth=(usr["uname"], usr["pwd"]))
    assert resp.status_code == 200
    assert "token" in resp.json()

def test_bad_tok():
    resp = client.get("/salary", headers={"Authorization": "Bearer badtoken"})
    assert resp.status_code == 401

def test_good_tok(usr):
    resp = client.post("/register", json=usr)
    resp = client.post("/token", auth=(usr["uname"], usr["pwd"]))
    assert resp.status_code == 200
    tok = resp.json()["token"]
    resp = client.get("/salary", headers={"Authorization": f"Bearer {tok}"})
    assert resp.status_code == 200
    assert "sal" in resp.json()
    assert "raise_date" in resp.json()

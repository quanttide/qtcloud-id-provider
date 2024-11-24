import pytest
from fastapi.testclient import TestClient
from src.qtcloud_id_provider.main import app

client = TestClient(app)

def test_register():
    response = client.post("/register/", json={"username": "testuser", "password": "testpassword"})
    assert response.status_code == 200
    assert response.json() == {"username": "testuser"}

def test_login():
    response = client.post("/token", data={"username": "testuser", "password": "testpassword"})
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_read_users_me():
    # 首先登录以获取 token
    login_response = client.post("/token", data={"username": "testuser", "password": "testpassword"})
    token = login_response.json()["access_token"]

    # 使用 token 访问受保护的路由
    response = client.get("/users/me/", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["username"] == "testuser"

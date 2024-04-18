from fastapi.testclient import TestClient
from app import app
import pytest


@pytest.fixture
def test_app():
    return TestClient(app)


@pytest.mark.integration
def test_healthcheck(test_app):
    """Test the healthcheck endpoint."""
    response = test_app.get("/healthcheck")
    assert response.status_code == 200
    data = response.json()
    assert "health" in data
    assert "version" in data


@pytest.mark.parametrize("input_data, expected_status_code", [
    ({"username": "admin_pytest", "password": "admin", "is_admin": True}, 201),  # Valid input
    ({"username": "admin_pytest", "password": "admin", "is_admin": True}, 409),  # Duplicate user
])
def test_create_admin_user_endpoint(test_app, input_data, expected_status_code):
    """Test the /create_admin_user endpoint with various input data."""
    response = test_app.post("/user/create_admin_user", json=input_data)
    assert response.status_code == expected_status_code


@pytest.mark.parametrize("input_data, expected_status_code", [
    ({"username": "admin_pytest", "password": "admin"}, 200),  # Valid credentials
    ({"username": "admin_pytest", "password": "invalid_password"}, 401),  # Invalid username or password
])
def test_login_endpoint(test_app, input_data, expected_status_code):
    """Test the /login endpoint with various input data."""
    response = test_app.post("/auth/login", json=input_data)
    assert response.status_code == expected_status_code




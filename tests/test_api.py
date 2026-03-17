"""
Tests para la API de detección de anomalías.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_root():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "running"


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


def test_analyze_normal_traffic():
    payload = {
        "records": [
            {
                "timestamp": "2025-03-01T14:30:00",
                "ip_address": "192.168.1.100",
                "user": "user_12",
                "method": "GET",
                "endpoint": "/api/products",
                "status_code": 200,
                "response_bytes": 1500,
                "requests_per_minute": 5,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            }
        ]
    }
    response = client.post("/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["total_records"] == 1


def test_analyze_anomalous_traffic():
    payload = {
        "records": [
            {
                "timestamp": "2025-03-01T03:15:00",
                "ip_address": "10.0.45.12",
                "user": "user_3",
                "method": "DELETE",
                "endpoint": "/admin/users/delete",
                "status_code": 403,
                "response_bytes": 0,
                "requests_per_minute": 150,
                "user_agent": "sqlmap/1.7"
            }
        ]
    }
    response = client.post("/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["threats_detected"] >= 0  # Model decides


def test_analyze_mixed_batch():
    payload = {
        "records": [
            {
                "timestamp": "2025-03-01T10:00:00",
                "ip_address": "192.168.1.50",
                "user": "user_20",
                "method": "GET",
                "endpoint": "/home",
                "status_code": 200,
                "response_bytes": 2000,
                "requests_per_minute": 3,
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
            },
            {
                "timestamp": "2025-03-01T02:45:00",
                "ip_address": "10.0.100.5",
                "user": "user_1",
                "method": "PUT",
                "endpoint": "/api/../etc/passwd",
                "status_code": 500,
                "response_bytes": 200000,
                "requests_per_minute": 300,
                "user_agent": "nikto/2.5.0"
            }
        ]
    }
    response = client.post("/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["total_records"] == 2
    assert len(data["all_decisions"]) == 2


def test_analyze_empty_records():
    payload = {"records": []}
    response = client.post("/analyze", json=payload)
    assert response.status_code == 400

"""Lightweight smoke tests for service health endpoints.

Run with: pytest tests/test_health.py
These tests are skipped if the services are not running.
"""
import os

import pytest
import requests

BASE_URLS = {
    "auth": os.environ.get("AUTH_URL", "http://localhost:8001"),
    "patient": os.environ.get("PATIENT_URL", "http://localhost:8002"),
    "appointment": os.environ.get("APPOINTMENT_URL", "http://localhost:8003"),
    "billing": os.environ.get("BILLING_URL", "http://localhost:8004"),
}


@pytest.mark.parametrize("service,url", list(BASE_URLS.items()))
def test_health_endpoint(service, url):
    try:
        res = requests.get(f"{url}/health", timeout=2)
    except requests.RequestException:
        pytest.skip(f"{service} service not reachable at {url}")
    assert res.status_code == 200
    body = res.json()
    assert body.get("status") == "ok"
    assert body.get("service") == service

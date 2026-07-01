"""Tests for the backend health endpoint."""

from httpx import AsyncClient, ASGITransport
from app.main import app


class TestHealthEndpoint:
    """Backend /health endpoint behaviour."""

    async def test_health_returns_healthy(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "timestamp" in data

import pytest


@pytest.mark.asyncio
async def test_health_endpoint_returns_200(client):
    """Health endpoint should return 200 with status ok."""
    response = await client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

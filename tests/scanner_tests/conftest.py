"""Test fixtures for scanner tests using httpx transport mocking."""

import httpx
import pytest


def _mock_response(status_code: int = 200, headers: dict | None = None,
                   body: str = "", set_cookie: list[str] | None = None,
                   location: str | None = None) -> httpx.Response:
    hdrs = dict(headers or {})
    if set_cookie:
        hdrs["set-cookie"] = set_cookie
    if location:
        hdrs["location"] = location
    return httpx.Response(status_code=status_code, headers=hdrs, text=body)


@pytest.fixture
def mock_handler():
    """Returns a factory that creates an httpx MockTransport handler.

    Usage:
        def handler(request):
            if "https" in request.url.scheme:
                return _response(200, {...})
            return _response(301, location="https://...")
        client = mock_handler(handler)
    """
    def _make(handler):
        return httpx.Client(transport=httpx.MockTransport(handler))
    return _make

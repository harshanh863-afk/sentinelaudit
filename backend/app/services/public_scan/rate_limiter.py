"""IP-based rate limiting for public scan endpoints.

Uses Redis when available, falls back to in-memory storage.
"""

import time
from collections import defaultdict


class RateLimiter:
    def __init__(self, max_requests: int = 5, window_seconds: int = 3600):
        self.max_requests = max_requests
        self.window_seconds = window_seconds

    def is_allowed(self, key: str) -> bool:
        raise NotImplementedError

    def remaining(self, key: str) -> int:
        raise NotImplementedError


class InMemoryRateLimiter(RateLimiter):
    """In-memory sliding window rate limiter."""

    def __init__(self, max_requests: int = 5, window_seconds: int = 3600):
        super().__init__(max_requests, window_seconds)
        self._buckets: dict[str, list[float]] = defaultdict(list)

    def _prune(self, key: str, now: float) -> None:
        cutoff = now - self.window_seconds
        self._buckets[key] = [t for t in self._buckets[key] if t > cutoff]

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        self._prune(key, now)
        bucket = self._buckets[key]
        if len(bucket) >= self.max_requests:
            return False
        bucket.append(now)
        return True

    def remaining(self, key: str) -> int:
        now = time.time()
        self._prune(key, now)
        return max(0, self.max_requests - len(self._buckets[key]))

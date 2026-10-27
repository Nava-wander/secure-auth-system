import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    """In-process sliding-window limiter. For several workers/servers use a shared store (e.g. Redis)."""

    def __init__(self, limit: int, window: int = 60):
        self.limit, self.window = limit, window
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= now - self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            if len(self._hits) > 10_000:  # opportunistic cleanup
                for k in [k for k, v in self._hits.items() if not v]:
                    del self._hits[k]
            return True

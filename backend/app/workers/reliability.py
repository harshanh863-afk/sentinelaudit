"""Reliability utilities for Celery tasks — retry policies, timeouts, graceful shutdown."""

import os
import threading
import time
from functools import wraps
from typing import Any, Callable


def retry_with_backoff(
    max_retries: int = 3,
    base_delay: float = 30.0,
    max_delay: float = 300.0,
    backoff_factor: float = 2.0,
) -> Callable:
    """Decorator: exponential backoff retry for scanner tasks.

    Args:
        max_retries: Maximum retry attempts
        base_delay: Initial delay in seconds
        max_delay: Maximum delay cap in seconds
        backoff_factor: Multiplier for each retry
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exception = None
            delay = base_delay

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries:
                        actual_delay = min(delay, max_delay)
                        time.sleep(actual_delay)
                        delay *= backoff_factor
                    else:
                        raise last_exception
            return None  # unreachable
        return wrapper
    return decorator


def task_timeout(seconds: int = 120) -> Callable:
    """Decorator: enforces maximum execution time for a task.

    Uses SIGALRM on Unix, threading.Timer on Windows as a fallback.
    Celery's own `soft_time_limit` / `time_limit` should be the primary
    mechanism. This is a Python-level safety net.
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if os.name == "nt":
                return _timeout_windows(func, seconds, args, kwargs)
            return _timeout_unix(func, seconds, args, kwargs)
        return wrapper
    return decorator


def _timeout_unix(func: Callable, seconds: int, args: tuple, kwargs: dict) -> Any:
    import signal

    def _timeout_handler(_signum: int, _frame: Any) -> None:
        raise TimeoutError(f"Task exceeded {seconds}s timeout")

    original_handler = signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(seconds)
    try:
        return func(*args, **kwargs)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, original_handler)


def _timeout_windows(func: Callable, seconds: int, args: tuple, kwargs: dict) -> Any:
    """Windows-compatible timeout using threading.Timer."""
    result: list[Any] = []
    exception: list[Exception] = []
    completed = threading.Event()

    def runner():
        try:
            result.append(func(*args, **kwargs))
        except Exception as e:
            exception.append(e)
        finally:
            completed.set()

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    if not completed.wait(timeout=seconds):
        raise TimeoutError(f"Task exceeded {seconds}s timeout")
    if exception:
        raise exception[0]
    return result[0]

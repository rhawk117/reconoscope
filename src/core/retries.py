from dataclasses import dataclass
from typing import Callable, Awaitable, Any, Literal
import asyncio
import random
import httpx


class NoAttemptsLeftError(Exception): ...


@dataclass(slots=True)
class AsyncRetries:
    attempts: int = 3
    delay: float = 0.25
    jitter: float = 0.0
    backoff: Literal['linear', 'expo'] = "linear"  # "linear" | "expo"

    retry_on: tuple[type[BaseException], ...] = (
        httpx.ConnectError,
        httpx.ReadTimeout,
        httpx.WriteError,
        httpx.RemoteProtocolError,
        httpx.PoolTimeout,
        httpx.ProxyError,
        httpx.NetworkError,
    )

    def _calc_delay(self, attempt_no: int) -> float:
        base = (
            self.delay * attempt_no
            if self.backoff == "linear"
            else self.delay * (2 ** (attempt_no - 1))
        )
        if self.jitter:
            j = base * self.jitter
            base += random.uniform(-j, j)
        return max(0.0, base)

    async def call(self, func: Callable[..., Awaitable[Any]], *args, **kwargs) -> Any:
        last_exc: BaseException | None = None
        for attempt_no in range(1, self.attempts + 1):
            try:
                return await func(*args, **kwargs)
            except self.retry_on as exc:
                last_exc = exc
                if attempt_no == self.attempts:
                    raise NoAttemptsLeftError(
                        f"Failed after {self.attempts} attempts"
                    ) from exc
                await asyncio.sleep(self._calc_delay(attempt_no))
            except Exception:
                raise
        raise NoAttemptsLeftError(
            f"Failed after {self.attempts} attempts"
        ) from last_exc


def async_retries(
    *,
    attempts: int = 3,
    delay: float = 0.25,
    jitter: float = 0.0,
    backoff: Literal['linear', 'expo'] = "linear",
    retry_on: tuple[type[BaseException], ...] | None = None,
) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    if retry_on is None:
        retry_on = (
            httpx.ConnectError,
            httpx.ReadTimeout,
            httpx.WriteError,
            httpx.RemoteProtocolError,
            httpx.PoolTimeout,
            httpx.ProxyError,
            httpx.NetworkError,
        )

    retries = AsyncRetries(
        attempts=attempts,
        delay=delay,
        jitter=jitter,
        backoff=backoff,
        retry_on=retry_on,
    )

    def decorator(
        func: Callable[..., Awaitable[Any]]
    ) -> Callable[..., Awaitable[Any]]:
        async def wrapper(*args, **kwargs) -> Any:
            return await retries.call(func, *args, **kwargs)
        wrapper.__annotations__ = func.__annotations__
        return wrapper


    return decorator
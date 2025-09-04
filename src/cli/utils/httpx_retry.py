import abc
from collections.abc import Awaitable, Callable
from typing import Any
import httpx
import asyncio
import random
import functools
from typing import Literal
from dataclasses import dataclass


class NoAttemptsLeftError(Exception): ...


@dataclass(slots=True)
class AsyncRetries:
    '''
    An async iterator that yields the current attempt number,
    and adheres to the specified delay, jitter, and backoff strategy.
    Caller must handle exceptions and decide whether to continue
    or break the loop.
    '''
    attempts: int
    delay: float = 0.25
    jitter: float = 0.0
    backoff: Literal["linear", "expo"] = "linear"


    def calculate_delay(self, attempt_no: int) -> float:
        if self.backoff == "linear":
            delay = self.delay * attempt_no
        else:
            delay = self.delay * (2 ** (attempt_no - 1))

        if self.jitter:
            jitter_delta = delay * self.jitter
            delay += random.uniform(-jitter_delta, jitter_delta)

        return delay

    async def __aiter__(self):
        attempts = self.attempts
        for attempt_no in range(1, attempts + 1):
            yield attempt_no
            if attempt_no < attempts:
                await asyncio.sleep(self.calculate_delay(attempt_no))


class HttpxStatusError(Exception):
    '''
    Custom exception to encapsulate httpx.HTTPStatusError details,
    can be handled seperately on caller side.
    '''
    def __init__(
        self,
        message: str,
        status_code: int,
        response: httpx.Response,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response = response


class _RetryDecorator(abc.ABC):
    '''
    Provides a decorator to wrap async functions with retry logic.
    '''
    def __init__(
        self,
        *,
        attempts: int = 3,
        delay: float = 0.25,
        jitter: float = 0.0,
        backoff: Literal["linear", "expo"] = "linear",
    ) -> None:
        self._attempt_iterator = AsyncRetries(
            attempts=attempts,
            delay=delay,
            jitter=jitter,
            backoff=backoff,
        )

    @abc.abstractmethod
    async def _wrap_func(self, func: Callable[..., Awaitable[Any]], *args, **kwargs) -> Any:
        ...

    def __call__(self, func: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            return await self._wrap_func(func, *args, **kwargs)

        return wrapper



class retry_async(_RetryDecorator):
    async def _wrap_func(self, func: Callable[..., Awaitable[Any]], *args, **kwargs) -> Any:
        async for _ in self._attempt_iterator:
            try:
                return await func(*args, **kwargs)
            except Exception:
                continue
        raise NoAttemptsLeftError("All retry attempts exhausted")


class httpx_retry(_RetryDecorator):
    async def _wrap_func(self, func: Callable[..., Awaitable[httpx.Response]], *args, **kwargs) -> httpx.Response:
        async for _ in self._attempt_iterator:
            try:
                return await func(*args, **kwargs)
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code >= 500:
                    continue
                raise HttpxStatusError(
                    message=f"HTTP error {exc.response.status_code}",
                    status_code=exc.response.status_code,
                    response=exc.response,
                ) from exc
            except (
                httpx.ConnectError,
                httpx.ReadTimeout,
                httpx.WriteError,
                httpx.RemoteProtocolError
            ):
                pass
        raise NoAttemptsLeftError("All retry attempts exhausted")



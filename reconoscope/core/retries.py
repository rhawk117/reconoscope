from __future__ import annotations

import asyncio
import functools
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal, ParamSpec, TypeVar

from loguru import logger


class NoAttemptsLeftError(Exception): ...



P = ParamSpec("P")
R = TypeVar("R")


@dataclass(slots=True)
class AsyncRetries:
    '''
    A decorator that retries a function call on specified exceptions
    that are passed to the constructor.

    When all attempts are exhausted, a NoAttemptsLeftError is raised.

    Parameters
    ----------
    retry_on : tuple[type[BaseException], ...]
        _The exceptions to retry on_
    attempts : int
        _The number of attempts to make_
    delay : float
        _The initial delay between attempts in seconds_
    jitter : float
        _The jitter factor to apply to the delay_
    backoff : Literal["linear", "expo"]
        _The backoff strategy to use_
    '''
    retry_on: tuple[type[BaseException], ...]
    attempts: int = 3
    delay: float = 0.25
    jitter: float = 0.0
    backoff: Literal["linear", "expo"] = "linear"  # "linear" | "expo"

    def _calculate_delay(self, attempt_no: int) -> float:
        """
        Calculates the delay before the next retry

        Parameters
        ----------
        attempt_no : int

        Returns
        -------
        float
        """
        if self.backoff == "linear":
            base = self.delay * attempt_no
        else:
            base = self.delay * (2 ** (attempt_no - 1))

        if self.jitter:
            j = base * self.jitter
            base += random.uniform(-j, j)
        return max(0.0, base)

    async def call_with_retries(
        self, func: Callable[P, Awaitable[R]], *args, **kwargs
    ) -> R:
        """
        Calls a function with retries

        Parameters
        ----------
        func : Callable[..., Awaitable[Any]]
            _The function to call_

        Returns
        -------
        Any

        Raises
        ------
        NoAttemptsLeftError
        """

        last_exc: BaseException | None = None
        for attempt_no in range(1, self.attempts + 1):
            try:
                return await func(*args, **kwargs)
            except self.retry_on as exc:
                logger.error(f"Attempt {attempt_no} failed: {exc}")
                if attempt_no == self.attempts:
                    raise NoAttemptsLeftError(
                        f"Failed after {self.attempts} attempts"
                    ) from exc
                last_exc = exc
                await asyncio.sleep(self._calculate_delay(attempt_no))
            except Exception:
                raise

        raise NoAttemptsLeftError(
            f"Failed after {self.attempts} attempts"
        ) from last_exc

    def __call__(
        self,
        func: Callable[P, Awaitable[R]],
    ) -> Callable[P, Awaitable[R]]:
        """
        A decorator that applies retries to an async function

        Parameters
        ----------
        func : Callable[P, Awaitable[R]]

        Returns
        -------
        Callable[P, Awaitable[R]]
        """

        @functools.wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            return await self.call_with_retries(func, *args, **kwargs)

        return wrapper



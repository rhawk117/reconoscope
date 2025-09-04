@httpx_retry(
        attempts=3,
        delay=0.25,
        jitter=0.1,
        backoff="expo",
    )import abc
from contextlib import asynccontextmanager
import functools
import random
import anyio
import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal, NamedTuple, Protocol, TypedDict
import anyio.lowlevel
import httpx
from loguru import logger
from tqdm import tqdm





def _defaultretry_on() -> tuple[type[BaseException], ...]:
    return (
        httpx.ConnectError,
        httpx.ReadTimeout,
        httpx.WriteError,
        httpx.RemoteProtocolError,
    )


class OnErrorCallback(Protocol):
    async def __call__(self, exc: BaseException, attempts_left: int) -> None: ...


class MapGiveUpCallback(Protocol):
    def __call__(self, exc: BaseException) -> dict: ...


def httpx_status_to_dict(exc: BaseException) -> dict:
    if not isinstance(exc, httpx.HTTPStatusError):
        return {'error': 'Unknown error', 'details': str(exc)}

    status_code = exc.response.status_code
    try:
        error_detail = exc.response.json()
    except Exception:
        return {'error': f'HTTP {status_code}', 'details': str(exc)}
    return {'error': f'HTTP {status_code}', 'details': error_detail}










def get_default_headers() -> dict:
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
    }



@dataclass
class HTTPClientConfig:
    timeout: int = 10
    max_connections: int = 10
    max_keepalive: int = 5
    keep_alive_expiry: int = 15
    connect_timeout: int = 5
    read_timeout: int = 5

    def makeclient(self) -> httpx.AsyncClient:
        httptimeout = httpx.Timeout(
            self.timeout,
            connect=self.connect_timeout,
            read=self.read_timeout,
        )
        httplimits = httpx.Limits(
            max_connections=self.max_connections,
            max_keepalive_connections=self.max_keepalive,
            keepalive_expiry=self.keep_alive_expiry,
        )

        return httpx.AsyncClient(
            timeout=httptimeout,
            headers=get_default_headers(),
            limits=httplimits,
        )

async def get_json(
    *,
    client: httpx.AsyncClient,
    url: str,
    params: dict | None = None,
) -> dict:
    """
    sends GET request and returns JSON response

    Parameters
    ----------
    client : httpx.AsyncClient
    url : str
    params : dict | None, optional
        _params for the request_, by default None

    Returns
    -------
    dict
    """
    response = await client.get(url, params=params)
    response.raise_for_status()
    return response.json()


async def try_get_json(
    *,
    client: httpx.AsyncClient,
    url: str,
    params: dict | None = None,
    attempts: int = 3,
) -> dict:
    response = None
    while attempts > 0 and response is None:
        try:
            response = await get_json(
                client=client,
                url=url,
                params=params,
            )
        except (
            httpx.ConnectError,
            httpx.ReadTimeout,
            httpx.WriteError,
            httpx.RemoteProtocolError
        ) as exc:
            logger.error(
                f'Error fetching URL {url}: {exc}. Attempts left: {attempts}'
            )
        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code
            try:
                error_detail = exc.response.json()
            except Exception:
                return {'error': f'HTTP {status_code}', 'details': str(exc)}
            return {'error': f'HTTP {status_code}', 'details': error_detail}

        attempts -= 1
        await asyncio.sleep(0.25 * attempts)

    if response is None:
        raise RuntimeError(f'Failed to fetch URL {url} after retries')

    return response


class AccountResultType(StrEnum):
    EXISTS = "exists"
    NOT_FOUND = "not_found"
    ERROR = "error"
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"
    REQUEST_ERROR = "request_error"


class AccountInfo(NamedTuple):
    url: str
    result: AccountResultType


@dataclass(slots=True)
class RequestBlaster:
    concurrency: int = 10

    async def _fetch(self, url: str, client: httpx.AsyncClient) -> AccountResultType:
        response = await client.get(url)
        status_code = response.status_code
        if status_code == 200:
            return AccountResultType.EXISTS
        elif status_code == 404:
            return AccountResultType.NOT_FOUND
        else:
            return AccountResultType.ERROR

    async def _fetchone(self, url: str, client: httpx.AsyncClient) -> AccountResultType:
        try:
            return await self._fetch(url, client)
        except httpx.ConnectError:
            return AccountResultType.CONNECTION_ERROR
        except httpx.TimeoutException:
            return AccountResultType.TIMEOUT
        except httpx.RequestError:
            return AccountResultType.REQUEST_ERROR

    async def __call__(
        self, *, urls: list[str], client_config: HTTPClientConfig
    ) -> list[AccountInfo]:
        semaphore = asyncio.Semaphore(self.concurrency)

        async with client_config.makeclient() as client:

            async def semaworker(url: str) -> AccountInfo:
                async with semaphore:
                    result = await self._fetchone(url, client)
                    return AccountInfo(url=url, result=result)

        tasks = [asyncio.create_task(semaworker(url)) for url in urls]

        results: list[AccountInfo] = []
        with tqdm(
            total=len(tasks),
            desc="Processing",
            unit="req",
            ncols=80,
            leave=False,
        ) as pbar:
            for fut in asyncio.as_completed(tasks):
                result = await fut
                results.append(result)
                pbar.update(1)

        return results
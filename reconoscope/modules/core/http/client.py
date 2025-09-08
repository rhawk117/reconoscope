import dataclasses as dc
from contextlib import asynccontextmanager
from typing import Self

import httpx

from reconoscope.modules.core.http._user_agents import user_agents
from reconoscope.modules.core.http.events import ClientEvents
from reconoscope.modules.core.http.retries import AsyncRetries


def httpxretry(
    *,
    attempts: int = 3,
    delay: float = 0.5,
    jitter: float = 0.1,
) -> AsyncRetries:
    return AsyncRetries(
        attempts=attempts,
        delay=delay,
        jitter=jitter,
        retry_on=(
            httpx.ConnectError,
            httpx.ReadTimeout,
            httpx.WriteError,
            httpx.RemoteProtocolError,
            httpx.PoolTimeout,
            httpx.ProxyError,
            httpx.NetworkError,
            httpx.HTTPStatusError,
        ),
    )

HttpxExceptions = (
    httpx.ConnectError,
    httpx.ReadTimeout,
    httpx.WriteError,
    httpx.RemoteProtocolError,
    httpx.PoolTimeout,
    httpx.ProxyError,
    httpx.NetworkError,
    httpx.HTTPStatusError,
)

@dc.dataclass(slots=True)
class ClientOptions:
    """
    Options for configuring the HTTPX AsyncClient.
    """

    timeout: int = 10
    max_connections: int = 10
    max_keepalive: int = 5
    keep_alive_expiry: int = 15
    connect_timeout: int = 5
    read_timeout: int = 5
    http2: bool = True
    verify: bool = True
    follow_redirects: bool = True
    headers: dict[str, str] = dc.field(default_factory=dict)

    @property
    def httpx_timeout(self) -> httpx.Timeout:
        return httpx.Timeout(
            self.timeout,
            connect=self.connect_timeout,
            read=self.read_timeout,
        )

    @property
    def httpx_limits(self) -> httpx.Limits:
        return httpx.Limits(
            max_connections=self.max_connections,
            max_keepalive_connections=self.max_keepalive,
            keepalive_expiry=self.keep_alive_expiry,
        )




@dc.dataclass
class ReconoscopeHttpClient:
    '''
    A simple HTTP client wrapper for osint modules with
    utility options and defaults that are sensible for
    standard usage.

    '''
    client: httpx.AsyncClient

    async def __aenter__(self) -> Self:
        if self.client.is_closed:
            await self.client.__aenter__()
        return self

    async def __aexit__(self, *args) -> None:
        if not self.client.is_closed:
            await self.client.__aexit__(*args)


    async def aclose(self) -> None:
        await self.client.aclose()


    async def get_json(
        self,
        url: str,
        *,
        raise_for_status: bool = True,
        headers: dict[str, str] | None = None,
        query: dict[str, str] | None = None,
        extensions: dict | None = None,
        cookies: httpx.Cookies | None = None,
    ) -> dict:
        '''
        Performs a GET request and returns the JSON response.

        Parameters
        ----------
        url : str
        raise_for_status : bool, optional
            _Will call raise_for_status() if true_, by default True
        headers : dict[str, str] | None, optional
            by default None
        query : dict[str, str] | None, optional
            by default None
        extensions : dict | None, optional
            by default None
        cookies : httpx.Cookies | None, optional
             by default None

        Returns
        -------
        dict
        '''
        response = await self.client.get(
            url,
            headers=headers,
            params=query,
            extensions=extensions,
            cookies=cookies,
        )
        if raise_for_status:
            response.raise_for_status()
        return response.json()

    async def get_text(
        self,
        url: str,
        *,
        raise_for_status: bool = True,
        headers: dict[str, str] | None = None,
        query: dict[str, str] | None = None,
        extensions: dict | None = None,
        cookies: httpx.Cookies | None = None,
    ) -> str:
        '''
        Performs a GET request and returns the text response.

        Parameters
        ----------
        url : str
        raise_for_status : bool, optional
            by default True
        headers : dict[str, str] | None, optional
            by default None
        query : dict[str, str] | None, optional
            by default None
        extensions : dict | None, optional
            by default None
        cookies : httpx.Cookies | None, optional
            by default None

        Returns
        -------
        str
        '''
        response = await self.client.get(
            url,
            headers=headers,
            params=query,
            extensions=extensions,
            cookies=cookies,
        )
        if raise_for_status:
            response.raise_for_status()
        return response.text


def create_httpx_client(
    *,
    options: ClientOptions | None = None,
    headers: dict[str, str] | None = None,
    events: ClientEvents | None = None,
) -> httpx.AsyncClient:
    headers = headers or {}
    options = options or ClientOptions()

    if 'User-Agent' not in headers:
        headers['User-Agent'] = user_agents.random()

    kwargs = {
        'timeout': options.httpx_timeout,
        'headers': headers,
        'limits': options.httpx_limits,
        'http2': options.http2,
        'follow_redirects': options.follow_redirects,
        'verify': options.verify,
    }
    if events:
        kwargs.update(events.httpx_args())

    return httpx.AsyncClient(
        **kwargs,
    )


def create_reconoscope_client(
    *,
    options: ClientOptions | None = None,
    headers: dict[str, str] | None = None,
) -> ReconoscopeHttpClient:
    httpx_client = create_httpx_client(
        options=options,
        headers=headers,
    )
    return ReconoscopeHttpClient(client=httpx_client)

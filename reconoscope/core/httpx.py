



import dataclasses as dc
from typing import TypedDict

import httpx

from reconoscope.core._user_agents import OS, Browser, UserAgentSpec, Versions
from reconoscope.core.retries import AsyncRetries


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

class UserAgentConfig(TypedDict):
    browser: Browser | None
    os: OS | None
    os_version: Versions | None
    device: str | None

@dc.dataclass(slots=True)
class HttpxOptions:
    '''
    Options for configuring the HTTPX AsyncClient.
    '''
    timeout: int = 10
    max_connections: int = 10
    max_keepalive: int = 5
    keep_alive_expiry: int = 15
    connect_timeout: int = 5
    read_timeout: int = 5
    http2: bool = True
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

user_agent_spec = UserAgentSpec()

def make_httpx_client(
    options: HttpxOptions | None = None,
    headers: dict[str, str] | None = None,
) -> httpx.AsyncClient:
    headers = headers or {}
    options = options or HttpxOptions()
    return httpx.AsyncClient(
        timeout=options.httpx_timeout,
        headers=headers,
        limits=options.httpx_limits,
        http2=options.http2,
        follow_redirects=options.follow_redirects,
    )



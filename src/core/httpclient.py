



import dataclasses
import httpx



def _defaultheaders() -> dict:
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
    }

@dataclasses.dataclass(slots=True)
class HttpConnectionOptions:
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
    headers: dict[str, str] = dataclasses.field(
        default_factory=_defaultheaders
    )

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

def makeclient(options: HttpConnectionOptions) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=options.httpx_timeout,
        headers=options.headers,
        limits=options.httpx_limits,
        http2=options.http2,
        follow_redirects=options.follow_redirects,
    )



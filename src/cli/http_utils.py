
import asyncio
import httpx
from loguru import logger


def get_default_headers() -> dict:
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
    }

def makeclient(timeout: int) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        headers=get_default_headers(),
    )

async def get_json(
    *,
    client: httpx.AsyncClient,
    url: str,
    params: dict | None = None,
) -> dict:
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

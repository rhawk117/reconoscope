import asyncio
import concurrent
import concurrent.futures
import dataclasses as dc
import logging
import sys

import httpx
from loguru import logger
from rich.console import Console

from reconoscope.core.httpx import (
    HttpxOptions,
    httpxretry,
    make_httpx_client,
    user_agent_spec,
)
from reconoscope.modules.whatsmyname.collection import (
    WMNCollection,
    WMNLoaders,
    WMNRuleSet,
)
from reconoscope.modules.whatsmyname.dtos import WhatsMyNameSite
from reconoscope.modules.whatsmyname.utils import HTTPStreamUtils, WmnSiteUtils

log = logging.getLogger(__name__)

@dc.dataclass(slots=True)
class WMNHit:
    """
    A hit from a WhatsMyName site check.
    """

    site: str
    url: str
    status: int


@httpxretry(attempts=3)
async def fetch_one(
    site: WhatsMyNameSite,
    client: httpx.AsyncClient,
    username: str,
    base_headers: dict[str, str],
) -> WMNHit | None:
    """
    Fetch a single WhatsMyName site to check for a username,
    has retry logic built in.

    Parameters
    ----------
    site : WhatsMyNameSite
    client : httpx.AsyncClient
    username : str
    base_headers : dict[str, str]

    Returns
    -------
    WMNHit | None
    """
    invalid_status = site.options.m_code
    expected_status = site.entry.e_code

    negative_id = site.entry.m_string or ''
    positive_id = site.entry.e_string or ''

    request_template = WmnSiteUtils.get_request_parts(
        site=site,
        account=username,
        base_headers=base_headers
    )

    async with request_template.stream(client) as response:
        status = response.status_code
        if invalid_status is not None and status == invalid_status:
            return None

        if status != expected_status:
            return None

        saw_positive, saw_negative = await HTTPStreamUtils.stream_contains(
            response,
            must_contain=positive_id,
            must_not_contain=negative_id,
        )

    if saw_negative and negative_id:
        return None

    if not saw_positive and positive_id:
        return None

    return WMNHit(
        site=site.entry.name,
        url=request_template.url,
        status=status,
    )


class _ChunkProber:
    @staticmethod
    async def worker_future(
        chunk: list[dict],
        username: str,
        options: HttpxOptions,
        concurrency_per_process: int,
        base_headers: dict[str, str],
    ) -> list[WMNHit]:
        async with make_httpx_client(options, base_headers) as client:
            semaphore = asyncio.Semaphore(concurrency_per_process)
            hits: list[WMNHit] = []

            async def run_one(site_json: dict) -> None:
                parse_result = WmnSiteUtils.try_load_wmn_site_json(site_json)
                if not (site := parse_result.site):
                    logger.warning(f'Skipping invalid site entry: {parse_result.error}')
                    return

                try:
                    async with semaphore:
                        hit = await fetch_one(
                            site=site,
                            client=client,
                            username=username,
                            base_headers=base_headers,
                        )
                        if hit:
                            log.info(f'Found account on {hit.site}: {hit.url}')
                            hits.append(hit)
                except Exception as exc:
                    log.error(f'Error checking {site.entry.name}, {exc}')

            tasks = [asyncio.create_task(run_one(site)) for site in chunk]
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            return hits

    @staticmethod
    def worker(
        chunk: list[dict],
        username: str,
        options: HttpxOptions,
        concurrency_per_process: int,
        base_headers: dict[str, str],
    ) -> list[WMNHit]:
        return asyncio.run(
            _ChunkProber.worker_future(
                chunk,
                username,
                options,
                concurrency_per_process,
                base_headers,
            )
        )


class _UserUtils:
    @staticmethod
    def defaultheaders() -> dict:
        return {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'User-Agent': user_agent_spec.random_header(),
        }

    @staticmethod
    def client_config(concurrency: int, headers: dict) -> HttpxOptions:
        keep_alive = max(2, concurrency // 2)
        return HttpxOptions(
            timeout=15,
            max_connections=concurrency,
            max_keepalive=keep_alive,
            keep_alive_expiry=10,
            connect_timeout=10,
            read_timeout=10,
            http2=True,
            follow_redirects=True,
            headers=headers,
        )


@dc.dataclass(slots=True)
class WhatsMyNameOptions:
    wmn_url: str | None = None
    local_path: str | None = None
    categories: list[str] = dc.field(default_factory=list)
    processes: int = 4
    chunk_size: int = 100
    concurrency_per_process: int = 50


async def load_wmn_collection(
    *,
    wmn_url: str | None = None,
    client: httpx.AsyncClient | None = None,
    local_path: str | None = None,
    rule_set: WMNRuleSet | None = None,
) -> WMNCollection:
    """
    Load a WMNCollection from either a URL or a local file, applying an optional rule set.


    Parameters
    ----------
    wmn_url : str | None, optional
        _If the loaded via a url you can supply a custom one_, by default None
    client : httpx.AsyncClient | None, optional
        _A custom httpx client to use for the request_, by default None
    local_path : str | None, optional
        _A JSON file to load locally_, by default None
    rule_set : WMNRuleSet | None, optional
        _Rulesets for the collection_, by default None

    Returns
    -------
    WMNCollection
    """
    if local_path:
        schema = WMNLoaders.load_json(local_path)
    elif client:
        schema = await WMNLoaders.fetch_wmn_json(client, wmn_url)
    else:
        logger.info('No HTTP client provided, creating a temporary one to fetch WMN data.')
        async with make_httpx_client() as temp_client:
            schema = await WMNLoaders.fetch_wmn_json(temp_client, wmn_url)

    return WMNCollection.build(schema, rule_set=rule_set)


async def check_whatsmyusername_multiprocess(
    *,
    collection: WMNCollection,
    username: str,
    processes: int = 4,
    chunk_size: int = 100,
    concurrency_per_process: int = 50,
) -> list[WMNHit]:
    headers = _UserUtils.defaultheaders()
    config = _UserUtils.client_config(
        concurrency=concurrency_per_process,
        headers=headers,
    )
    logger.debug(f'Using client config: {dc.asdict(config)}')
    all_hits: list[WMNHit] = []
    event_loop = asyncio.get_running_loop()

    with concurrent.futures.ProcessPoolExecutor(max_workers=processes) as pool:
        futures = []
        logger.info(f'Starting check with {processes} processes.')
        for chunk in collection.chunkate(chunk_size=chunk_size):
            futures.append(
                event_loop.run_in_executor(
                    pool,
                    _ChunkProber.worker,
                    chunk,
                    username,
                    config,
                    concurrency_per_process,
                    headers,
                )
            )

        for fut in asyncio.as_completed(futures):
            try:
                hits = await fut
                if not hits:
                    logger.warning('No hits found in chunk.')
                    continue

                all_hits.extend(hits)
            except Exception as exc:
                logger.error(f'Error in process pool worker: {exc}')

    return all_hits


async def check_username(
    username: str,
    options: WhatsMyNameOptions | None = None,
    rule_set: WMNRuleSet | None = None,
) -> list[WMNHit]:
    """
    Check a username across the WhatsMyName collection.

    Parameters
    ----------
    username : str
        The username to check.
    options : WhatsMyNameOptions
        Options for the check.

    Returns
    -------
    list[WMNHit]
        A list of hits found.
    """

    options = options or WhatsMyNameOptions()


    async with make_httpx_client() as client:
        collection = await load_wmn_collection(
            wmn_url=options.wmn_url,
            local_path=options.local_path,
            client=client,
            rule_set=rule_set,
        )

    logger.info(f'Loaded {collection.size} sites from WhatsMyName collection.')

    if collection.size == 0:
        return []

    hits = await check_whatsmyusername_multiprocess(
        collection=collection,
        username=username,
        processes=options.processes,
        chunk_size=options.chunk_size,
        concurrency_per_process=options.concurrency_per_process,
    )

    return hits


async def example(username: str) -> None:
    console = Console()

    hits = await check_username(
        username,
        WhatsMyNameOptions(
            processes=4,
            chunk_size=100,
            concurrency_per_process=50,
            categories=['social', 'gaming'],
        ),
        WMNRuleSet(
            ignore_protected=True,
            http_get_only=True,
            any_known_accounts=True,
        )
    )
    for hit in hits:
        console.print(
            '----------------------\n'
            f'[bold]Site:[/bold] [italic cyan]{hit.site}[/italic cyan]\n'
            f'[bold]URL:[/bold] [green]{hit.url}[/green]\n'
            '----------------------\n'
        )

def run_example(username: str) -> None:
    _setup_log()
    asyncio.run(example(username))

def _setup_log() -> None:
    LOGURU_FORMAT = (
        '<green>{time:YYYY-MM-DD HH:mm:ss}</green> | '
        '<level>{level: <8}</level> | '
        '<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - '
        '<level>{message}</level>'
    )



    logger.add(
        sys.stdout,
        format=LOGURU_FORMAT,
        level='INFO',
        colorize=True,
        backtrace=True,
        diagnose=True,
        enqueue=True,
    )

def auto_run() -> None:
    import sys
    _setup_log()
    console = Console()
    if len(sys.argv) != 2:
        username = console.input(
            '[italic]Enter a username to check with WhatsMyName:[/italic] '
        )
    else:
        username = sys.argv[1]

    console.print(f'Checking username: [bold]{username}[/bold]')
    coro = check_username(
        username,
        WhatsMyNameOptions(
            processes=8,
            chunk_size=100,
            concurrency_per_process=100,
        ),
        WMNRuleSet(
            ignore_protected=True,
            http_get_only=True,
            any_known_accounts=True,
        ),
    )
    result = asyncio.run(coro)

    for hit in result:
        console.print(
            '----------------------\n'
            f'[bold]Site:[/bold] [italic cyan]{hit.site}[/italic cyan]\n'
            f'[bold]URL:[/bold] [green]{hit.url}[/green]\n'
            '----------------------\n'
        )

if __name__ == '__main__':
    auto_run()

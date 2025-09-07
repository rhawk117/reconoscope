from __future__ import annotations

import asyncio
import concurrent
import concurrent.futures
import dataclasses as dc
import json
import logging
from collections.abc import Iterator
from typing import Protocol, TypedDict

import httpx
from rich.console import Console

from reconoscope.core.httpx import (
    HttpxOptions,
    httpxretry,
    make_httpx_client,
    user_agent_spec,
)
from reconoscope.modules.whatsmyname import wmn_utils
from reconoscope.modules.whatsmyname.dtos import WhatsMyNameSite

log = logging.getLogger(__name__)


class WhatsMyNameSchema(TypedDict, total=False):
    """
    The response structure for a JSON site.
    """

    license: list[str]
    authors: list[str]
    categories: list[str]
    sites: list[dict]


class _WMNRulesetFilter(Protocol):
    def matches(self, site: 'WhatsMyNameSite') -> bool: ...


@dc.dataclass(slots=True)
class WMNRuleSet:
    include_categories: frozenset[str] = frozenset()
    exclude_categories: frozenset[str] = frozenset()

    any_known_accounts: bool = False
    require_protections_any_of: frozenset[str] = frozenset()

    http_get_only: bool = False

    def is_allowed(self, site: WhatsMyNameSite) -> bool:
        if self.include_categories and site.entry.cat not in self.include_categories:
            return False

        if self.exclude_categories and site.entry.cat in self.exclude_categories:
            return False

        if self.http_get_only and site.method != 'GET':
            return False

        if self.require_protections_any_of:
            have = {p.lower() for p in site.options.protection}
            if not (have & self.require_protections_any_of):
                return False

        return True

    def pre_filter(self, site_json: dict) -> bool:
        cat = site_json.get('cat', '')
        if self.include_categories and cat not in self.include_categories:
            return False
        if self.exclude_categories and cat in self.exclude_categories:
            return False

        if self.http_get_only and (
            'post_body' in site_json and site_json.get('post_body')
        ):
            return False

        if self.any_known_accounts and not site_json.get('known'):
            return False

        if self.require_protections_any_of:
            protection = site_json.get('protection') or []
            have = {p.lower() for p in protection}
            if not (have & self.require_protections_any_of):
                return False

        return True


@dc.dataclass(slots=True)
class WMNCollection:
    sites: list[dict] = dc.field(default_factory=list)
    categories: set[str] = dc.field(default_factory=set)
    authors: set[str] = dc.field(default_factory=set)
    rule_set: WMNRuleSet | None = None

    @classmethod
    def build(
        cls,
        schema: WhatsMyNameSchema,
        rule_set: WMNRuleSet | None = None,
    ) -> 'WMNCollection':
        """
        build a WMNCollection from a WhatsMyNameSchema and optional rule set.

        Parameters
        ----------
        schema : WhatsMyNameSchema
            The schema to load sites from.
        rule_set : WMNRuleSet | None, optional
            An optional rule set to filter sites, by default None

        Returns
        -------
        WMNCollection
        """
        return cls(
            rule_set=rule_set,
            sites=schema.get('sites', []),
            authors=set(schema.get('authors', [])),
            categories=set(schema.get('categories', [])),
        )

    @property
    def size(self) -> int:
        """
        Get the total number of site entries in the collection.

        Returns
        -------
        int
        """
        return len(self.sites)

    def _auto_discard_iterator(self) -> Iterator[dict]:
        while self.sites:
            cur = self.sites.pop()
            if self.rule_set and not self.rule_set.pre_filter(cur):
                continue
            yield cur

    def _basic_iterator(self) -> Iterator[dict]:
        for entry in self.sites:
            if self.rule_set and not self.rule_set.pre_filter(entry):
                continue
            yield entry

    def iter_site_json(self, *, auto_discard: bool = True) -> Iterator[dict]:
        """
        Iterate over all sites in the collection, applying any rule set filters.

        Yields
        ------
        Iterator[WhatsMyNameSite]
        """

        if auto_discard:
            iterator = self._auto_discard_iterator
        else:
            iterator = self._basic_iterator

        for site_json in iterator():
            yield site_json

    def producer(self, *, auto_discard: bool = True) -> Iterator[WhatsMyNameSite]:
        """
        build WhatsMyNameSite instances from the collection, applying any rule set
        filters.

        Yields
        ------
        Iterator[WhatsMyNameSite]
        """

        for site_json in self.iter_site_json(auto_discard=auto_discard):
            result = wmn_utils.try_load_wmn_site_json(site_json)
            if not (site := result.site):
                log.warning(f'Skipping invalid site entry: {result.error}')
                continue
            yield site

    def chunkate(self, chunk_size: int) -> Iterator[list[dict]]:
        """
        Chunk the sites into lists of a given size.

        Parameters
        ----------
        chunk_size : int
            The size of each chunk.

        Yields
        ------
        Iterator[list[WhatsMyNameSite]]
        """

        if chunk_size <= 0:
            raise ValueError('chunk_size must be greater than 0')

        chunk: list[dict] = []
        for raw_json in self._auto_discard_iterator():
            chunk.append(raw_json)

            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []
        if chunk:
            yield chunk


class WMNLoaders:
    _WMN_DEFAULT_URL = (
        'https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json'
    )
    _DEFAULT_PATHNAME = 'data/whatsmyname.json'

    @staticmethod
    @httpxretry(attempts=3)
    async def fetch_wmn_json(
        client: httpx.AsyncClient,
        url: str | None = None,
    ) -> WhatsMyNameSchema:
        """
        Fetch the WhatsMyName JSON schema from a URL.

        Parameters
        ----------
        url : str | None, optional
            The URL to fetch the schema from, by default None
            (uses the default WMN URL)
        client : httpx.AsyncClient
            The HTTPX client to use for the request.

        Returns
        -------
        WhatsMyNameSchema
            The fetched schema.

        Raises
        ------
        httpx.HTTPError
            If the request fails.
        ValueError
            If the response is not valid JSON or does not conform to the schema.
        """
        fetch_url = url or WMNLoaders._WMN_DEFAULT_URL
        log.debug(f'Fetching WhatsMyName JSON from {fetch_url}')
        response = await client.get(fetch_url, timeout=15)
        response.raise_for_status()
        try:
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError('Response JSON is not an object')
            return data  # type: ignore
        except Exception as exc:
            raise ValueError(f'Failed to parse WhatsMyName JSON: {exc}') from exc

    @staticmethod
    def load_json(pathname: str) -> WhatsMyNameSchema:
        """
        Load the WhatsMyName JSON schema from a local file.

        Parameters
        ----------
        pathname : str
            The path to the local JSON file.

        Returns
        -------
        WhatsMyNameSchema
            The loaded schema.

        Raises
        ------
        FileNotFoundError
            If the file does not exist.
        ValueError
            If the file is not valid JSON or does not conform to the schema.
        """
        from reconoscope.core import fs_utils

        json_string = fs_utils.read_text(pathname, join_to_root=True)

        log.debug(f'Loading WhatsMyName JSON from {pathname}')
        try:
            return json.loads(json_string)
        except Exception as exc:
            raise ValueError(f'Failed to load WhatsMyName JSON: {exc}') from exc


class _HTTPStreamUtils:
    @staticmethod
    def encode_nullable(s: str | None) -> bytes:
        return s.encode('utf-8') if s else b''

    @staticmethod
    async def stream_contains(
        response: httpx.Response,
        *,
        must_contain: str | None,
        must_not_contain: str | None,
        chunk_size: int = 16_384,
        max_size_mb: int = 10,
    ) -> tuple[bool, bool]:
        """
        Streams a httpx.response and check for the presence of certain strings
        in a very memory efficient manner.

        Technical Details
        -----------------
        This function reads the response body in chunks, checking each chunk
        for the presence of the specified strings. It handles cases where the
        strings may span across chunk boundaries by maintaining a tail of bytes
        from the end of the previous chunk.

        - Seen Positive Identifier: A flag that indicates whether the positive
        identifier has been found in the stream or the sites `m_string`

        - Seen Negative Identifier: A flag that indicates whether the negative
        identifier has been found in the stream or the sites `e_string`

        This function could've been a class tbh but I'm too sleep deprived to
        refactor it now.

        Parameters
        ----------
        response : httpx.Response
        must_contain : str | None
        must_not_contain : str | None
        chunk_size : int, optional
            _description_, by default 16_384 (16 KB)
        max_size_mb : int, optional
            _description_, by default 10

        Returns
        -------
        tuple[bool, bool]
            _(seen_positive_identifier, seen_negative_identifier)_
        """
        seen_positive_identifier = False
        seen_negative_identifier = False

        pos_identifier: bytes = _HTTPStreamUtils.encode_nullable(must_contain)
        negative_identifier: bytes = _HTTPStreamUtils.encode_nullable(must_not_contain)

        need_positive = bool(pos_identifier)
        need_negative = bool(negative_identifier)

        overlap_boundary = max(len(pos_identifier), len(negative_identifier), 1) - 1
        tail = b''
        total_read = 0

        max_bytes = max_size_mb * 1_048_576
        async for chunk in response.aiter_bytes(chunk_size=chunk_size):
            total_read += len(chunk)
            if total_read > max_bytes:
                break

            buffer = tail + chunk
            if need_positive and pos_identifier in buffer:
                seen_positive_identifier = True

            if need_negative and negative_identifier in buffer:
                seen_negative_identifier = True

            if need_negative and seen_negative_identifier:
                return (seen_positive_identifier, seen_negative_identifier)
            if need_positive and seen_positive_identifier and not need_negative:
                return (True, False)

            tail = buffer[-overlap_boundary:] if overlap_boundary > 0 else b''

        return (seen_positive_identifier, seen_negative_identifier)


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

    request_template = wmn_utils.get_request_parts(
        site=site, account=username, base_headers=base_headers
    )

    async with request_template.stream(client) as response:
        status = response.status_code
        if invalid_status is not None and status == invalid_status:
            return None

        if status != expected_status:
            return None

        saw_positive, saw_negative = await _HTTPStreamUtils.stream_contains(
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


async def _mp_worker_async(
    chunk: list[dict],
    username: str,
    options: HttpxOptions,
    concurrency_per_process: int,
    base_headers: dict[str, str],
) -> list[WMNHit]:
    async with make_httpx_client(options, base_headers) as client:
        sem = asyncio.Semaphore(concurrency_per_process)
        hits: list[WMNHit] = []

        async def run_one(site_json: dict) -> None:
            parse_result = wmn_utils.try_load_wmn_site_json(site_json)
            site = parse_result.site
            if not site:
                log.warning('Skipping invalid site entry: %s', parse_result.error)
                return
            try:
                async with sem:
                    hit = await fetch_one(
                        site=site,
                        client=client,
                        username=username,
                        base_headers=base_headers,
                    )
                if hit:
                    log.info('Found account on %s: %s', hit.site, hit.url)
                    hits.append(hit)
            except Exception as exc:
                log.error('Error checking %s: %s', site.entry.name, exc)

        tasks = [asyncio.create_task(run_one(s)) for s in chunk]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        return hits


def _mp_worker(
    chunk: list[dict],
    username: str,
    options: HttpxOptions,
    concurrency_per_process: int,
    base_headers: dict[str, str],
) -> list[WMNHit]:
    return asyncio.run(
        _mp_worker_async(
            chunk, username, options, concurrency_per_process, base_headers
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
            follow_redirects=True,
            headers=headers,
        )


@dc.dataclass(slots=True)
class WhatsMyNameOptions:
    wmn_url: str | None = None
    local_path: str | None = None
    categories: list[str] = dc.field(default_factory=list)
    http_get_only: bool = False
    any_known_accounts: bool = False
    require_protections_any_of: list[str] = dc.field(default_factory=list)
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
        log.info('No HTTP client provided, creating a temporary one to fetch WMN data.')
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
    log.debug(f'Using client config: {dc.asdict(config)}')
    all_hits: list[WMNHit] = []
    event_loop = asyncio.get_running_loop()

    with concurrent.futures.ProcessPoolExecutor(max_workers=processes) as pool:
        futures = []
        log.info(f'Starting check with {processes} processes.')
        for chunk in collection.chunkate(chunk_size=chunk_size):
            futures.append(
                event_loop.run_in_executor(
                    pool,
                    _mp_worker,
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
                    log.warning('No hits found in chunk.')
                    continue
                all_hits.extend(hits)
            except Exception as exc:
                log.error(f'Error in process pool worker: {exc}')

    return all_hits


async def username_check(
    username: str,
    *,
    options: WhatsMyNameOptions | None = None,
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

    rule_set = WMNRuleSet(
        include_categories=frozenset(options.categories),
        http_get_only=options.http_get_only,
        any_known_accounts=options.any_known_accounts,
        require_protections_any_of=frozenset(
            p.lower() for p in options.require_protections_any_of
        ),
    )

    async with make_httpx_client() as client:
        collection = await load_wmn_collection(
            wmn_url=options.wmn_url,
            local_path=options.local_path,
            client=client,
            rule_set=rule_set,
        )

    log.info(f'Loaded {collection.size} sites from WhatsMyName collection.')

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


def example(username: str) -> None:
    console = Console()
    hits = asyncio.run(username_check(username))
    for hit in hits:
        console.print(
            '----------------------'
            f'[bold]Site:[/bold] [italic cyan]{hit.site}[/italic cyan]\n'
            f'[bold]URL:[/bold] [green]{hit.url}[/green]\n'
            '----------------------'
        )


if __name__ == '__main__':
    import sys

    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} <username>')
        sys.exit(1)

    example(sys.argv[1])

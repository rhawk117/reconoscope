from __future__ import annotations
import sys
from rich.console import Console
import asyncio
import itertools
import os
from typing import Any, TypedDict
from collections.abc import Generator, Iterable

from pathlib import Path
from core.retries import AsyncRetries, NoAttemptsLeftError
from core.httpclient import HttpConnectionOptions, makeclient
import httpx

import multiprocessing as mp
from typing import Optional, Iterable, Generator
from tqdm import tqdm


class AccountProbeResult(TypedDict):
    url: str
    success: bool
    final_url: str | None
    status: int | None
    message: str


def chunked(iterable: Iterable[Any], n: int) -> Iterable[list[Any]]:
    it = iter(iterable)
    while True:
        batch = list(itertools.islice(it, n))
        if not batch:
            break
        yield batch


class AccountProbeWorker:
    _EXIST_STATUS_CODES = (200, 204, 301, 302, 303, 307, 308, 401, 403)

    def _defaultoptions(self) -> HttpConnectionOptions:
        return HttpConnectionOptions(
            connect_timeout=3,
            max_connections=100,
            max_keepalive=100,
            keep_alive_expiry=15,
            read_timeout=5,
            http2=True,
        )

    def __init__(
        self,
        *,
        options: HttpConnectionOptions | None = None,
        concurrency: int = 100,
        head_first: bool = True,
    ) -> None:
        self._semaphore = asyncio.Semaphore(concurrency)
        self._client = makeclient(options or self._defaultoptions())
        self.concurrency = concurrency
        self.head_first = head_first
        self.retries = AsyncRetries(attempts=3, delay=0.15, jitter=0.1)

    async def aclose(self) -> None:
        await self._client.aclose()

    def _check_status(self, status: int) -> bool:
        return status in self._EXIST_STATUS_CODES or 200 <= status < 400

    async def _request(self, url: str, query: dict | None = None) -> httpx.Response:
        if not self.head_first:
            return await self._client.get(url, params=query)

        resp = await self._client.head(url, params=query)
        if resp.status_code in (405, 501) or resp.status_code >= 400:
            resp = await self._client.get(url, params=query)
        return resp

    async def _get_probe_result(
        self,
        url: str,
        query: dict | None = None,
    ) -> AccountProbeResult:
        resp: httpx.Response | None = None
        try:
            resp = await self._request(url, query=query)
            if not self._check_status(resp.status_code):
                resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            resp = getattr(exc, "response", None)
            if resp is None:
                return AccountProbeResult(
                    url=url,
                    success=False,
                    final_url=None,
                    status=None,
                    message=f"HTTP error for {url}: {exc}",
                )

        assert resp is not None
        return AccountProbeResult(
            url=url,
            success=self._check_status(resp.status_code),
            final_url=str(resp.url),
            status=resp.status_code,
            message=f"Status {resp.status_code} for {url}",
        )

    async def probe(self, *, url: str, query: dict | None = None) -> AccountProbeResult:
        try:
            async with self._semaphore:
                return await self.retries.retry(
                    self._get_probe_result, url, query=query
                )
        except NoAttemptsLeftError as exc:
            return AccountProbeResult(
                url=url,
                success=False,
                final_url=None,
                status=None,
                message=f"No attempts left: {exc}",
            )
        except Exception as exc:
            return AccountProbeResult(
                url=url,
                success=False,
                final_url=None,
                status=None,
                message=f"Error probing {url}: {exc}",
            )

    async def probe_all(
        self, urls: list[str], *, query: dict | None = None
    ) -> list[AccountProbeResult]:
        tasks = [asyncio.create_task(self.probe(url=u, query=query)) for u in urls]
        out: list[AccountProbeResult] = []
        for coro in asyncio.as_completed(tasks):
            out.append(await coro)
        return out


def _child_run_batch(args) -> list[AccountProbeResult]:
    urls, options, concurrency, head_first, query = args

    async def _runner():
        probe = AccountProbeWorker(
            options=options,
            concurrency=concurrency,
            head_first=head_first
        )
        try:
            return await probe.probe_all(urls, query=query)
        finally:
            await probe.aclose()

    return asyncio.run(_runner())


class MultiprocessAccountProbe:
    def __init__(
        self,
        *,
        options: Optional[HttpConnectionOptions] = None,
        concurrency: int = 100,
        head_first: bool = True,
    ) -> None:
        self.options = options or HttpConnectionOptions()
        self.concurrency = concurrency
        self.head_first = head_first

    def stream(
        self,
        urls: list[str],
        *,
        shards: int = 8,
        batch_size: int = 100,
        query: dict | None = None,
    ) -> Generator[list[AccountProbeResult], None, None]:
        ctx = mp.get_context("spawn")
        with ctx.Pool(processes=shards) as pool:
            args_iter = (
                (batch, self.options, self.concurrency, self.head_first, query)
                for batch in chunked(urls, batch_size)
            )
            for batch_result in pool.imap_unordered(
                _child_run_batch, args_iter, chunksize=1
            ):
                yield batch_result

    def run(
        self,
        urls: list[str],
        *,
        shards: int = 8,
        batch_size: int = 100,
        query: dict | None = None,
    ) -> list[AccountProbeResult]:
        results: list[AccountProbeResult] = []
        with tqdm(total=len(urls), desc="Probing", unit="url", ncols=90) as pbar:
            for batch in self.stream(
                urls, shards=shards, batch_size=batch_size, query=query
            ):
                results.extend(batch)
                pbar.update(len(batch))
        return results


def load_url_txt_list(file_path: str, account: str) -> list[str]:
    txt_file = Path(file_path)
    if not txt_file.is_file() or not txt_file.exists():
        raise FileNotFoundError(f"URL list file not found: {file_path}")

    url_lines = txt_file.read_text().splitlines()

    urls: list[str] = []
    for line in url_lines:
        line = line.strip()
        if "{account}" not in line:
            print(f"Skipping line without '{{account}}' placeholder: {line}")
            continue

        line = line.format(account=account)
        urls.append(line)

    return urls


def run(account: str) -> None:
    os.chdir(Path(__file__).parent.parent.parent)

    console = Console()

    console.print(f"""
[bold blue]Multiprocess HTTP Probe[/bold blue]
[italic]Probes a list of URLs using HTTP HEAD and GET requests with retries and concurrency.[/italic]

CWD: {os.getcwd()}

""")

    account_url_list_file = "data/account_search_list.txt"
    console.print(f"Loading account list from: {account_url_list_file}")

    urls = load_url_txt_list(account_url_list_file, account=account)

    console.print(f"Loaded {len(urls)} URLs to probe.")

    prober = MultiprocessAccountProbe(
        concurrency=200,
        head_first=True,
    )

    console.print(f"Starting probe with {prober.concurrency} concurrency...")

    results = prober.run(
        urls,
        shards=10,
        batch_size=20,
    )
    console.print(f"Probing complete. [green]{len(results)}[/green] results obtained.")
    for result in results:
        status = "[green]Success[/green]" if result["success"] else "[red]Failed[/red]"
        console.print(
            f"""
[bold]URL:[/bold]{result["url"]}
[bold]Status:[/bold] {status}
[bold]HTTP Status:[/bold] {result["status"]}
[bold]Final URL:[/bold] {result["final_url"]}
[bold]Message:[/bold] {result["message"]}
"""
        )


def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <account>")
        sys.exit(1)

    account = sys.argv[1]
    run(account)


# class WhatsMyNameEntry(TypedDict):
#     name: str
#     uri_check: str
#     e_code: int
#     e_string: str
#     m_code: int
#     m_string: str


# class WhatsMyNameProbe:
#     GITHUB_URL = (
#         "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
#     )


class WhatsMyNameRule(TypedDict):
    name: str
    uri_check: str
    e_code: int
    e_string: str
    m_string: str
    # 
    m_code: int
    # Category
    cat: str